//! Browser sessions: their cookie, lifetime, idle limit and sign-out.

use crate::common::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{TimeDelta, Utc};
use ito::{db::session, http::secrets::digest_sha256};
use sea_orm::EntityTrait;
use serde_json::Value;

/// Changes the stored session of `s`, such as to make it older than it is.
async fn edit_session(env: &Env, s: &Session, change: impl FnOnce(&mut session::Model)) {
    let tx = env.app.db.begin_write().await.unwrap();
    let mut row = session::Entity::find_by_id(digest_sha256(&s.cookie))
        .one(&*tx)
        .await
        .unwrap()
        .unwrap();
    change(&mut row);
    tx.update::<session::ActiveModel>(row).await.unwrap();
    tx.commit().await.unwrap();
}

async fn read_last_seen(env: &Env, s: &Session) -> chrono::DateTime<Utc> {
    let row = session::Entity::find_by_id(digest_sha256(&s.cookie))
        .one(&env.app.db.conn)
        .await
        .unwrap()
        .unwrap();
    row.last_seen
}

#[tokio::test]
async fn requests_without_a_session_are_unauthorized() {
    let env = start_env().await;
    let request = Request::get("/api/v1/session").body(Body::empty()).unwrap();
    assert_eq!(env.send(request).await.code(), "invalid_credentials");
}

#[tokio::test]
async fn sessions_report_their_account_admin_flag_and_csrf_token() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let view = env
        .get(&admin, "/api/v1/session")
        .await
        .expect(StatusCode::OK);
    assert_eq!(view["account_id"], admin.account_id.as_str());
    assert_eq!(view["admin"], true);
    assert_eq!(view["csrf_token"], admin.csrf.as_str());
}

#[tokio::test]
async fn sessions_end_after_their_lifetime() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    edit_session(&env, &user, |s| {
        s.expires_at = Utc::now() - TimeDelta::seconds(1)
    })
    .await;
    let reply = env.get(&user, "/api/v1/session").await;
    assert_eq!(reply.code(), "invalid_credentials");
}

#[tokio::test]
async fn idle_sessions_end() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let idle = TimeDelta::from_std(env.app.config.session_idle).unwrap();
    edit_session(&env, &user, |s| {
        s.last_seen = Utc::now() - idle - TimeDelta::seconds(1);
    })
    .await;
    let reply = env.get(&user, "/api/v1/session").await;
    assert_eq!(reply.code(), "invalid_credentials");
}

#[tokio::test]
async fn requests_restart_the_idle_time() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    // Two thirds of the idle limit have passed, more than the minute after which the time is
    // written again.
    let idle = TimeDelta::from_std(env.app.config.session_idle).unwrap();
    let seen = Utc::now() - idle * 2 / 3;
    edit_session(&env, &user, |s| s.last_seen = seen).await;
    env.get(&user, "/api/v1/session")
        .await
        .expect(StatusCode::OK);
    assert!(read_last_seen(&env, &user).await > seen + idle / 2);
}

#[tokio::test]
async fn signing_out_ends_the_session_before_optional_provider_logout() {
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{method, path},
    };

    for case in ["supported", "unsupported", "unavailable", "unsafe"] {
        let idp = idp::start_idp().await;
        let env = start_env_with(|c| c.oidc.issuer = idp.issuer()).await;
        if matches!(case, "supported" | "unsafe") {
            let url = format!("{}/.well-known/openid-configuration", idp.issuer());
            let mut metadata: Value = reqwest::get(url).await.unwrap().json().await.unwrap();
            metadata["end_session_endpoint"] = if case == "unsafe" {
                "javascript:alert(1)".into()
            } else {
                format!("{}/logout", idp.issuer()).into()
            };
            Mock::given(method("GET"))
                .and(path("/realms/ito/.well-known/openid-configuration"))
                .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
                .with_priority(1)
                .mount(&idp.server)
                .await;
        } else if case == "unavailable" {
            idp.server.reset().await;
        }
        let user = env.sign_in("user", false).await;
        let reply = env
            .call(&user, "POST", "/api/v1/auth/logout", None, Value::Null)
            .await;
        let cookies: Vec<_> = reply.headers.get_all("set-cookie").iter().collect();
        assert_eq!(cookies.len(), 2);
        assert!(
            cookies
                .iter()
                .all(|c| c.to_str().unwrap().contains("Max-Age=0"))
        );
        let body = reply.expect(StatusCode::OK);
        let redirect = body["redirect_url"].as_str().unwrap();
        if case == "supported" {
            let url = reqwest::Url::parse(redirect).unwrap();
            assert_eq!(url.path(), "/realms/ito/logout");
            let params: std::collections::HashMap<_, _> = url.query_pairs().collect();
            assert_eq!(params.len(), 2);
            assert_eq!(params["client_id"], "portal");
            assert_eq!(params["post_logout_redirect_uri"], format!("{ORIGIN}/"));
        } else {
            assert_eq!(redirect, "/", "{case}");
        }
        assert_eq!(
            env.get(&user, "/api/v1/session").await.code(),
            "invalid_credentials"
        );
    }
}

#[tokio::test]
async fn stored_session_ids_do_not_sign_in() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let rows = session::Entity::find().all(&env.app.db.conn).await.unwrap();
    // The database holds the digest of the cookie, which works as a cookie no better than a guess.
    let stolen = Session {
        cookie: rows[0].id.clone(),
        account_id: user.account_id.clone(),
        csrf: user.csrf.clone(),
    };
    let reply = env.get(&stolen, "/api/v1/session").await;
    assert_eq!(reply.code(), "invalid_credentials");
}

#[tokio::test]
async fn insecure_cookies_drop_the_host_prefix() {
    let env = start_env_with(|c| c.cookie_secure = false).await;
    let user = env.sign_in("user", false).await;
    let send_cookie = async |name: &str| {
        let request = Request::get("/api/v1/session")
            .header("cookie", format!("{name}={}", user.cookie))
            .body(Body::empty())
            .unwrap();
        env.send(request).await.status
    };
    assert_eq!(send_cookie("ito_session").await, StatusCode::OK);
    assert_eq!(
        send_cookie("__Host-ito_session").await,
        StatusCode::UNAUTHORIZED
    );
}
