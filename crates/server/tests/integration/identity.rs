//! Sign-in with OpenID Connect and the SCIM user status, against a wiremock identity provider.

use crate::common::{
    idp::{IdToken, Idp, start_idp},
    *,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use chrono::{TimeDelta, Utc};
use ito::{
    accounts,
    config::{Config, Scim},
    db::account::IdpStatus,
    error::{Code, internal},
    identity,
};
use serde_json::Value;
use std::{collections::BTreeMap, time::Duration};

/// Signs in to `idp`, where the group `/ito-admins` grants administrator rights.
fn use_idp(config: &mut Config, idp: &Idp) {
    config.oidc.issuer = idp.issuer();
    config.oidc.admin_groups = vec!["/ito-admins".into()];
}

/// Checks user status at the SCIM service of `idp`.
fn use_scim<'c>(config: &'c mut Config, idp: &Idp) -> &'c mut Scim {
    config.scim.insert(Scim {
        url: idp.scim_url(),
        client_id: "status".into(),
        secret_file: config.oidc.secret_file.with_file_name("status"),
        ..Scim::default()
    })
}

/// A sign-in started at the controller: the redirect's query, and the login cookie it set.
struct SignIn {
    query: BTreeMap<String, String>,
    set_cookie: String,
}

impl SignIn {
    /// The ID token the provider issues for this sign-in to a member of `groups`.
    fn issue_token(&self, azp: &str, groups: &[&str]) -> IdToken {
        IdToken {
            nonce: self.query["nonce"].clone(),
            challenge: self.query["code_challenge"].clone(),
            azp: azp.into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }
}

async fn start_sign_in(env: &Env) -> SignIn {
    let request = Request::get("/api/v1/auth/login")
        .body(Body::empty())
        .unwrap();
    let reply = env.send(request).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
    let location = reqwest::Url::parse(reply.headers["location"].to_str().unwrap()).unwrap();
    SignIn {
        query: location.query_pairs().into_owned().collect(),
        set_cookie: reply.headers["set-cookie"].to_str().unwrap().into(),
    }
}

/// Returns to the controller from the provider with `query`, holding the sign-in's login cookie.
async fn return_from_idp(env: &Env, sign_in: &SignIn, query: &str) -> Reply {
    let login_cookie = sign_in.set_cookie.split(';').next().unwrap();
    let request = Request::get(format!("/api/v1/auth/callback?{query}"))
        .header("cookie", login_cookie)
        .body(Body::empty())
        .unwrap();
    env.send(request).await
}

/// Completes a sign-in whose ID token is issued to the portal for a member of `groups`.
async fn sign_in_at_idp(env: &Env, idp: &Idp, groups: &[&str]) -> Reply {
    let sign_in = start_sign_in(env).await;
    idp.serve_id_token(sign_in.issue_token("portal", groups))
        .await;
    let state = &sign_in.query["state"];
    return_from_idp(env, &sign_in, &format!("code=abc&state={state}")).await
}

/// Finds the `Set-Cookie` header of the reply that sets the cookie `name`.
fn find_set_cookie<'r>(reply: &'r Reply, name: &str) -> &'r str {
    let headers = reply.headers.get_all("set-cookie").iter();
    let mut values = headers.map(|h| h.to_str().unwrap());
    values.find(|h| h.starts_with(&format!("{name}="))).unwrap()
}

/// Reads the browser session that the sign-in `reply` set.
async fn read_session(env: &Env, reply: &Reply) -> Value {
    let session = find_set_cookie(reply, "__Host-ito_session");
    let request = Request::get("/api/v1/session")
        .header("cookie", session.split(';').next().unwrap())
        .body(Body::empty())
        .unwrap();
    env.send(request).await.expect(StatusCode::OK)
}

// --- Sign-in ---

#[tokio::test]
async fn sign_in_sends_a_pkce_challenge() {
    let idp = start_idp().await;
    let env = start_env_with(|c| use_idp(c, &idp)).await;
    let sign_in = start_sign_in(&env).await;
    assert_eq!(sign_in.query["code_challenge_method"], "S256");
}

#[tokio::test]
async fn login_cookies_cannot_be_planted_by_sibling_domains() {
    let idp = start_idp().await;
    let env = start_env_with(|c| use_idp(c, &idp)).await;
    let cookie = start_sign_in(&env).await.set_cookie;
    assert!(cookie.starts_with("__Host-ito_login="), "{cookie}");
    assert!(cookie.contains("; Path=/;"), "{cookie}");
    assert!(cookie.ends_with("; Secure"), "{cookie}");
}

#[tokio::test]
async fn admin_groups_sign_in_as_administrators() {
    let idp = start_idp().await;
    let env = start_env_with(|c| use_idp(c, &idp)).await;
    let reply = sign_in_at_idp(&env, &idp, &["/ito-admins"]).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
    assert_eq!(read_session(&env, &reply).await["admin"], true);
}

#[tokio::test]
async fn other_groups_sign_in_as_members() {
    let idp = start_idp().await;
    let env = start_env_with(|c| use_idp(c, &idp)).await;
    let reply = sign_in_at_idp(&env, &idp, &["/staff"]).await;
    assert_eq!(read_session(&env, &reply).await["admin"], false);
}

#[tokio::test]
async fn session_cookies_are_hidden_from_scripts() {
    let idp = start_idp().await;
    let env = start_env_with(|c| use_idp(c, &idp)).await;
    let reply = sign_in_at_idp(&env, &idp, &[]).await;
    let cookie = find_set_cookie(&reply, "__Host-ito_session");
    assert!(
        cookie.contains("; HttpOnly; SameSite=Lax; Secure"),
        "{cookie}"
    );
}

#[tokio::test]
async fn csrf_cookies_are_readable_by_scripts() {
    let idp = start_idp().await;
    let env = start_env_with(|c| use_idp(c, &idp)).await;
    let reply = sign_in_at_idp(&env, &idp, &[]).await;
    let cookie = find_set_cookie(&reply, "__Host-ito_csrf");
    assert!(!cookie.contains("HttpOnly"), "{cookie}");
    let token = cookie.split(';').next().unwrap();
    let token = token.trim_start_matches("__Host-ito_csrf=");
    assert_eq!(read_session(&env, &reply).await["csrf_token"], token);
}

#[tokio::test]
async fn returns_with_a_forged_state_are_refused() {
    let idp = start_idp().await;
    let env = start_env_with(|c| use_idp(c, &idp)).await;
    let sign_in = start_sign_in(&env).await;
    idp.serve_id_token(sign_in.issue_token("portal", &[])).await;
    let reply = return_from_idp(&env, &sign_in, "code=abc&state=forged").await;
    assert_eq!(reply.code(), "invalid_login");
}

#[tokio::test]
async fn sign_ins_cancelled_at_the_provider_are_refused() {
    let idp = start_idp().await;
    let env = start_env_with(|c| use_idp(c, &idp)).await;
    let sign_in = start_sign_in(&env).await;
    let state = &sign_in.query["state"];
    let query = format!("error=access_denied&state={state}");
    let reply = return_from_idp(&env, &sign_in, &query).await;
    assert_eq!(reply.code(), "invalid_login");
}

#[tokio::test]
async fn id_tokens_issued_to_another_client_are_refused() {
    let idp = start_idp().await;
    let env = start_env_with(|c| use_idp(c, &idp)).await;
    let sign_in = start_sign_in(&env).await;
    idp.serve_id_token(sign_in.issue_token("another-client", &[]))
        .await;
    let state = &sign_in.query["state"];
    let reply = return_from_idp(&env, &sign_in, &format!("code=abc&state={state}")).await;
    assert_eq!(reply.code(), "invalid_login");
}

#[tokio::test]
async fn sign_in_without_scim_looks_up_no_user_status() {
    let idp = start_idp().await;
    let env = start_env_with(|c| use_idp(c, &idp)).await;
    let reply = sign_in_at_idp(&env, &idp, &[]).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
    assert_eq!(idp.count_scim_lookups().await, 0);
}

#[tokio::test]
async fn sign_in_with_scim_looks_up_the_user_status() {
    let idp = start_idp().await;
    idp.serve_scim_user("user-1", true).await;
    let env = start_env_with(|c| {
        use_idp(c, &idp);
        use_scim(c, &idp);
    })
    .await;
    let reply = sign_in_at_idp(&env, &idp, &[]).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.text);
    assert_eq!(idp.count_scim_lookups().await, 1);
}

#[tokio::test]
async fn users_disabled_at_the_provider_cannot_sign_in() {
    let idp = start_idp().await;
    idp.serve_scim_user("user-1", false).await;
    let env = start_env_with(|c| {
        use_idp(c, &idp);
        use_scim(c, &idp);
    })
    .await;
    let reply = sign_in_at_idp(&env, &idp, &[]).await;
    assert_eq!(reply.code(), "forbidden");
}

#[tokio::test]
async fn users_unknown_to_scim_cannot_sign_in() {
    let idp = start_idp().await;
    let env = start_env_with(|c| {
        use_idp(c, &idp);
        use_scim(c, &idp);
    })
    .await;
    let reply = sign_in_at_idp(&env, &idp, &[]).await;
    assert_eq!(reply.code(), "identity_mapping_invalid");
}

// --- User status ---

#[tokio::test]
async fn scim_lookups_report_the_user_status() {
    let idp = start_idp().await;
    idp.serve_scim_user("on", true).await;
    idp.serve_scim_user("off", false).await;
    let env = start_env_with(|c| {
        use_idp(c, &idp);
        use_scim(c, &idp);
    })
    .await;
    let scim = env.app.config.scim.as_ref().unwrap();
    for (subject, status) in [
        ("on", IdpStatus::Active),
        ("off", IdpStatus::Disabled),
        ("gone", IdpStatus::Missing),
    ] {
        let found = identity::scim::lookup(&env.app, scim, subject).await;
        assert_eq!(found.unwrap(), status, "{subject}");
    }
}

#[tokio::test]
async fn negative_lookups_fail_while_the_health_subject_is_not_active() {
    let idp = start_idp().await;
    let env = start_env_with(|c| {
        use_idp(c, &idp);
        use_scim(c, &idp).health_subject = "health".into();
    })
    .await;
    let scim = env.app.config.scim.as_ref().unwrap();
    let error = identity::scim::lookup(&env.app, scim, "gone")
        .await
        .unwrap_err();
    assert_eq!(error.code, Code::IdentityUnavailable);
}

#[tokio::test]
async fn negative_lookups_stand_while_the_health_subject_is_active() {
    let idp = start_idp().await;
    idp.serve_scim_user("health", true).await;
    let env = start_env_with(|c| {
        use_idp(c, &idp);
        use_scim(c, &idp).health_subject = "health".into();
    })
    .await;
    let scim = env.app.config.scim.as_ref().unwrap();
    let found = identity::scim::lookup(&env.app, scim, "gone").await;
    assert_eq!(found.unwrap(), IdpStatus::Missing);
}

#[tokio::test]
async fn status_sweeps_check_every_account() {
    let idp = start_idp().await;
    idp.serve_scim_user("on", true).await;
    idp.serve_scim_user("off", false).await;
    let env = start_env_with(|c| {
        use_idp(c, &idp);
        use_scim(c, &idp);
    })
    .await;
    let on = env.sign_in("on", false).await;
    let off = env.sign_in("off", false).await;
    let gone = env.sign_in("gone", false).await;
    let scim = env.app.config.scim.as_ref().unwrap();
    accounts::sweep_once(&env.app, scim).await.unwrap();
    for (session, status) in [
        (on, IdpStatus::Active),
        (off, IdpStatus::Disabled),
        (gone, IdpStatus::Missing),
    ] {
        let a = env.read_account_row(&session.account_id).await;
        assert_eq!(a.idp_status, status, "{}", a.subject);
    }
}

#[tokio::test]
async fn accounts_gone_from_the_provider_lose_their_sessions() {
    let idp = start_idp().await;
    let env = start_env_with(|c| {
        use_idp(c, &idp);
        use_scim(c, &idp);
    })
    .await;
    let gone = env.sign_in("gone", false).await;
    let scim = env.app.config.scim.as_ref().unwrap();
    accounts::sweep_once(&env.app, scim).await.unwrap();
    let reply = env.get(&gone, "/api/v1/session").await;
    assert_eq!(reply.code(), "invalid_credentials");
}

#[tokio::test]
async fn administrators_wake_the_status_sweep() {
    let idp = start_idp().await;
    let env = start_env_with(|c| {
        use_idp(c, &idp);
        use_scim(c, &idp);
    })
    .await;
    let admin = env.sign_in("admin", true).await;
    let reply = env
        .call(
            &admin,
            "POST",
            "/api/v1/accounts/refresh",
            None,
            Value::Null,
        )
        .await;
    reply.expect(StatusCode::ACCEPTED);
    let woken = tokio::time::timeout(Duration::ZERO, env.app.sweep_notify.notified()).await;
    assert!(woken.is_ok());
}

#[tokio::test]
async fn older_status_checks_do_not_overwrite_newer_ones() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let a = env.read_account_row(&user.account_id).await;
    let started = a.idp_checked_at.unwrap() - TimeDelta::seconds(1);
    let mut tx = env.app.db.begin_write().await.unwrap();
    let missing = Ok(IdpStatus::Missing);
    let a = accounts::apply_idp_status(&mut tx, &env.app.approvals, a, started, &missing)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(a.idp_status, IdpStatus::Active);
}

#[tokio::test]
async fn sign_in_renames_accounts() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let old = env.read_account_row(&user.account_id).await;
    let mut tx = env.app.db.begin_write().await.unwrap();
    let a = accounts::provision_at_login(
        &mut tx,
        &env.app.approvals,
        &old.subject,
        "New name",
        Utc::now() + TimeDelta::seconds(1),
        &Ok(IdpStatus::Active),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(a.display_name, "New name");
    assert!(a.revision > old.revision);
}

#[tokio::test]
async fn sign_in_keeps_the_name_when_the_status_check_fails() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let old = env.read_account_row(&user.account_id).await;
    let mut tx = env.app.db.begin_write().await.unwrap();
    let a = accounts::provision_at_login(
        &mut tx,
        &env.app.approvals,
        &old.subject,
        "Unverified name",
        Utc::now() + TimeDelta::seconds(1),
        &Err(internal("unavailable")),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(a.display_name, old.display_name);
    assert!(a.idp_check_error);
}
