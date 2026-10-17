//! Who may read and change devices: owners, administrators and agents, checked again inside each
//! write.

use crate::common::*;
use axum::{
    extract::FromRequestParts,
    http::{Request, StatusCode},
};
use ito::{
    db::agent_credential,
    error::Code,
    http::{
        extract::{AuthenticatedAgent, AuthenticatedUser},
        secrets::digest_sha256,
    },
};
use sea_orm::EntityTrait;
use serde_json::{Value, json};

#[tokio::test]
async fn members_cannot_see_devices_of_others() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let other = env.sign_in("other", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let reply = env.get(&other, &format!("/api/v1/devices/{id}")).await;
    assert_eq!(reply.code(), "not_found");
}

#[tokio::test]
async fn user_writes_check_the_session_again_inside_the_transaction() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let request = env.build_request(&admin, "POST", "/").body(()).unwrap();
    let (mut parts, ()) = request.into_parts();
    let user = AuthenticatedUser::from_request_parts(&mut parts, &env.app)
        .await
        .unwrap();
    env.block_account(&admin.account_id).await;
    let Err(refused) = user.begin(&env.app).await else {
        panic!("a write began for a blocked account");
    };
    assert_eq!(refused.code, Code::InvalidCredentials);
}

#[tokio::test]
async fn agent_writes_check_the_credential_again_inside_the_transaction() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (_, token) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    let request = Request::post("/")
        .header("authorization", format!("Bearer {token}"))
        .body(())
        .unwrap();
    let (mut parts, ()) = request.into_parts();
    let agent = AuthenticatedAgent::from_request_parts(&mut parts, &env.app)
        .await
        .unwrap();
    env.block_account(&user.account_id).await;
    let Err(refused) = agent.begin(&env.app).await else {
        panic!("a write began for a blocked account");
    };
    assert_eq!(refused.code, Code::InvalidCredentials);
}

#[tokio::test]
async fn revocation_needs_no_if_match() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, token) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    // The agent changes its device by renewing its key, which leaves the owner's view stale.
    let revision = env.read_device_row(&id).await.unwrap().revision;
    env.call_as_agent(
        &token,
        "POST",
        "/api/v1/agent/key",
        Some(revision),
        json!({}),
    )
    .await
    .expect(StatusCode::OK);
    let path = format!("/api/v1/devices/{id}/revoke");
    let reply = env.call(&user, "POST", &path, None, Value::Null).await;
    reply.expect(StatusCode::OK);
}

#[tokio::test]
async fn revocation_checks_a_sent_if_match() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    let stale = env.read_device_row(&id).await.unwrap().revision - 1;
    let path = format!("/api/v1/devices/{id}/revoke");
    let reply = env
        .call(&user, "POST", &path, Some(stale), Value::Null)
        .await;
    assert_eq!(reply.code(), "revision_conflict");
}

#[tokio::test]
async fn revoked_agents_are_unauthorized() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, token) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    let path = format!("/api/v1/devices/{id}/revoke");
    env.call(&user, "POST", &path, None, Value::Null)
        .await
        .expect(StatusCode::OK);
    let reply = env
        .call_as_agent(&token, "GET", "/api/v1/agent/device", None, Value::Null)
        .await;
    assert_eq!(reply.code(), "invalid_credentials");
}

#[tokio::test]
async fn agents_cannot_change_their_device_settings() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (_, token) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    let body = json!({ "name": "x" });
    let reply = env
        .call_as_agent(&token, "PATCH", "/api/v1/agent/device", None, body)
        .await;
    assert_eq!(reply.code(), "method_not_allowed");
}

#[tokio::test]
async fn stored_agent_credential_ids_do_not_authenticate() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (_, token) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    let rows = agent_credential::Entity::find()
        .all(&env.app.db.conn)
        .await
        .unwrap();
    // The database holds the digest of the secret, which works as a token no better than a guess.
    assert_eq!(
        rows[0].id,
        digest_sha256(token.strip_prefix("itoa_").unwrap())
    );
    let stolen = format!("itoa_{}", rows[0].id);
    let reply = env
        .call_as_agent(&stolen, "GET", "/api/v1/agent/config", None, Value::Null)
        .await;
    assert_eq!(reply.code(), "invalid_credentials");
}
