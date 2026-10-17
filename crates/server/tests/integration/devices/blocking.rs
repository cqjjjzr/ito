//! Blocked devices and the devices of blocked accounts.

use crate::common::*;
use axum::http::StatusCode;
use chrono::Utc;
use serde_json::{Value, json};

/// Blocks or unblocks the device `id` as the administrator `admin`, without `If-Match`.
async fn set_blocked(env: &Env, admin: &Session, id: &str, action: &str) {
    let path = format!("/api/v1/devices/{id}/{action}");
    let reply = env.call(admin, "POST", &path, None, Value::Null).await;
    reply.expect(StatusCode::OK);
}

/// Sets the account `account_id` blocked or not with the default quota, as the administrator
/// `admin`.
async fn set_account_blocked(env: &Env, admin: &Session, account_id: &str, blocked: bool) {
    let policy = json!({ "blocked": blocked, "quota": { "ipv4": "", "ipv6": "" } });
    let reply = env.set_policy(admin, account_id, policy).await;
    reply.expect(StatusCode::OK);
}

async fn read_agent_status(env: &Env, token: &str) -> StatusCode {
    let reply = env
        .call_as_agent(token, "GET", "/api/v1/agent/config", None, Value::Null)
        .await;
    reply.status
}

#[tokio::test]
async fn blocking_needs_no_if_match() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let id = read_id(&env.create_device(&admin, "wg0").await);
    let path = format!("/api/v1/devices/{id}/block");
    let d = env
        .call(&admin, "POST", &path, None, Value::Null)
        .await
        .expect(StatusCode::OK);
    assert_eq!(d["blocked"], true);
}

#[tokio::test]
async fn blocked_devices_lose_their_peer() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let (id, _) = env
        .create_device_with_agent(&admin, "wg0", &derive_test_key(5))
        .await;
    env.sync().await;
    set_blocked(&env, &admin, &id, "block").await;
    env.sync().await;
    assert_eq!(env.kernel.find_peers("wg0"), []);
}

#[tokio::test]
async fn blocked_devices_refuse_their_agent() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let (id, token) = env
        .create_device_with_agent(&admin, "wg0", &derive_test_key(5))
        .await;
    set_blocked(&env, &admin, &id, "block").await;
    assert_eq!(
        read_agent_status(&env, &token).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn members_cannot_change_blocked_devices() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    set_blocked(&env, &admin, &id, "block").await;
    let revision = Some(env.read_device_row(&id).await.unwrap().revision);
    let path = format!("/api/v1/devices/{id}");
    for (method, action, body) in [
        ("POST", "/key", json!({})),
        ("PUT", "/psk", json!({ "generate": true })),
        ("PUT", "/addresses", json!({ "addresses": ["10.0.0.9"] })),
        ("DELETE", "", Value::Null),
    ] {
        let reply = env
            .call(&user, method, &format!("{path}{action}"), revision, body)
            .await;
        assert_eq!(reply.code(), "forbidden", "{method} {action}");
    }
}

#[tokio::test]
async fn unblocked_devices_get_their_peer_back() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let (id, _) = env
        .create_device_with_agent(&admin, "wg0", &derive_test_key(5))
        .await;
    set_blocked(&env, &admin, &id, "block").await;
    env.sync().await;
    set_blocked(&env, &admin, &id, "unblock").await;
    env.sync().await;
    assert_eq!(
        env.kernel.find_peers("wg0")[0].public_key,
        derive_test_key(5)
    );
}

#[tokio::test]
async fn unblocked_devices_accept_their_agent_again() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let (id, token) = env
        .create_device_with_agent(&admin, "wg0", &derive_test_key(5))
        .await;
    set_blocked(&env, &admin, &id, "block").await;
    set_blocked(&env, &admin, &id, "unblock").await;
    assert_eq!(read_agent_status(&env, &token).await, StatusCode::OK);
}

#[tokio::test]
async fn blocked_accounts_lose_their_agent_credentials_for_good() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let user = env.sign_in("user", false).await;
    let (_, token) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    set_account_blocked(&env, &admin, &user.account_id, true).await;
    set_account_blocked(&env, &admin, &user.account_id, false).await;
    assert_eq!(
        read_agent_status(&env, &token).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn blocked_accounts_keep_their_device_keys_expired() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    set_account_blocked(&env, &admin, &user.account_id, true).await;
    let d = env.read_device_row(&id).await.unwrap();
    assert_eq!(d.public_key, Some(derive_test_key(5)));
    assert!(d.key_expires_at.unwrap() <= Utc::now());
}

#[tokio::test]
async fn reactivated_accounts_renew_their_device_keys() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    set_account_blocked(&env, &admin, &user.account_id, true).await;
    set_account_blocked(&env, &admin, &user.account_id, false).await;
    // Blocking ended the member's sessions, so the administrator renews the key.
    let revision = env.read_device_row(&id).await.unwrap().revision;
    let path = format!("/api/v1/devices/{id}/key");
    let d = env
        .call(&admin, "POST", &path, Some(revision), json!({}))
        .await
        .expect(StatusCode::OK);
    assert_eq!(
        (&d["public_key"], &d["disabled_reason"]),
        (&json!(derive_test_key(5)), &Value::Null)
    );
}
