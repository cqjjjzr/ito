//! Preshared keys: set, generated or cleared by owners and agents, and installed in the kernel.

use crate::common::*;
use axum::http::StatusCode;
use base64::Engine as _;
use serde_json::{Value, json};

/// Sets the preshared key of the device `id` from `body` as the session `s`.
async fn set_psk(env: &Env, s: &Session, id: &str, body: Value) -> Reply {
    let revision = env.read_device_row(id).await.unwrap().revision;
    let path = format!("/api/v1/devices/{id}/psk");
    env.call(s, "PUT", &path, Some(revision), body).await
}

/// Reads the preshared key of the only peer on `wg0`.
fn read_kernel_psk(env: &Env) -> String {
    env.kernel.find_peers("wg0")[0].preshared_key.clone()
}

#[tokio::test]
async fn given_psks_reach_the_kernel() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    let psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let body = json!({ "preshared_key": psk });
    set_psk(&env, &user, &id, body).await.expect(StatusCode::OK);
    env.sync().await;
    assert_eq!(read_kernel_psk(&env), psk);
}

#[tokio::test]
async fn generated_psks_reach_the_kernel() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    let body = json!({ "generate": true });
    set_psk(&env, &user, &id, body).await.expect(StatusCode::OK);
    env.sync().await;
    let path = format!("/api/v1/devices/{id}/config");
    let config = env.get(&user, &path).await.expect(StatusCode::OK);
    let psk = config["preshared_key"].as_str().unwrap();
    assert_eq!((psk.len(), read_kernel_psk(&env)), (44, psk.to_string()));
}

#[tokio::test]
async fn cleared_psks_leave_the_kernel() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    let body = json!({ "generate": true });
    set_psk(&env, &user, &id, body).await.expect(StatusCode::OK);
    env.sync().await;
    let body = json!({ "preshared_key": "" });
    set_psk(&env, &user, &id, body).await.expect(StatusCode::OK);
    env.sync().await;
    assert_eq!(read_kernel_psk(&env), "");
}

#[tokio::test]
async fn psk_requests_need_exactly_one_valid_input() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    for body in [
        json!({}),
        json!({ "generate": true, "preshared_key": "" }),
        json!({ "preshared_key": "not a key" }),
    ] {
        let reply = set_psk(&env, &user, &id, body.clone()).await;
        assert_eq!(reply.code(), "invalid_request", "{body}");
    }
}

#[tokio::test]
async fn agent_psks_reach_the_kernel() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, token) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    let revision = env.read_device_row(&id).await.unwrap().revision;
    let body = json!({ "generate": true });
    let reply = env
        .call_as_agent(&token, "PUT", "/api/v1/agent/psk", Some(revision), body)
        .await;
    reply.expect(StatusCode::OK);
    env.sync().await;
    let reply = env
        .call_as_agent(&token, "GET", "/api/v1/agent/config", None, Value::Null)
        .await;
    let psk = reply.expect(StatusCode::OK)["preshared_key"].clone();
    assert_ne!(psk, "");
    assert_eq!(psk, read_kernel_psk(&env));
}
