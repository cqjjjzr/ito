//! Which committed device changes wake the reconciler and the DNS server.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::{Value, json};
use std::time::Duration;

/// Takes the pending wake-ups of the reconciler and the DNS server, returning which ones fired.
async fn take_wakeups(env: &Env) -> (bool, bool) {
    let db = &env.app.db;
    // A zero timeout still polls once, which takes a stored wake-up.
    let kernel = tokio::time::timeout(Duration::ZERO, db.wait_kernel_changed()).await;
    let dns = tokio::time::timeout(Duration::ZERO, db.wait_dns_changed()).await;
    (kernel.is_ok(), dns.is_ok())
}

/// Creates a device for a fresh member and takes the wake-ups of its creation.
async fn create_quiet_device(env: &Env) -> (Session, String) {
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    take_wakeups(env).await;
    (user, id)
}

#[tokio::test]
async fn settings_wake_only_the_components_that_use_them() {
    let env = start_env().await;
    let (user, id) = create_quiet_device(&env).await;
    let path = format!("/api/v1/devices/{id}");
    for (settings, expected) in [
        (json!({ "note": "x" }), (false, false)),
        (json!({ "dns_name": "laptop" }), (false, true)),
        (json!({ "paused": true }), (true, false)),
        (json!({ "dns_name": "" }), (false, true)),
    ] {
        let revision = env.read_device_row(&id).await.unwrap().revision;
        let reply = env
            .call(&user, "PATCH", &path, Some(revision), settings.clone())
            .await;
        reply.expect(StatusCode::OK);
        assert_eq!(take_wakeups(&env).await, expected, "{settings}");
    }
}

#[tokio::test]
async fn key_changes_wake_the_reconciler() {
    let env = start_env().await;
    let (user, id) = create_quiet_device(&env).await;
    let revision = env.read_device_row(&id).await.unwrap().revision;
    let path = format!("/api/v1/devices/{id}/key");
    let body = json!({ "public_key": derive_test_key(3) });
    let reply = env.call(&user, "POST", &path, Some(revision), body).await;
    reply.expect(StatusCode::OK);
    assert_eq!(take_wakeups(&env).await, (true, false));
}

#[tokio::test]
async fn revocations_wake_the_reconciler() {
    let env = start_env().await;
    let (user, id) = create_quiet_device(&env).await;
    let token = env.set_up_agent(&user, &id, &derive_test_key(3)).await;
    take_wakeups(&env).await;
    let reply = env
        .call_as_agent(&token, "POST", "/api/v1/agent/revoke", None, Value::Null)
        .await;
    reply.expect(StatusCode::NO_CONTENT);
    assert_eq!(take_wakeups(&env).await, (true, false));
}

#[tokio::test]
async fn blocked_accounts_wake_the_reconciler() {
    let env = start_env().await;
    let (user, id) = create_quiet_device(&env).await;
    env.set_up_agent(&user, &id, &derive_test_key(3)).await;
    take_wakeups(&env).await;
    env.block_account(&user.account_id).await;
    assert_eq!(take_wakeups(&env).await, (true, false));
}
