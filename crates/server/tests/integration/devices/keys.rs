//! Device keys: binding, uniqueness, expiry, renewal and revocation.

use crate::common::*;
use axum::http::StatusCode;
use ito::http::secrets::generate_secret;
use serde_json::{Value, json};

/// Posts `body` to the key endpoint of the device `id` as the session `s`, at its revision.
async fn set_key(env: &Env, s: &Session, id: &str, body: Value) -> Reply {
    let revision = env.read_device_row(id).await.unwrap().revision;
    let path = format!("/api/v1/devices/{id}/key");
    env.call(s, "POST", &path, Some(revision), body).await
}

#[tokio::test]
async fn keys_held_by_another_device_are_refused() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let user = env.sign_in("user", false).await;
    let other = env.sign_in("other", false).await;
    let held = derive_test_key(7);
    let (holder, _) = env.create_device_with_agent(&user, "wg0", &held).await;
    let (sibling, sibling_token) = env
        .create_device_with_agent(&user, "wg1", &derive_test_key(8))
        .await;
    let theirs = read_id(&env.create_device(&other, "wg0").await);
    let holder_before = env.read_device_row(&holder).await;
    let body = json!({ "public_key": held });
    let revision = env.read_device_row(&sibling).await.unwrap().revision;
    for (case, reply) in [
        (
            "owner on a sibling",
            set_key(&env, &user, &sibling, body.clone()).await,
        ),
        (
            "administrator",
            set_key(&env, &admin, &sibling, body.clone()).await,
        ),
        (
            "another account",
            set_key(&env, &other, &theirs, body.clone()).await,
        ),
        (
            "sibling's agent",
            env.call_as_agent(
                &sibling_token,
                "POST",
                "/api/v1/agent/key",
                Some(revision),
                body.clone(),
            )
            .await,
        ),
    ] {
        assert_eq!(reply.code(), "key_conflict", "{case}");
    }
    assert_eq!(env.read_device_row(&holder).await, holder_before);
}

#[tokio::test]
async fn claims_cannot_take_another_devices_key() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let held = derive_test_key(7);
    env.create_device_with_agent(&user, "wg0", &held).await;
    let sibling = read_id(&env.create_device(&user, "wg1").await);
    let secret = generate_secret();
    env.approve_claim(&user, &sibling, &secret)
        .await
        .expect(StatusCode::NO_CONTENT);
    let reply = env.claim_device(&secret, &held, None).await;
    assert_eq!(reply.code(), "key_conflict");
}

#[tokio::test]
async fn server_keys_are_refused() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let reply = set_key(
        &env,
        &user,
        &id,
        json!({ "public_key": derive_test_key(1) }),
    )
    .await;
    assert_eq!(reply.code(), "key_conflict");
}

#[tokio::test]
async fn expired_keys_leave_the_kernel() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    env.sync().await;
    env.expire_key(&id).await;
    env.sync().await;
    assert_eq!(env.kernel.find_peers("wg0"), []);
    let d = env.get(&user, &format!("/api/v1/devices/{id}")).await;
    assert_eq!(d.body["disabled_reason"], "key_expired");
}

#[tokio::test]
async fn agents_replace_expired_keys() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, token) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    env.expire_key(&id).await;
    let revision = env.read_device_row(&id).await.unwrap().revision;
    let body = json!({ "public_key": derive_test_key(6) });
    let d = env
        .call_as_agent(&token, "POST", "/api/v1/agent/key", Some(revision), body)
        .await
        .expect(StatusCode::OK);
    assert_eq!(d["disabled_reason"], Value::Null);
    env.sync().await;
    assert_eq!(
        env.kernel.find_peers("wg0")[0].public_key,
        derive_test_key(6)
    );
}

#[tokio::test]
async fn renewals_without_a_key_extend_the_current_one() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    env.expire_key(&id).await;
    let d = set_key(&env, &user, &id, json!({}))
        .await
        .expect(StatusCode::OK);
    assert_eq!(
        (&d["public_key"], &d["disabled_reason"]),
        (&json!(derive_test_key(5)), &Value::Null)
    );
}

#[tokio::test]
async fn new_agents_replace_the_previous_credential() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, first) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    env.set_up_agent(&user, &id, &derive_test_key(6)).await;
    let reply = env
        .call_as_agent(&first, "GET", "/api/v1/agent/config", None, Value::Null)
        .await;
    assert_eq!(reply.code(), "invalid_credentials");
}

#[tokio::test]
async fn revoking_a_device_clears_its_key() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    let path = format!("/api/v1/devices/{id}/revoke");
    let d = env
        .call(&user, "POST", &path, None, Value::Null)
        .await
        .expect(StatusCode::OK);
    assert_eq!(
        (&d["public_key"], &d["key_expires_at"]),
        (&Value::Null, &Value::Null)
    );
}

#[tokio::test]
async fn revoked_devices_cannot_renew_keys() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(5))
        .await;
    let path = format!("/api/v1/devices/{id}/revoke");
    env.call(&user, "POST", &path, None, Value::Null)
        .await
        .expect(StatusCode::OK);
    let reply = set_key(&env, &user, &id, json!({})).await;
    assert_eq!(reply.code(), "invalid_request");
}
