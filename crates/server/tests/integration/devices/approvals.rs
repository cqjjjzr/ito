//! Agent login requests: approval by the device owner, claims and their retries.

use crate::common::*;
use axum::http::StatusCode;
use chrono::Utc;
use ito::{
    db::device,
    devices,
    http::secrets::{digest_sha256, generate_secret},
};
use sea_orm::EntityTrait;
use serde_json::{Value, json};
use std::time::Duration;

#[tokio::test]
async fn agents_wait_until_their_request_is_approved() {
    let env = start_env().await;
    let reply = env
        .claim_device(&generate_secret(), &derive_test_key(5), None)
        .await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn stale_requests_cannot_be_approved() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let approval = json!({
        "id": digest_sha256(&generate_secret()),
        "t": Utc::now().timestamp() - 3600,
    });
    let path = format!("/api/v1/devices/{id}/claims");
    let reply = env.call(&user, "POST", &path, None, approval).await;
    assert_eq!(reply.code(), "invalid_request");
}

#[tokio::test]
async fn members_cannot_approve_requests_for_devices_of_others() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let other = env.sign_in("other", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let reply = env.approve_claim(&other, &id, &generate_secret()).await;
    assert_eq!(reply.code(), "not_found");
}

#[tokio::test]
async fn blocked_devices_cannot_be_approved() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let id = read_id(&env.create_device(&admin, "wg0").await);
    let path = format!("/api/v1/devices/{id}/block");
    env.call(&admin, "POST", &path, None, Value::Null)
        .await
        .expect(StatusCode::OK);
    let reply = env.approve_claim(&admin, &id, &generate_secret()).await;
    assert_eq!(reply.code(), "forbidden");
}

#[tokio::test]
async fn approved_agents_claim_the_device_with_their_key() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let secret = generate_secret();
    env.approve_claim(&user, &id, &secret)
        .await
        .expect(StatusCode::NO_CONTENT);
    let claimed = env
        .claim_device(&secret, &derive_test_key(5), Some(&id))
        .await
        .expect(StatusCode::OK);
    assert_eq!(claimed["device"]["public_key"], derive_test_key(5));
    let token = claimed["token"].as_str().unwrap();
    let reply = env
        .call_as_agent(token, "GET", "/api/v1/agent/config", None, Value::Null)
        .await;
    assert_eq!(reply.status, StatusCode::OK);
}

#[tokio::test]
async fn claims_for_another_device_are_refused() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let secret = generate_secret();
    env.approve_claim(&user, &id, &secret)
        .await
        .expect(StatusCode::NO_CONTENT);
    let reply = env
        .claim_device(&secret, &derive_test_key(5), Some("elsewhere"))
        .await;
    assert_eq!(reply.code(), "claim_device_mismatch");
    assert_eq!(env.read_device_row(&id).await.unwrap().public_key, None);
}

#[tokio::test]
async fn retried_claims_replace_the_credential() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let secret = generate_secret();
    env.approve_claim(&user, &id, &secret)
        .await
        .expect(StatusCode::NO_CONTENT);
    let key = derive_test_key(5);
    let first = env
        .claim_device(&secret, &key, None)
        .await
        .expect(StatusCode::OK);
    let again = env
        .claim_device(&secret, &key, None)
        .await
        .expect(StatusCode::OK);
    assert_ne!(again["token"], first["token"]);
    let reply = env
        .call_as_agent(
            first["token"].as_str().unwrap(),
            "GET",
            "/api/v1/agent/config",
            None,
            Value::Null,
        )
        .await;
    assert_eq!(reply.code(), "invalid_credentials");
}

#[tokio::test]
async fn self_revoked_agents_cannot_claim_again() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let secret = generate_secret();
    env.approve_claim(&user, &id, &secret)
        .await
        .expect(StatusCode::NO_CONTENT);
    let key = derive_test_key(5);
    let claimed = env
        .claim_device(&secret, &key, None)
        .await
        .expect(StatusCode::OK);
    let token = claimed["token"].as_str().unwrap();
    env.call_as_agent(token, "POST", "/api/v1/agent/revoke", None, Value::Null)
        .await
        .expect(StatusCode::NO_CONTENT);
    let reply = env.claim_device(&secret, &key, None).await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn approved_requests_stay_with_their_account() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let other = env.sign_in("other", false).await;
    let ours = read_id(&env.create_device(&user, "wg0").await);
    let theirs = read_id(&env.create_device(&other, "wg0").await);
    let secret = generate_secret();
    env.approve_claim(&user, &ours, &secret)
        .await
        .expect(StatusCode::NO_CONTENT);
    let reply = env.approve_claim(&other, &theirs, &secret).await;
    assert_eq!(reply.code(), "claim_taken");
}

#[tokio::test]
async fn revoking_the_device_cancels_its_approvals() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let secret = generate_secret();
    env.approve_claim(&user, &id, &secret)
        .await
        .expect(StatusCode::NO_CONTENT);
    let path = format!("/api/v1/devices/{id}/revoke");
    env.call(&user, "POST", &path, None, Value::Null)
        .await
        .expect(StatusCode::OK);
    let reply = env.claim_device(&secret, &derive_test_key(5), None).await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn blocking_the_account_cancels_its_approvals() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let secret = generate_secret();
    env.approve_claim(&user, &id, &secret)
        .await
        .expect(StatusCode::NO_CONTENT);
    env.block_account(&user.account_id).await;
    let reply = env.claim_device(&secret, &derive_test_key(5), None).await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn waiting_claims_cannot_revive_a_revoked_approval() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let secret = generate_secret();
    env.approve_claim(&user, &id, &secret)
        .await
        .expect(StatusCode::NO_CONTENT);
    // The claim starts while a revocation holds the write lock.
    let mut tx = env.app.db.begin_write().await.unwrap();
    let key = derive_test_key(5);
    let waiting = env.claim_device(&secret, &key, None);
    tokio::pin!(waiting);
    // With the clock paused, the timeout fires only once nothing else can run, so by then the
    // claim has gone as far as it can.
    tokio::time::pause();
    let waited = tokio::time::timeout(Duration::from_secs(1), &mut waiting).await;
    tokio::time::resume();
    assert!(waited.is_err(), "the claim waits for the write lock");
    let old = device::Entity::find_by_id(&id)
        .one(&*tx)
        .await
        .unwrap()
        .unwrap();
    let revoked = devices::revoke(&mut tx, &env.app.approvals, old.clone())
        .await
        .unwrap();
    devices::save(&mut tx, &old, revoked).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(waiting.await.status, StatusCode::ACCEPTED);
}
