//! Device addresses, grants and extra routes: pools, quotas and overlaps.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

async fn create_device_with(env: &Env, s: &Session, body: Value) -> Reply {
    env.call(s, "POST", "/api/v1/devices", None, body).await
}

/// Sets the extra routes of the device `id` as the administrator `admin`.
async fn set_allowed_ips(env: &Env, admin: &Session, id: &str, routes: Value) -> Reply {
    let revision = env.read_device_row(id).await.unwrap().revision;
    let path = format!("/api/v1/devices/{id}/allowed-ips");
    let body = json!({ "allowed_ips": routes });
    env.call(admin, "PUT", &path, Some(revision), body).await
}

/// Sets the addresses of the device `id` as the session `s`.
async fn set_addresses(env: &Env, s: &Session, id: &str, body: Value) -> Reply {
    let revision = env.read_device_row(id).await.unwrap().revision;
    let path = format!("/api/v1/devices/{id}/addresses");
    env.call(s, "PUT", &path, Some(revision), body).await
}

#[tokio::test]
async fn addresses_of_other_devices_are_refused() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let other = env.sign_in("other", false).await;
    env.create_device(&user, "wg0").await;
    let body = json!({ "interface_id": "wg0", "name": "x", "grants": ["10.0.0.2/32"] });
    let reply = create_device_with(&env, &other, body).await;
    assert_eq!(reply.code(), "address_conflict");
}

#[tokio::test]
async fn grants_beyond_the_quota_are_refused() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let grants = json!(["10.0.0.32/28", "10.0.0.48/28"]);
    let body = json!({ "interface_id": "wg0", "name": "x", "grants": grants });
    let reply = create_device_with(&env, &user, body).await;
    assert_eq!(reply.code(), "address_quota_exceeded");
}

#[tokio::test]
async fn concurrent_requests_for_one_address_admit_one_device() {
    let env = start_env().await;
    let users = [env.sign_in("a", false).await, env.sign_in("b", false).await];
    let body = json!({ "interface_id": "wg0", "name": "x", "grants": ["10.0.0.99/32"] });
    let (one, two) = tokio::join!(
        create_device_with(&env, &users[0], body.clone()),
        create_device_with(&env, &users[1], body.clone()),
    );
    let mut codes = [one.status, two.status];
    codes.sort();
    assert_eq!(codes, [StatusCode::CREATED, StatusCode::CONFLICT]);
}

#[tokio::test]
async fn devices_hold_at_most_max_prefixes_grants_of_a_pool() {
    // The pools allow four grants per device.
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    for (count, code) in [(4, ""), (5, "invalid_request")] {
        let addresses: Vec<String> = (0..count)
            .map(|n| format!("10.0.0.{}", count * 10 + n))
            .collect();
        let body = json!({ "interface_id": "wg0", "name": "x", "addresses": addresses });
        let reply = create_device_with(&env, &user, body).await;
        assert_eq!(reply.code(), code, "{count} addresses");
    }
}

#[tokio::test]
async fn allocated_grants_come_with_an_address_of_their_own() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let block = json!([{ "pool": "10.0.0.0/24", "prefix_length": 29 }]);
    let body = json!({ "interface_id": "wg0", "name": "router", "allocate_grants": block });
    let d = create_device_with(&env, &user, body)
        .await
        .expect(StatusCode::CREATED);
    assert_eq!(d["grants"], json!(["10.0.0.2/32", "10.0.0.8/29"]));
    assert_eq!(d["client_addresses"], json!(["10.0.0.2"]));
}

#[tokio::test]
async fn addresses_inside_a_grant_need_no_grant_of_their_own() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let body = json!({ "addresses": ["10.0.0.9"], "grants": ["10.0.0.8/29"] });
    let d = set_addresses(&env, &user, &id, body)
        .await
        .expect(StatusCode::OK);
    assert_eq!(d["grants"], json!(["10.0.0.8/29"]));
    assert_eq!(d["client_addresses"], json!(["10.0.0.9"]));
}

#[tokio::test]
async fn addresses_must_be_single_hosts() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let body = json!({ "addresses": ["10.0.0.16/28"] });
    let reply = set_addresses(&env, &user, &id, body).await;
    assert_eq!(reply.code(), "invalid_request");
}

#[tokio::test]
async fn allocated_addresses_join_the_given_ones() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let body = json!({ "addresses": ["10.0.0.9"], "allocate_addresses": ["10.0.0.0/24"] });
    let d = set_addresses(&env, &user, &id, body)
        .await
        .expect(StatusCode::OK);
    assert_eq!(d["client_addresses"], json!(["10.0.0.2", "10.0.0.9"]));
}

#[tokio::test]
async fn extra_routes_inside_a_pool_are_not_allocated() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let gateway = read_id(&env.create_device(&admin, "wg0").await);
    let routes = json!(["10.0.0.3/32", "0.0.0.0/0"]);
    set_allowed_ips(&env, &admin, &gateway, routes)
        .await
        .expect(StatusCode::OK);
    let next = env.create_device(&admin, "wg0").await;
    assert_eq!(next["grants"], json!(["10.0.0.4/32"]));
}

#[tokio::test]
async fn extra_routes_cannot_cover_grants_of_other_devices() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let gateway = read_id(&env.create_device(&admin, "wg0").await);
    env.create_device(&admin, "wg0").await;
    let reply = set_allowed_ips(&env, &admin, &gateway, json!(["10.0.0.0/24"])).await;
    assert_eq!(
        (reply.code(), &reply.body["detail"]),
        ("address_conflict", &json!("10.0.0.0/24"))
    );
}

#[tokio::test]
async fn extra_routes_may_nest() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let a = read_id(&env.create_device(&admin, "wg0").await);
    let b = read_id(&env.create_device(&admin, "wg0").await);
    let reply = set_allowed_ips(&env, &admin, &a, json!(["10.0.0.128/25"])).await;
    reply.expect(StatusCode::OK);
    let reply = set_allowed_ips(&env, &admin, &b, json!(["10.0.0.192/26"])).await;
    reply.expect(StatusCode::OK);
}

#[tokio::test]
async fn extra_routes_cannot_repeat() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let a = read_id(&env.create_device(&admin, "wg0").await);
    let b = read_id(&env.create_device(&admin, "wg0").await);
    let reply = set_allowed_ips(&env, &admin, &a, json!(["10.0.0.128/25"])).await;
    reply.expect(StatusCode::OK);
    let reply = set_allowed_ips(&env, &admin, &b, json!(["10.0.0.128/25"])).await;
    assert_eq!(reply.code(), "address_conflict");
}

#[tokio::test]
async fn extra_routes_of_deleting_devices_cannot_change() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let id = read_id(&env.create_device(&admin, "wg0").await);
    let path = format!("/api/v1/devices/{id}");
    let reply = env.call(&admin, "DELETE", &path, None, Value::Null).await;
    reply.expect(StatusCode::OK);
    let reply = set_allowed_ips(&env, &admin, &id, json!([])).await;
    assert_eq!(reply.code(), "not_found");
}
