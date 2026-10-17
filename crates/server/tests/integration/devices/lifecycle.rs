//! Devices from creation through their configuration and status to deletion.

use crate::common::*;
use axum::{body::Body, http::StatusCode};
use serde_json::{Value, json};

#[tokio::test]
async fn new_devices_get_the_first_free_address() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let d = env.create_device(&user, "wg0").await;
    assert_eq!(d["grants"], json!(["10.0.0.2/32"]));
    assert_eq!(d["client_addresses"], json!(["10.0.0.2"]));
}

#[tokio::test]
async fn device_views_hide_the_preshared_key() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let d = env.create_device(&user, "wg0").await;
    assert_eq!(d.get("preshared_key"), None);
}

#[tokio::test]
async fn device_views_tag_their_revision() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let reply = env.get(&user, &format!("/api/v1/devices/{id}")).await;
    let revision = read_revision(&reply.body).unwrap();
    assert_eq!(reply.headers["etag"], format!("\"{revision}\""));
}

#[tokio::test]
async fn changes_keep_the_settings_they_do_not_mention() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let d = env.create_device(&user, "wg0").await;
    let path = format!("/api/v1/devices/{}", read_id(&d));
    let note = json!({ "note": "desk" });
    let d = env
        .call(&user, "PATCH", &path, read_revision(&d), note)
        .await
        .expect(StatusCode::OK);
    assert_eq!((&d["name"], &d["note"]), (&json!("laptop"), &json!("desk")));
}

#[tokio::test]
async fn members_list_their_own_devices() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let other = env.sign_in("other", false).await;
    let mine = read_id(&env.create_device(&user, "wg0").await);
    env.create_device(&other, "wg0").await;
    let list = env
        .get(&user, "/api/v1/devices")
        .await
        .expect(StatusCode::OK);
    let ids: Vec<_> = list.as_array().unwrap().iter().map(read_id).collect();
    assert_eq!(ids, [mine]);
}

#[tokio::test]
async fn administrators_list_every_device() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let user = env.sign_in("user", false).await;
    env.create_device(&user, "wg0").await;
    env.create_device(&admin, "wg1").await;
    let list = env
        .get(&admin, "/api/v1/devices")
        .await
        .expect(StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn administrators_create_devices_for_other_accounts() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let user = env.sign_in("user", false).await;
    let body = json!({ "account_id": user.account_id, "interface_id": "wg0", "name": "x" });
    let d = env
        .call(&admin, "POST", "/api/v1/devices", None, body)
        .await
        .expect(StatusCode::CREATED);
    assert_eq!(d["account_id"], user.account_id.as_str());
}

#[tokio::test]
async fn members_cannot_create_devices_for_other_accounts() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let other = env.sign_in("other", false).await;
    let body = json!({ "account_id": other.account_id, "interface_id": "wg0", "name": "x" });
    let reply = env.call(&user, "POST", "/api/v1/devices", None, body).await;
    assert_eq!(reply.code(), "forbidden");
}

#[tokio::test]
async fn deleted_devices_go_once_their_peer_is_gone() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let path = format!("/api/v1/devices/{id}");
    let d = env
        .call(&user, "DELETE", &path, None, Value::Null)
        .await
        .expect(StatusCode::OK);
    assert_eq!(d["deleting"], true);
    env.sync().await;
    assert_eq!(env.kernel.find_peers("wg0"), []);
    assert_eq!(env.read_device_row(&id).await, None);
}

#[tokio::test]
async fn configs_become_ready_once_the_peer_is_applied() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (_, token) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    let read_ready = async || {
        let reply = env
            .call_as_agent(&token, "GET", "/api/v1/agent/config", None, Value::Null)
            .await;
        let config = reply.expect(StatusCode::OK);
        (config["enabled"].clone(), config["ready"].clone())
    };
    assert_eq!(read_ready().await, (json!(true), json!(false)));
    env.sync().await;
    assert_eq!(read_ready().await, (json!(true), json!(true)));
}

#[tokio::test]
async fn configs_name_the_server_and_its_endpoint() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let config = env
        .get(&user, &format!("/api/v1/devices/{id}/config"))
        .await
        .expect(StatusCode::OK);
    assert_eq!(config["server_public_key"], derive_test_key(1));
    assert_eq!(config["endpoint"], "vpn.test:51820");
}

#[tokio::test]
async fn configs_offer_the_pools_without_route_profiles() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let config = env
        .get(&user, &format!("/api/v1/devices/{id}/config"))
        .await
        .expect(StatusCode::OK);
    assert_eq!(config["default_profile_id"], "pools");
    let profile = &config["route_profiles"][0];
    assert_eq!(
        (&profile["id"], &profile["allowed_ips"]),
        (&json!("pools"), &json!(["10.0.0.0/24"]))
    );
}

#[tokio::test]
async fn unchanged_configs_answer_not_modified() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let path = format!("/api/v1/devices/{id}/config");
    let etag = env.get(&user, &path).await.headers["etag"].clone();
    let request = env
        .build_request(&user, "GET", &path)
        .header("if-none-match", etag.clone())
        .body(Body::empty())
        .unwrap();
    let reply = env.send(request).await;
    assert_eq!(
        (reply.status, &reply.headers["etag"]),
        (StatusCode::NOT_MODIFIED, &etag)
    );
}

#[tokio::test]
async fn config_etags_change_with_the_device() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let d = env.create_device(&user, "wg0").await;
    let path = format!("/api/v1/devices/{}", read_id(&d));
    let before = env.get(&user, &format!("{path}/config")).await.headers["etag"].clone();
    let paused = json!({ "paused": true });
    let reply = env
        .call(&user, "PATCH", &path, read_revision(&d), paused)
        .await;
    reply.expect(StatusCode::OK);
    let after = env.get(&user, &format!("{path}/config")).await.headers["etag"].clone();
    assert_ne!(before, after);
}

#[tokio::test]
async fn device_status_shows_the_kernel_peer() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let status = env
        .get(&user, &format!("/api/v1/devices/{id}/status"))
        .await
        .expect(StatusCode::OK);
    assert_eq!(
        (
            &status["interface_up"],
            &status["peer_present"],
            &status["allowed_ips"]
        ),
        (&json!(true), &json!(true), &json!(["10.0.0.2/32"]))
    );
}

#[tokio::test]
async fn agent_status_shows_the_kernel_peer() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, token) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let status = env
        .call_as_agent(&token, "GET", "/api/v1/agent/status", None, Value::Null)
        .await
        .expect(StatusCode::OK);
    assert_eq!(
        (&status["device_id"], &status["peer_present"]),
        (&json!(id), &json!(true))
    );
}

#[tokio::test]
async fn status_without_a_link_shows_no_interface() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let id = read_id(&env.create_device(&user, "wg0").await);
    let status = env
        .get(&user, &format!("/api/v1/devices/{id}/status"))
        .await
        .expect(StatusCode::OK);
    assert_eq!(
        (&status["interface_present"], &status["peer_present"]),
        (&json!(false), &json!(false))
    );
}
