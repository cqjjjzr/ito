//! The reconciler against the fake kernel, and once against a real one.

use crate::common::*;
use axum::http::StatusCode;
use ito::kernel::{KernelDriver, Link, LocalKernelDriver};
use serde_json::{Value, json};
use std::sync::Arc;

/// Makes the link `name` drift from its MTU and fail to change it back, so its setup fails.
fn break_link_setup(env: &Env, name: &str) {
    env.kernel.edit_link(name, |l| l.mtu = 1000);
    env.kernel.inject_failure(&format!("{name} mtu"));
}

async fn read_apply_error(env: &Env, s: &Session, interface_id: &str) -> String {
    let path = format!("/api/v1/interfaces/{interface_id}");
    let i = env.get(s, &path).await.expect(StatusCode::OK);
    i["apply_error"].as_str().unwrap().into()
}

#[tokio::test]
async fn configured_links_come_up_with_their_settings() {
    let env = start_env().await;
    env.sync().await;
    let link = env.kernel.find_link("wg0").unwrap();
    let expected = Link {
        alias: "ito:wg0".into(),
        up: true,
        mtu: 1420,
        listen_port: 51820,
        public_key: derive_test_key(1),
        addresses: vec!["10.0.0.1/24".into()],
        peers: Vec::new(),
    };
    assert_eq!(link, expected);
}

#[tokio::test]
async fn devices_with_keys_become_peers() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    env.create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let peers = env.kernel.find_peers("wg0");
    let seen: Vec<_> = peers
        .iter()
        .map(|p| (&p.public_key, &p.allowed_ips))
        .collect();
    assert_eq!(
        seen,
        [(&derive_test_key(9), &vec!["10.0.0.2/32".to_string()])]
    );
}

#[tokio::test]
async fn idle_passes_run_no_commands() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    env.create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let before = env.kernel.list_commands().len();
    env.sync().await;
    let ran = &env.kernel.list_commands()[before..];
    assert!(ran.is_empty(), "{ran:?}");
}

#[tokio::test]
async fn paused_devices_leave_the_kernel() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let revision = env.read_device_row(&id).await.unwrap().revision;
    let path = format!("/api/v1/devices/{id}");
    let paused = json!({ "paused": true });
    let reply = env
        .call(&user, "PATCH", &path, Some(revision), paused)
        .await;
    reply.expect(StatusCode::OK);
    env.sync().await;
    assert_eq!(env.kernel.find_peers("wg0"), []);
}

#[tokio::test]
async fn drifted_mtu_and_addresses_are_repaired() {
    let env = start_env().await;
    env.sync().await;
    env.kernel.edit_link("wg0", |l| {
        l.mtu = 1000;
        l.addresses = vec!["192.0.2.1/24".into()];
    });
    env.sync().await;
    let link = env.kernel.find_link("wg0").unwrap();
    assert_eq!(
        (link.mtu, link.addresses),
        (1420, vec!["10.0.0.1/24".into()])
    );
}

#[tokio::test]
async fn disabled_interfaces_go_down_without_peers() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    env.create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let env = env.restart(|c| c.interfaces.get_mut("wg0").unwrap().disabled = true);
    env.sync().await;
    let link = env.kernel.find_link("wg0").unwrap();
    assert_eq!((link.up, link.peers), (false, Vec::new()));
}

#[tokio::test]
async fn links_of_other_owners_are_left_alone() {
    for alias in ["", "someone-else"] {
        let env = start_env().await;
        let admin = env.sign_in("admin", true).await;
        let foreign = Link {
            alias: alias.into(),
            addresses: vec!["192.0.2.1/24".into()],
            ..Link::default()
        };
        env.kernel.insert_link("wg0", foreign.clone());
        env.sync().await;
        assert_eq!(env.kernel.find_link("wg0").unwrap(), foreign, "{alias:?}");
        let error = read_apply_error(&env, &admin, "wg0").await;
        assert!(
            error.starts_with("interface_ownership_mismatch"),
            "{alias:?}: {error}"
        );
    }
}

#[tokio::test]
async fn devices_outside_the_pools_lose_their_peer() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg1", &derive_test_key(9))
        .await;
    env.sync().await;
    let env = env.restart(|c| {
        c.interfaces.get_mut("wg1").unwrap().pools[0].prefix = "10.1.1.0/24".parse().unwrap();
    });
    env.sync().await;
    assert_eq!(env.kernel.find_peers("wg1"), []);
    let d = env.get(&user, &format!("/api/v1/devices/{id}")).await;
    assert_eq!(d.body["disabled_reason"], "outside_pools", "{}", d.text);
}

#[tokio::test]
async fn devices_covering_a_server_address_lose_their_peer() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    let env = env.restart(|c| {
        c.interfaces.get_mut("wg0").unwrap().addresses = vec!["10.0.0.2/24".into()];
    });
    env.sync().await;
    assert_eq!(env.kernel.find_peers("wg0"), []);
    let d = env.get(&user, &format!("/api/v1/devices/{id}")).await;
    assert_eq!(d.body["disabled_reason"], "address_conflict", "{}", d.text);
}

#[tokio::test]
async fn removed_interfaces_lose_their_link() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let env = env.restart(|c| {
        c.interfaces.remove("wg0");
    });
    env.sync().await;
    assert_eq!(env.kernel.find_link("wg0"), None);
    let d = env.get(&user, &format!("/api/v1/devices/{id}")).await;
    assert_eq!(
        d.body["disabled_reason"], "interface_not_configured",
        "{}",
        d.text
    );
}

#[tokio::test]
async fn deleted_devices_of_removed_interfaces_stay_until_the_link_is_gone() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let env = env.restart(|c| {
        c.interfaces.remove("wg0");
    });
    let path = format!("/api/v1/devices/{id}");
    let reply = env.call(&user, "DELETE", &path, None, Value::Null).await;
    reply.expect(StatusCode::OK);
    env.kernel.inject_failure("link delete dev wg0");
    env.sync().await;
    assert!(env.read_device_row(&id).await.is_some());
    env.kernel.clear_failures();
    env.sync().await;
    assert_eq!(env.read_device_row(&id).await, None);
}

#[tokio::test]
async fn deleted_devices_keep_their_address_until_peer_removal_succeeds() {
    for revoke_first in [false, true] {
        let env = start_env().await;
        let user = env.sign_in("user", false).await;
        let key = derive_test_key(9);
        let (id, _) = env.create_device_with_agent(&user, "wg0", &key).await;
        let healthy_key = derive_test_key(10);
        env.create_device_with_agent(&user, "wg0", &healthy_key)
            .await;
        env.sync().await;
        let peers = env.kernel.find_peers("wg0");
        let path = format!("/api/v1/devices/{id}");
        if revoke_first {
            env.call(&user, "POST", &format!("{path}/revoke"), None, Value::Null)
                .await
                .expect(StatusCode::OK);
        }
        env.call(&user, "DELETE", &path, None, Value::Null)
            .await
            .expect(StatusCode::OK);
        env.kernel.inject_failure(&format!("wg0 peer {key} remove"));
        env.sync().await;

        assert_eq!(env.kernel.find_peers("wg0"), peers);
        let d = env.read_device_row(&id).await.expect("deletion is pending");
        assert!(d.deleting);
        assert!(!d.apply_error.is_empty());
        let other = env.create_device(&user, "wg0").await;
        assert_eq!(other["client_addresses"], json!(["10.0.0.4"]));

        env.kernel.clear_failures();
        env.sync().await;
        assert_eq!(env.read_device_row(&id).await, None);
        let peers = env.kernel.find_peers("wg0");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, healthy_key);
        let replacement = env.create_device(&user, "wg0").await;
        assert_eq!(replacement["client_addresses"], json!(["10.0.0.2"]));
    }
}

#[tokio::test]
async fn deleted_devices_wait_for_a_reused_key_to_stop_routing_their_address() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let key = derive_test_key(9);
    let (id, _) = env.create_device_with_agent(&user, "wg0", &key).await;
    env.create_device_with_agent(&user, "wg0", &derive_test_key(10))
        .await;
    env.sync().await;
    let path = format!("/api/v1/devices/{id}");
    env.call(&user, "DELETE", &path, None, Value::Null)
        .await
        .expect(StatusCode::OK);
    env.create_device_with_agent(&user, "wg0", &key).await;
    env.kernel.inject_failure(&format!("wg0 peer {key}"));
    env.sync().await;

    let peers = env.kernel.find_peers("wg0");
    let peer = peers.iter().find(|p| p.public_key == key).unwrap();
    assert_eq!(peer.allowed_ips, ["10.0.0.2/32"]);
    let d = env.read_device_row(&id).await.expect("deletion is pending");
    assert!(d.deleting);
    assert!(!d.apply_error.is_empty());
    let other = env.create_device(&user, "wg0").await;
    assert_eq!(other["client_addresses"], json!(["10.0.0.5"]));

    env.kernel.clear_failures();
    env.sync().await;
    assert_eq!(env.read_device_row(&id).await, None);
    let peers = env.kernel.find_peers("wg0");
    assert_eq!(peers.len(), 2);
    let peer = peers.iter().find(|p| p.public_key == key).unwrap();
    assert_eq!(peer.allowed_ips, ["10.0.0.4/32"]);
    let replacement = env.create_device(&user, "wg0").await;
    assert_eq!(replacement["client_addresses"], json!(["10.0.0.2"]));
}

#[tokio::test]
async fn edits_that_leave_the_kernel_alone_keep_devices_ready() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let path = format!("/api/v1/devices/{id}");
    let revision = env.read_device_row(&id).await.unwrap().revision;
    let note = json!({ "note": "desk" });
    let reply = env.call(&user, "PATCH", &path, Some(revision), note).await;
    reply.expect(StatusCode::OK);
    let config = env.get(&user, &format!("{path}/config")).await;
    assert_eq!(config.body["ready"], true, "{}", config.text);
}

#[tokio::test]
async fn revocations_do_not_wait_for_interface_setup() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    env.create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    break_link_setup(&env, "wg0");
    env.block_account(&user.account_id).await;
    env.sync().await;
    assert_eq!(env.kernel.find_peers("wg0"), []);
}

#[tokio::test]
async fn deleted_devices_go_although_interface_setup_fails() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let path = format!("/api/v1/devices/{id}");
    let reply = env.call(&user, "DELETE", &path, None, Value::Null).await;
    reply.expect(StatusCode::OK);
    break_link_setup(&env, "wg0");
    env.sync().await;
    assert_eq!(env.read_device_row(&id).await, None);
}

#[tokio::test]
async fn members_learn_only_that_their_interface_failed() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let (id, _) = env
        .create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    break_link_setup(&env, "wg0");
    env.sync().await;
    let d = env.get(&user, &format!("/api/v1/devices/{id}")).await;
    assert_eq!(d.body["apply_error"], "interface wg0 failed to apply");
}

#[tokio::test]
async fn disabled_interfaces_go_down_although_peer_removal_fails() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    env.create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let env = env.restart(|c| c.interfaces.get_mut("wg0").unwrap().disabled = true);
    env.kernel.inject_failure("wg0 peer");
    env.sync().await;
    assert!(!env.kernel.find_link("wg0").unwrap().up);
}

#[tokio::test]
async fn peers_of_disabled_interfaces_go_although_taking_them_down_fails() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    env.create_device_with_agent(&user, "wg0", &derive_test_key(9))
        .await;
    env.sync().await;
    let env = env.restart(|c| c.interfaces.get_mut("wg0").unwrap().disabled = true);
    env.kernel.inject_failure("wg0 down");
    env.sync().await;
    assert_eq!(env.kernel.find_peers("wg0"), []);
}

#[tokio::test]
async fn alias_failures_remove_only_the_link_just_created() {
    let env = start_env().await;
    let owned = Link {
        alias: "ito:wg1".into(),
        ..Link::default()
    };
    env.kernel.insert_link("wg1", owned);
    env.kernel.inject_failure("dev wg0 alias");
    env.sync().await;
    assert_eq!(env.kernel.find_link("wg0"), None);
    assert!(env.kernel.find_link("wg1").is_some());
}

/// Run with `just test-kernel`, which provides a disposable network namespace.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN in a disposable network namespace"]
async fn real_kernel_follows_devices_and_repairs_drift() {
    assert_eq!(std::env::var("ITO_KERNEL_TEST").as_deref(), Ok("1"));
    let kernel: Arc<dyn KernelDriver> = Arc::new(LocalKernelDriver::new().await.unwrap());
    let env = start_env_with_kernel(kernel.clone(), |_| {}).await;
    let admin = env.sign_in("admin", true).await;
    let (id, _) = env
        .create_device_with_agent(&admin, "wg0", &derive_test_key(3))
        .await;
    env.sync().await;
    let link = kernel.read_link("wg0").await.unwrap().unwrap();
    assert!(link.up);
    assert_eq!(
        (link.public_key, link.listen_port),
        (derive_test_key(1), 51820)
    );
    assert_eq!(link.addresses, ["10.0.0.1/24"]);
    assert_eq!(link.peers[0].allowed_ips, ["10.0.0.2/32"]);
    assert_eq!(env.read_device_row(&id).await.unwrap().apply_error, "");

    // Pausing the device removes its peer.
    let revision = env.read_device_row(&id).await.unwrap().revision;
    let path = format!("/api/v1/devices/{id}");
    let paused = json!({ "paused": true });
    let reply = env
        .call(&admin, "PATCH", &path, Some(revision), paused)
        .await;
    reply.expect(StatusCode::OK);
    env.sync().await;
    let link = kernel.read_link("wg0").await.unwrap().unwrap();
    assert_eq!(link.peers, []);

    // Addresses flushed outside the controller come back on the next pass.
    std::process::Command::new("ip")
        .args(["address", "flush", "dev", "wg0"])
        .status()
        .unwrap();
    env.sync().await;
    let link = kernel.read_link("wg0").await.unwrap().unwrap();
    assert_eq!(link.addresses, ["10.0.0.1/24"]);

    // An interface removed from the configuration loses its link.
    let env = env.restart(|c| {
        c.interfaces.remove("wg0");
    });
    env.sync().await;
    assert_eq!(kernel.read_link("wg0").await.unwrap(), None);
}
