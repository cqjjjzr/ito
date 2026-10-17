//! Keeping saved connections and their tunnels in step with the controller: connecting,
//! synchronizing, key rotation, status and logging out.

use super::*;
use mockall::Sequence;
use wiremock::matchers::body_json;

#[tokio::test]
async fn connecting_brings_the_tunnel_up_with_the_default_profile() {
    let server = start_mock_controller().await;
    let mut tunnel = build_mock_tunnel(false);
    tunnel
        .expect_up()
        .withf(|name, spec| {
            name == "ito-a" && spec.peer.allowed_ips == ["10.0.0.0/24", "fd00::/64"]
        })
        .times(1)
        .returning(|_, _| Ok(()));
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Disconnected);
    let summary = agent.connect("ito-a").await.unwrap();
    assert_eq!(summary.state, Connected);
    assert_eq!(summary.last_error, None);
}

#[tokio::test]
async fn unknown_connections_are_reported() {
    let (_dir, agent) = start_agent(MockTunnelDriver::new());
    assert!(matches!(
        agent.connect("ito-0").await,
        Err(AgentError::Unknown(_))
    ));
}

#[tokio::test]
async fn unchanged_configs_leave_running_tunnels_alone() {
    let server = start_mock_controller().await;
    // The mock has no `up` or `down` expectation, so restarting the tunnel would fail it.
    let (dir, agent) = start_agent(build_mock_tunnel(true));
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    agent.sync_all().await.unwrap();
    assert_eq!(agent.load("ito-a").unwrap().state, Connected);
}

#[tokio::test]
async fn failed_restarts_are_retried_even_when_the_driver_follows_external_state() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let server = start_mock_controller().await;
    let running = Arc::new(AtomicBool::new(true));
    let mut tunnel = MockTunnelDriver::new();
    let current = running.clone();
    tunnel
        .expect_is_up()
        .returning(move |_| Ok(current.load(Ordering::SeqCst)));
    let current = running.clone();
    tunnel.expect_down().times(1).returning(move |_| {
        current.store(false, Ordering::SeqCst);
        Ok(())
    });
    let mut attempts = 0;
    tunnel.expect_up().times(2).returning(move |_, _| {
        attempts += 1;
        if attempts == 1 {
            return Err(TunnelError("temporary install failure".into()));
        }
        running.store(true, Ordering::SeqCst);
        Ok(())
    });
    tunnel.expect_reconcile().times(1).returning(|_, _| Ok(()));
    tunnel.expect_follows_external_state().return_const(true);
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    assert!(agent.set_profile("ito-a", Some("all"), None).await.is_err());
    let failed = agent.load("ito-a").unwrap();
    assert_eq!(failed.state, Errored);
    assert!(
        failed
            .last_error
            .unwrap()
            .contains("temporary install failure")
    );
    agent.sync_all().await.unwrap();
    let recovered = agent.load("ito-a").unwrap();
    assert_eq!(recovered.state, Connected);
    assert_eq!(recovered.last_error, None);
}

#[tokio::test]
async fn failed_disconnects_are_retried_without_reconnecting() {
    let server = start_mock_controller().await;
    let mut tunnel = MockTunnelDriver::new();
    tunnel.expect_is_up().returning(|_| Ok(true));
    tunnel.expect_follows_external_state().return_const(true);
    let mut attempts = 0;
    tunnel.expect_down().times(2).returning(move |_| {
        attempts += 1;
        if attempts == 1 {
            Err(TunnelError("temporarily busy".into()))
        } else {
            Ok(())
        }
    });
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    assert!(agent.disconnect("ito-a").await.is_err());
    assert_eq!(agent.load("ito-a").unwrap().state, Disconnecting);
    agent.sync_all().await.unwrap();
    assert_eq!(agent.load("ito-a").unwrap().state, Disconnected);
}

#[tokio::test]
async fn unreadable_connection_files_are_reported_while_the_rest_keep_syncing() {
    let server = start_mock_controller().await;
    let mut tunnel = MockTunnelDriver::new();
    tunnel.expect_is_up().returning(|name| Ok(name == "ito-a"));
    tunnel.expect_reconcile().times(1).returning(|_, _| Ok(()));
    tunnel.expect_follows_external_state().return_const(false);
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    std::fs::write(dir.path().join("ito-b.json"), "broken").unwrap();
    std::fs::write(dir.path().join("unrelated.json"), "broken").unwrap();
    let error = agent.sync_all().await.unwrap_err().to_string();
    assert!(error.contains("ito-b.json") && !error.contains("unrelated.json"));
    assert_eq!(agent.list().await.unwrap().len(), 1);
    assert_eq!(agent.load("ito-a").unwrap().state, Connected);
}

#[tokio::test]
async fn revoked_credentials_take_the_tunnel_down() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let mut tunnel = build_mock_tunnel(true);
    tunnel.expect_down().times(1).returning(|_| Ok(()));
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    agent.sync_all().await.unwrap();
    let summary = &agent.list().await.unwrap()[0];
    assert!(summary.revoked);
    assert_eq!(summary.last_error, None);
}

#[tokio::test]
async fn revocation_clears_when_the_credential_works_again() {
    let server = start_mock_controller().await;
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_test_connection(dir.path(), "ito-a", &server.uri(), Disconnected);
    change_saved_connection(&agent, "ito-a", |c| c.revoked = true);
    agent.sync_all().await.unwrap();
    assert!(!agent.load("ito-a").unwrap().revoked);
}

#[tokio::test]
async fn keys_near_expiry_are_renewed() {
    let server = start_mock_controller().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/agent/key"))
        .and(body_json(json!({ "public_key": null })))
        .respond_with(ResponseTemplate::new(200).set_body_json(build_device_json(2)))
        .expect(1)
        .mount(&server)
        .await;
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_test_connection(dir.path(), "ito-a", &server.uri(), Disconnected);
    change_saved_connection(&agent, "ito-a", |c| {
        let soon = Utc::now() + chrono::TimeDelta::days(2);
        c.config.as_mut().unwrap().config.key_expires_at = Some(soon);
    });
    agent.sync_all().await.unwrap();
    assert_eq!(agent.load("ito-a").unwrap().device.revision, 2);
}

#[tokio::test]
async fn unreachable_controllers_leave_the_cached_tunnel_up_with_the_error() {
    // The mock has no `up` or `down` expectation, so restarting the tunnel would fail it.
    let (dir, agent) = start_agent(build_mock_tunnel(true));
    save_test_connection(dir.path(), "ito-a", UNREACHABLE_PORTAL, Connected);
    agent.sync_all().await.unwrap();
    let c = agent.load("ito-a").unwrap();
    assert_eq!(c.state, Connected);
    assert!(c.last_error.unwrap().starts_with("controller unreachable"));
}

#[tokio::test]
async fn tunnels_stopped_outside_the_agent_are_saved_as_disconnected() {
    let server = start_mock_controller().await;
    let mut tunnel = MockTunnelDriver::new();
    tunnel.expect_is_up().returning(|_| Ok(false));
    tunnel.expect_follows_external_state().return_const(true);
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    agent.sync_all().await.unwrap();
    assert_eq!(agent.load("ito-a").unwrap().state, Disconnected);
}

#[tokio::test]
async fn tunnels_started_outside_the_agent_are_saved_as_connected() {
    let server = start_mock_controller().await;
    let mut tunnel = MockTunnelDriver::new();
    tunnel.expect_is_up().returning(|_| Ok(true));
    tunnel.expect_follows_external_state().return_const(true);
    tunnel.expect_reconcile().returning(|_, _| Ok(()));
    // The agent restarts the tunnel with its own spec, since it never applied one.
    tunnel.expect_down().returning(|_| Ok(()));
    tunnel.expect_up().returning(|_, _| Ok(()));
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Disconnected);
    agent.sync_all().await.unwrap();
    assert_eq!(agent.load("ito-a").unwrap().state, Connected);
}

#[tokio::test]
async fn logging_out_revokes_the_credential_and_forgets_the_connection() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/agent/revoke"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let mut tunnel = MockTunnelDriver::new();
    tunnel.expect_remove().times(1).returning(|_| Ok(()));
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    assert!(agent.logout("ito-a").await.unwrap());
    assert!(agent.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn logging_out_without_the_controller_still_forgets_the_connection() {
    let mut tunnel = MockTunnelDriver::new();
    tunnel.expect_remove().times(1).returning(|_| Ok(()));
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", UNREACHABLE_PORTAL, Connected);
    assert!(!agent.logout("ito-a").await.unwrap());
    assert!(agent.list().await.unwrap().is_empty());
}

/// Makes `server` accept every new key for the device, answering with revision 2.
async fn accept_keys(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/v1/agent/key"))
        .and(header("if-match", "\"1\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(build_device_json(2)))
        .mount(server)
        .await;
}

#[tokio::test]
async fn rotated_keys_are_saved_before_the_tunnel_restarts() {
    let server = start_mock_controller().await;
    accept_keys(&server).await;
    let dir = create_private_dir();
    let state_path = dir.path().to_owned();
    let mut tunnel = build_mock_tunnel(true);
    let mut order = Sequence::new();
    tunnel
        .expect_down()
        .times(1)
        .in_sequence(&mut order)
        .returning(|_| Ok(()));
    tunnel
        .expect_up()
        .times(1)
        .in_sequence(&mut order)
        .returning(move |name, spec| {
            let saved = StateDir::open(&state_path).unwrap().load(name).unwrap();
            if saved.unwrap().private_key != spec.private_key {
                return Err(TunnelError("the new key was not saved first".into()));
            }
            Ok(())
        });
    let agent = Agent::new(StateDir::open(dir.path()).unwrap(), tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    let old_key = agent.load("ito-a").unwrap().private_key;
    agent.rotate_key("ito-a").await.unwrap();
    assert_ne!(agent.load("ito-a").unwrap().private_key, old_key);
}

#[tokio::test]
async fn rotated_keys_send_only_their_public_half() {
    use base64::Engine as _;
    let server = start_mock_controller().await;
    accept_keys(&server).await;
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_test_connection(dir.path(), "ito-a", &server.uri(), Disconnected);
    agent.rotate_key("ito-a").await.unwrap();
    let private_key = base64::engine::general_purpose::STANDARD
        .decode(agent.load("ito-a").unwrap().private_key)
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    let upload = requests
        .iter()
        .find(|r| r.url.path() == "/api/v1/agent/key");
    let sent: Value = upload.unwrap().body_json().unwrap();
    let public_key = ito_shared::keys::derive_public_key(&private_key.try_into().unwrap());
    assert_eq!(sent, json!({ "public_key": public_key }));
}

#[tokio::test]
async fn psk_rotation_restarts_the_tunnel_with_the_new_key() {
    let server = start_mock_controller().await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/agent/psk"))
        .and(body_json(json!({ "generate": true })))
        .respond_with(ResponseTemplate::new(200).set_body_json(build_device_json(2)))
        .expect(1)
        .mount(&server)
        .await;
    let new_psk = ito_shared::keys::generate_key_pair().public;
    let mut rotated = build_sample_config();
    rotated.preshared_key = new_psk.clone();
    // The controller's config changes with the key, so it now outranks the `304` answer.
    Mock::given(method("GET"))
        .and(path("/api/v1/agent/config"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(rotated)
                .insert_header("etag", "\"e2\""),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    let mut tunnel = build_mock_tunnel(true);
    tunnel.expect_down().times(1).returning(|_| Ok(()));
    tunnel
        .expect_up()
        .withf(move |_, spec| spec.peer.preshared_key == new_psk)
        .times(1)
        .returning(|_, _| Ok(()));
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    agent.rotate_psk("ito-a").await.unwrap();
}

#[tokio::test]
async fn status_combines_the_local_link_and_the_controller_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/agent/status"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({ "title": "Busy" })))
        .mount(&server)
        .await;
    let mut tunnel = MockTunnelDriver::new();
    tunnel.expect_read().returning(|_| {
        Ok(Some(Link {
            mtu: 1380,
            ..Link::default()
        }))
    });
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    let status = agent.status("ito-a").await.unwrap();
    assert_eq!(status.local.map(|l| l.mtu), Some(1380));
    assert_eq!(status.server, None);
    assert_eq!(status.server_error.as_deref(), Some("Busy"));
}
