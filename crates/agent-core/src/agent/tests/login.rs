//! Logging in: tickets, polling for approval and installing the claimed connection.

use super::*;

/// Makes `server` approve every claim for the device [`DEVICE_ID`] at revision 2.
async fn approve_claims(server: &MockServer) {
    let claimed = json!({ "token": "itoa_new", "device": build_device_json(2) });
    answer_claims(server, ResponseTemplate::new(200).set_body_json(claimed)).await;
}

/// Logs in to `portal` without connecting, polling without pause.
async fn log_in(
    agent: &Agent<MockTunnelDriver>,
    portal: &str,
    device: Option<&str>,
    no_dns: bool,
) -> LoginOutcome {
    let ticket = agent.begin_login(portal, device, "box", no_dns);
    let claimed = agent.await_claim(&ticket.request, Duration::ZERO).await;
    agent.install_claim(claimed.unwrap(), false).await.unwrap()
}

/// Backdates the pending login `request` to the Unix epoch, long past its expiry.
fn expire_ticket(agent: &Agent<MockTunnelDriver>, request: &str) {
    let mut logins = agent.logins.lock().unwrap();
    logins.get_mut(request).unwrap().ticket.requested_at = 0;
}

/// The interval at which `poll_new_login` polls.
const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Polls a new login on `portal` every [`POLL_INTERVAL`] and returns the result with the time it
/// took.
async fn poll_new_login(
    agent: &Agent<MockTunnelDriver>,
    portal: &str,
) -> (Result<ClaimedLogin>, Duration) {
    let ticket = agent.begin_login(portal, None, "box", false);
    let started = tokio::time::Instant::now();
    let result = agent.await_claim(&ticket.request, POLL_INTERVAL).await;
    (result, started.elapsed())
}

/// Saves connection `ito-a` for the device that `approve_claims` approves, with an old credential, a
/// revocation and local preferences.
fn save_connection_of_claimed_device(agent: &Agent<MockTunnelDriver>, dir: &Path, portal: &str) {
    save_test_connection(dir, "ito-a", portal, Disconnected);
    change_saved_connection(agent, "ito-a", |c| {
        c.device.id = DEVICE_ID.into();
        c.token = "itoa_old".into();
        c.revoked = true;
        c.no_dns = true;
        c.custom_allowed_ips = Some(vec!["10.2.0.0/24".into()]);
    });
}

#[tokio::test(start_paused = true)]
async fn abandoned_logins_are_pruned_while_fresh_ones_stay() {
    let (_dir, agent) = start_agent(MockTunnelDriver::new());
    let abandoned = agent.begin_login("https://vpn.test", None, "box", false);
    let fresh = agent.begin_login("https://vpn.test", None, "box", false);
    // The login expires after the pruner's first pass, so only a later pass can remove it.
    let expire_then_wait_a_minute = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        expire_ticket(&agent, &abandoned.request);
        tokio::time::sleep(Duration::from_secs(60)).await;
    };
    tokio::select! {
        () = agent.expire_logins() => unreachable!("the pruner runs forever"),
        () = expire_then_wait_a_minute => {}
    }
    let logins = agent.logins.lock().unwrap();
    assert!(!logins.contains_key(&abandoned.request));
    assert!(logins.contains_key(&fresh.request));
}

#[tokio::test]
async fn expired_tickets_are_refused_before_polling() {
    let server = MockServer::start().await;
    let (_dir, agent) = start_agent(MockTunnelDriver::new());
    let ticket = agent.begin_login(&server.uri(), None, "box", false);
    expire_ticket(&agent, &ticket.request);
    let claimed = agent.await_claim(&ticket.request, Duration::ZERO).await;
    assert!(matches!(claimed, Err(AgentError::Refused(_))));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn unknown_login_requests_are_refused() {
    let (_dir, agent) = start_agent(MockTunnelDriver::new());
    let claimed = agent.await_claim("0123", Duration::ZERO).await;
    assert!(matches!(claimed, Err(AgentError::Refused(_))));
}

#[tokio::test]
async fn claim_polling_retries_bad_gateway_and_unavailable_answers() {
    let server = MockServer::start().await;
    for (priority, status) in [(1, 503), (2, 502)] {
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(status))
            .with_priority(priority)
            .up_to_n_times(1)
            .mount(&server)
            .await;
    }
    approve_claims(&server).await;
    let (_dir, agent) = start_agent(MockTunnelDriver::new());
    let ticket = agent.begin_login(&server.uri(), None, "box", false);
    agent
        .await_claim(&ticket.request, Duration::ZERO)
        .await
        .unwrap();
    let sent = server.received_requests().await.unwrap();
    assert_eq!(sent.len(), 3);
    assert!(sent.windows(2).all(|pair| pair[0].body == pair[1].body));
}

#[tokio::test]
async fn claim_polling_stops_at_other_problems() {
    let server = MockServer::start().await;
    answer_claims(&server, ResponseTemplate::new(400)).await;
    let (_dir, agent) = start_agent(MockTunnelDriver::new());
    let ticket = agent.begin_login(&server.uri(), None, "box", false);
    let claimed = agent.await_claim(&ticket.request, Duration::ZERO).await;
    assert!(matches!(
        claimed,
        Err(AgentError::Client(ClientError::Problem { status: 400, .. }))
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn claim_polling_gives_up_at_the_deadline() {
    let server = MockServer::start().await;
    answer_claims(&server, ResponseTemplate::new(202)).await;
    let (_dir, agent) = start_agent(MockTunnelDriver::new());
    let (claimed, waited) = poll_new_login(&agent, &server.uri()).await;
    assert!(matches!(claimed, Err(AgentError::Refused(_))));
    // The last poll may come up to one interval, plus the second the ticket aged, before the end.
    assert!(waited >= LOGIN_TIMEOUT - 2 * POLL_INTERVAL);
}

#[tokio::test(start_paused = true)]
async fn claim_polling_survives_network_errors_until_the_deadline() {
    let (_dir, agent) = start_agent(MockTunnelDriver::new());
    let (claimed, waited) = poll_new_login(&agent, UNREACHABLE_PORTAL).await;
    assert!(matches!(claimed, Err(AgentError::Refused(_))));
    // The last poll may come up to one interval, plus the second the ticket aged, before the end.
    assert!(waited >= LOGIN_TIMEOUT - 2 * POLL_INTERVAL);
}

#[tokio::test]
async fn claims_send_the_secret_behind_the_request_id() {
    use sha2::Digest as _;
    let server = start_mock_controller().await;
    approve_claims(&server).await;
    let (_dir, agent) = start_agent(build_mock_tunnel(false));
    let ticket = agent.begin_login(&server.uri(), None, "box", false);
    agent
        .await_claim(&ticket.request, Duration::ZERO)
        .await
        .unwrap();
    let sent: Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    let digest = sha2::Sha256::digest(sent["secret"].as_str().unwrap().as_bytes());
    let request: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(request, ticket.request);
}

#[tokio::test]
async fn preselected_devices_are_sent_with_the_claim() {
    let server = start_mock_controller().await;
    approve_claims(&server).await;
    let (_dir, agent) = start_agent(build_mock_tunnel(false));
    let ticket = agent.begin_login(&server.uri(), Some("another-device"), "box", false);
    agent
        .await_claim(&ticket.request, Duration::ZERO)
        .await
        .unwrap();
    let sent: Value = server.received_requests().await.unwrap()[0]
        .body_json()
        .unwrap();
    assert_eq!(sent["device_id"], "another-device");
}

#[tokio::test]
async fn logins_add_a_connection_named_after_the_device() {
    let server = start_mock_controller().await;
    approve_claims(&server).await;
    let (_dir, agent) = start_agent(build_mock_tunnel(false));
    let outcome = log_in(&agent, &server.uri(), None, true).await;
    assert!(!outcome.reauthenticated);
    assert_eq!(outcome.summary.name, "ito-05c7ff30");
    assert!(outcome.summary.no_dns);
    assert_eq!(agent.list().await.unwrap(), [outcome.summary]);
}

#[tokio::test]
async fn logins_list_other_connections_to_the_same_portal() {
    let server = start_mock_controller().await;
    approve_claims(&server).await;
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    let portal = server.uri();
    save_test_connection(dir.path(), "ito-a", &portal, Disconnected);
    save_test_connection(dir.path(), "ito-b", "https://other.test", Disconnected);
    let outcome = log_in(&agent, &portal, None, false).await;
    let others: Vec<&str> = outcome.others.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(others, ["ito-a"]);
}

#[tokio::test]
async fn relogins_replace_the_credential_and_key_in_place() {
    let server = start_mock_controller().await;
    approve_claims(&server).await;
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_connection_of_claimed_device(&agent, dir.path(), &server.uri());
    let before = agent.load("ito-a").unwrap();
    let outcome = log_in(&agent, &server.uri(), Some(DEVICE_ID), false).await;
    assert!(outcome.reauthenticated);
    assert_eq!(agent.list().await.unwrap(), [outcome.summary]);
    let after = agent.load("ito-a").unwrap();
    assert_eq!(after.token, "itoa_new");
    assert_ne!(after.private_key, before.private_key);
    assert!(!after.revoked);
}

#[tokio::test]
async fn relogins_keep_the_local_preferences() {
    let server = start_mock_controller().await;
    approve_claims(&server).await;
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_connection_of_claimed_device(&agent, dir.path(), &server.uri());
    let outcome = log_in(&agent, &server.uri(), Some(DEVICE_ID), false).await;
    assert!(outcome.summary.no_dns);
    assert_eq!(outcome.summary.profile_id, None);
    assert_eq!(
        outcome.summary.custom_allowed_ips,
        Some(vec!["10.2.0.0/24".into()])
    );
}

#[tokio::test]
async fn relogins_keep_the_cached_config_when_the_controller_cannot_send_one() {
    let server = MockServer::start().await;
    approve_claims(&server).await;
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_connection_of_claimed_device(&agent, dir.path(), &server.uri());
    let cached = agent.load("ito-a").unwrap().config;
    log_in(&agent, &server.uri(), Some(DEVICE_ID), false).await;
    assert_eq!(agent.load("ito-a").unwrap().config, cached);
}

#[tokio::test]
async fn logins_connect_when_asked() {
    let server = start_mock_controller().await;
    approve_claims(&server).await;
    let mut tunnel = build_mock_tunnel(false);
    tunnel.expect_up().times(1).returning(|_, _| Ok(()));
    let (_dir, agent) = start_agent(tunnel);
    let ticket = agent.begin_login(&server.uri(), None, "box", false);
    let claimed = agent.await_claim(&ticket.request, Duration::ZERO).await;
    let outcome = agent.install_claim(claimed.unwrap(), true).await.unwrap();
    assert_eq!(outcome.summary.state, Connected);
}

#[tokio::test]
async fn logins_stay_disconnected_beside_a_tunnel_with_identical_routes() {
    let server = start_mock_controller().await;
    approve_claims(&server).await;
    // Only ito-a is up; bringing the new connection up would fail the mock.
    let mut tunnel = MockTunnelDriver::new();
    tunnel.expect_reconcile().returning(|_, _| Ok(()));
    tunnel.expect_is_up().returning(|name| Ok(name == "ito-a"));
    tunnel.expect_follows_external_state().return_const(false);
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    let ticket = agent.begin_login(&server.uri(), None, "box", false);
    let claimed = agent.await_claim(&ticket.request, Duration::ZERO).await;
    let outcome = agent.install_claim(claimed.unwrap(), true).await.unwrap();
    assert_eq!(outcome.summary.state, Disconnected);
    assert_eq!(outcome.overlap.as_deref(), Some("ito-a"));
}
