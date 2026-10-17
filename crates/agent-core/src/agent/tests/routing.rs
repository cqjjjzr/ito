//! Choosing routes: server profiles, local routes and keeping connected tunnels from using identical
//! route prefixes.

use super::*;
use mockall::Sequence;

/// Saves connected `ito-a` and `ito-b` in `b_state` on `portal`. `ito-b` has a stale cached config
/// with other routes, so only refreshing it gives `ito-b` the routes of `ito-a`.
fn save_connections_that_overlap_after_a_refresh(
    agent: &Agent<MockTunnelDriver>,
    dir: &Path,
    portal: &str,
    b_state: ConnectionState,
) {
    save_test_connection(dir, "ito-a", portal, Connected);
    save_test_connection(dir, "ito-b", portal, b_state);
    change_saved_connection(agent, "ito-b", |b| {
        let cache = b.config.as_mut().unwrap();
        cache.etag = "\"old\"".into();
        cache.config.route_profiles[0].allowed_ips = vec!["10.2.0.0/24".into()];
        if b.applied.is_some() {
            b.applied = build_spec(b);
        }
    });
}

/// Builds a mock tunnel driver where `ito-a` runs, and `ito-b` too when `b_up`.
fn build_tunnel_beside_ito_a(b_up: bool, follows_external_state: bool) -> MockTunnelDriver {
    let mut tunnel = MockTunnelDriver::new();
    tunnel.expect_reconcile().returning(|_, _| Ok(()));
    tunnel
        .expect_follows_external_state()
        .return_const(follows_external_state);
    tunnel
        .expect_is_up()
        .returning(move |name| Ok(name == "ito-a" || b_up));
    tunnel
}

/// Asserts that `ito-b` failed over the routes of `ito-a`, which stays connected.
fn assert_ito_b_lost_to_ito_a(agent: &Agent<MockTunnelDriver>) {
    let b = agent.load("ito-b").unwrap();
    assert_eq!(b.state, Errored);
    assert_eq!(b.applied, None);
    assert!(b.last_error.unwrap().contains("ito-a"));
    assert_eq!(agent.load("ito-a").unwrap().state, Connected);
}

#[tokio::test]
async fn profile_changes_restart_the_tunnel() {
    let server = start_mock_controller().await;
    let mut tunnel = build_mock_tunnel(true);
    let mut order = Sequence::new();
    tunnel
        .expect_down()
        .times(1)
        .in_sequence(&mut order)
        .returning(|_| Ok(()));
    tunnel
        .expect_up()
        .withf(|_, spec| !spec.default_routes().is_empty())
        .times(1)
        .in_sequence(&mut order)
        .returning(|_, _| Ok(()));
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    agent.set_profile("ito-a", Some("all"), None).await.unwrap();
}

#[tokio::test]
async fn local_routes_are_normalized() {
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_test_connection(dir.path(), "ito-a", UNREACHABLE_PORTAL, Disconnected);
    let routes = vec![
        "fd20::1/64".into(),
        "10.2.0.9/24".into(),
        "10.2.0.0/24".into(),
    ];
    let summary = agent
        .set_profile("ito-a", None, Some(routes))
        .await
        .unwrap();
    assert_eq!(summary.profile_id, None);
    assert_eq!(
        summary.custom_allowed_ips.unwrap(),
        ["10.2.0.0/24", "fd20::/64"]
    );
}

#[tokio::test]
async fn local_routes_survive_a_refreshed_config() {
    let server = start_mock_controller().await;
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_test_connection(dir.path(), "ito-a", &server.uri(), Disconnected);
    change_saved_connection(&agent, "ito-a", |c| {
        c.custom_allowed_ips = Some(vec!["10.2.0.0/24".into()]);
        c.config.as_mut().unwrap().etag = "\"old\"".into();
    });
    agent.sync_all().await.unwrap();
    let c = agent.load("ito-a").unwrap();
    assert_eq!(c.config.as_ref().unwrap().etag, "\"e1\"");
    assert_eq!(build_spec(&c).unwrap().peer.allowed_ips, ["10.2.0.0/24"]);
}

#[tokio::test]
async fn selecting_a_server_profile_keeps_the_local_routes_for_later() {
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_test_connection(dir.path(), "ito-a", UNREACHABLE_PORTAL, Disconnected);
    change_saved_connection(&agent, "ito-a", |c| {
        c.custom_allowed_ips = Some(vec!["10.2.0.0/24".into()]);
    });
    let summary = agent.set_profile("ito-a", Some("all"), None).await.unwrap();
    assert_eq!(summary.profile_id.as_deref(), Some("all"));
    assert_eq!(summary.custom_allowed_ips, Some(vec!["10.2.0.0/24".into()]));
}

#[tokio::test]
async fn empty_local_routes_route_nothing() {
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_test_connection(dir.path(), "ito-a", UNREACHABLE_PORTAL, Disconnected);
    agent
        .set_profile("ito-a", None, Some(vec![]))
        .await
        .unwrap();
    let spec = build_spec(&agent.load("ito-a").unwrap()).unwrap();
    assert!(spec.peer.allowed_ips.is_empty());
}

#[tokio::test]
async fn invalid_selections_are_refused_and_change_nothing() {
    let (dir, agent) = start_agent(MockTunnelDriver::new());
    save_test_connection(dir.path(), "ito-a", UNREACHABLE_PORTAL, Disconnected);
    let before = agent.load("ito-a").unwrap();
    let route = |r: &str| Some(vec![r.to_string()]);
    for (case, profile, allowed_ips) in [
        ("unknown profile", Some("gone"), None),
        ("route that is no prefix", None, route("garbage")),
        ("prefix that is too long", None, route("10.0.0.0/33")),
        (
            "route with a line break",
            None,
            route("10.0.0.0/24\nPostUp = calc"),
        ),
        ("neither profile nor routes", None, None),
        ("both profile and routes", Some("all"), Some(vec![])),
    ] {
        let refused = agent.set_profile("ito-a", profile, allowed_ips).await;
        assert!(matches!(refused, Err(AgentError::Invalid(_))), "{case}");
    }
    assert_eq!(agent.load("ito-a").unwrap(), before);
}

#[tokio::test]
async fn profile_changes_cannot_duplicate_a_connected_route() {
    // The refusal comes before the tunnel is touched; any call would fail the mock.
    let (dir, agent) = start_agent(MockTunnelDriver::new());
    save_test_connection(dir.path(), "ito-a", UNREACHABLE_PORTAL, Connected);
    save_test_connection(dir.path(), "ito-b", UNREACHABLE_PORTAL, Connected);
    change_saved_connection(&agent, "ito-b", |b| {
        b.profile_id = Some("all".into());
        b.applied = build_spec(b);
    });
    let before = agent.load("ito-b").unwrap();
    let route = Some(vec!["10.0.0.42/24".to_string()]);
    for (case, profile, allowed_ips) in [
        ("server profile", Some("vpn"), None),
        ("local routes", None, route),
    ] {
        let refused = agent.set_profile("ito-b", profile, allowed_ips).await;
        assert!(matches!(refused, Err(AgentError::Refused(_))), "{case}");
    }
    assert_eq!(agent.load("ito-b").unwrap(), before);
}

#[tokio::test]
async fn overlapping_tunnels_cannot_both_connect() {
    // The refusal comes before the tunnel is touched; any call would fail the mock.
    let (dir, agent) = start_agent(MockTunnelDriver::new());
    save_test_connection(dir.path(), "ito-a", UNREACHABLE_PORTAL, Connected);
    save_test_connection(dir.path(), "ito-b", UNREACHABLE_PORTAL, Disconnected);
    assert!(matches!(
        agent.connect("ito-b").await,
        Err(AgentError::Refused(_))
    ));
}

#[tokio::test]
async fn nested_routes_can_connect_together() {
    let server = start_mock_controller().await;
    let mut tunnel = build_mock_tunnel(false);
    tunnel
        .expect_up()
        .withf(|name, spec| name == "ito-b" && !spec.default_routes().is_empty())
        .times(1)
        .returning(|_, _| Ok(()));
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", &server.uri(), Connected);
    save_test_connection(dir.path(), "ito-b", &server.uri(), Disconnected);
    change_saved_connection(&agent, "ito-b", |b| b.profile_id = Some("all".into()));
    let summary = agent.connect("ito-b").await.unwrap();
    assert_eq!(summary.state, Connected);
}

#[tokio::test]
async fn failed_connections_without_a_live_tunnel_reserve_no_routes() {
    let mut tunnel = MockTunnelDriver::new();
    tunnel
        .expect_is_up()
        .withf(|name| name == "ito-a")
        .times(1)
        .returning(|_| Ok(false));
    let (dir, agent) = start_agent(tunnel);
    save_test_connection(dir.path(), "ito-a", UNREACHABLE_PORTAL, Errored);
    save_test_connection(dir.path(), "ito-b", UNREACHABLE_PORTAL, Disconnected);
    let b = agent.load("ito-b").unwrap();
    assert_eq!(agent.find_overlap(&b).await.unwrap(), None);
}

#[tokio::test]
async fn connecting_refuses_routes_that_a_refresh_makes_identical() {
    let server = start_mock_controller().await;
    // No tunnel may start with the conflicting routes; an `up` call would fail the mock.
    let (dir, agent) = start_agent(build_tunnel_beside_ito_a(false, false));
    let state = Disconnected;
    save_connections_that_overlap_after_a_refresh(&agent, dir.path(), &server.uri(), state);
    assert!(matches!(
        agent.connect("ito-b").await,
        Err(AgentError::Refused(_))
    ));
    assert_ito_b_lost_to_ito_a(&agent);
}

#[tokio::test]
async fn refreshes_that_duplicate_a_connected_route_take_the_tunnel_down() {
    let server = start_mock_controller().await;
    let mut tunnel = build_tunnel_beside_ito_a(true, false);
    tunnel
        .expect_down()
        .withf(|name| name == "ito-b")
        .times(1)
        .returning(|_| Ok(()));
    let (dir, agent) = start_agent(tunnel);
    let state = Connected;
    save_connections_that_overlap_after_a_refresh(&agent, dir.path(), &server.uri(), state);
    agent.sync_all().await.unwrap();
    assert_ito_b_lost_to_ito_a(&agent);
}

#[tokio::test]
async fn tunnels_started_outside_the_agent_with_duplicate_routes_are_taken_down() {
    let server = start_mock_controller().await;
    let mut tunnel = build_tunnel_beside_ito_a(true, true);
    tunnel
        .expect_down()
        .withf(|name| name == "ito-b")
        .times(1)
        .returning(|_| Ok(()));
    let (dir, agent) = start_agent(tunnel);
    let state = Disconnected;
    save_connections_that_overlap_after_a_refresh(&agent, dir.path(), &server.uri(), state);
    agent.sync_all().await.unwrap();
    assert_ito_b_lost_to_ito_a(&agent);
}
