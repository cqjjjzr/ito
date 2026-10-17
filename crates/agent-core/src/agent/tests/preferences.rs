//! Preferences and how connections are summarized: DNS, the profile in use and the described
//! state.

use super::*;
use ito_shared::api::DisabledReason;

#[tokio::test]
async fn turning_dns_off_clears_servers_and_search_domains() {
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_test_connection(dir.path(), "ito-a", UNREACHABLE_PORTAL, Disconnected);
    agent.set_dns("ito-a", false).await.unwrap();
    let c = agent.load("ito-a").unwrap();
    assert!(c.no_dns);
    let spec = build_spec(&c).unwrap();
    assert!(spec.dns.is_empty());
    assert!(spec.dns_search.is_empty());
}

#[tokio::test]
async fn turning_dns_back_on_restores_the_controller_dns() {
    let (dir, agent) = start_agent(build_mock_tunnel(false));
    save_test_connection(dir.path(), "ito-a", UNREACHABLE_PORTAL, Disconnected);
    change_saved_connection(&agent, "ito-a", |c| c.no_dns = true);
    agent.set_dns("ito-a", true).await.unwrap();
    let spec = build_spec(&agent.load("ito-a").unwrap()).unwrap();
    assert_eq!(spec.dns, ["10.0.0.1"]);
    assert_eq!(spec.dns_search, ["vpn.test"]);
}

#[test]
fn summaries_show_the_profile_in_use() {
    let routes = Some(vec!["10.2.0.0/24".to_string()]);
    for (case, chosen, custom_allowed_ips, cached, expected) in [
        ("chosen profile", Some("all"), None, true, Some("all")),
        ("no choice", None, None, true, Some("vpn")),
        ("local routes", None, routes.clone(), true, None),
        ("removed profile", Some("gone"), routes, true, Some("vpn")),
        (
            "no config to check",
            Some("gone"),
            None,
            false,
            Some("gone"),
        ),
    ] {
        let mut c = build_sample_connection("ito-a");
        c.profile_id = chosen.map(Into::into);
        c.custom_allowed_ips = custom_allowed_ips;
        if !cached {
            c.config = None;
        }
        let summary = build_connection_summary(&c);
        assert_eq!(summary.profile_id.as_deref(), expected, "{case}");
    }
}

#[test]
fn states_are_described_by_precedence() {
    let blocked = Some(DisabledReason::Blocked);
    for (revoked, state, disabled_reason, expected) in [
        (
            true,
            Connected,
            blocked,
            "Revoked: log in again through the portal",
        ),
        (false, Disconnected, blocked, "Disconnected"),
        (
            false,
            Disconnecting,
            blocked,
            "Error: retrying disconnection",
        ),
        (false, Errored, blocked, "Error: retrying connection"),
        (
            false,
            Connected,
            blocked,
            "Connected, but disabled by controller: blocked",
        ),
        (false, Connected, None, "Connected"),
    ] {
        let mut summary = build_connection_summary(&build_sample_connection("ito-a"));
        summary.revoked = revoked;
        summary.state = state;
        summary.disabled_reason = disabled_reason;
        assert_eq!(summary.describe_state(), expected);
    }
}
