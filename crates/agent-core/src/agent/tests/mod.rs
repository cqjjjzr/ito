use super::*;
use crate::{
    spec::tests::build_sample_config,
    state::{
        ConnectionState::{Connected, Disconnected, Disconnecting, Errored},
        tests::{build_sample_connection, create_private_dir},
    },
    tunnel::MockTunnelDriver,
};
use serde_json::{Value, json};
use std::path::Path;
use tempfile::TempDir;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

mod login;
mod preferences;
mod routing;
mod sync;

/// The ID of the device that the mock controller serves. Its tunnel name is `ito-05c7ff30`.
const DEVICE_ID: &str = "01a14162-f7c1-764c-b059-c93b05c7ff30";
/// A portal on the discard port of this host, where no controller answers.
const UNREACHABLE_PORTAL: &str = "http://127.0.0.1:9";

/// Builds the controller's JSON for the device [`DEVICE_ID`] at `revision`.
fn build_device_json(revision: i64) -> Value {
    json!({
        "id": DEVICE_ID, "account_id": "a", "name": "laptop", "note": "", "dns_name": null,
        "interface_id": "wg0", "revision": revision, "key_expires_at": null,
        "disabled_reason": null,
    })
}

/// Starts a mock controller whose config has ETag `"e1"` and answers `304` when `If-None-Match`
/// matches.
async fn start_mock_controller() -> MockServer {
    let server = MockServer::start().await;
    let match_route =
        |verb: &str, at: &str| Mock::given(method(verb)).and(path(format!("/api/v1/agent/{at}")));
    match_route("GET", "config")
        .and(header("if-none-match", "\"e1\""))
        .respond_with(ResponseTemplate::new(304))
        .mount(&server)
        .await;
    match_route("GET", "config")
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(build_sample_config())
                .insert_header("etag", "\"e1\""),
        )
        .mount(&server)
        .await;
    match_route("GET", "device")
        .respond_with(ResponseTemplate::new(200).set_body_json(build_device_json(1)))
        .mount(&server)
        .await;
    server
}

/// Makes `server` answer every claim with `response`.
async fn answer_claims(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/api/v1/agent/claim"))
        .respond_with(response)
        .mount(server)
        .await;
}

/// Saves connection `name` in the state directory `dir`, pointing at `portal` with cached ETag
/// `"e1"`. A connected one also records its spec as applied, as if its tunnel were running.
fn save_test_connection(dir: &Path, name: &str, portal: &str, state: ConnectionState) {
    let mut c = build_sample_connection(name);
    c.portal = portal.into();
    c.state = state;
    c.applied = (state == Connected).then(|| build_spec(&c).unwrap());
    c.config.as_mut().unwrap().etag = "\"e1\"".into();
    StateDir::open(dir).unwrap().save(&c).unwrap();
}

/// Changes the saved connection `name` with `change`.
fn change_saved_connection(
    agent: &Agent<MockTunnelDriver>,
    name: &str,
    change: impl FnOnce(&mut SavedConnection),
) {
    let mut c = agent.load(name).unwrap();
    change(&mut c);
    agent.state.save(&c).unwrap();
}

/// Builds a mock tunnel driver that reports every tunnel as `up`, accepts any reconciliation and
/// ignores external state.
fn build_mock_tunnel(up: bool) -> MockTunnelDriver {
    let mut tunnel = MockTunnelDriver::new();
    tunnel.expect_reconcile().returning(|_, _| Ok(()));
    tunnel.expect_is_up().returning(move |_| Ok(up));
    tunnel.expect_follows_external_state().return_const(false);
    tunnel
}

/// Starts an agent on a new private state directory with `tunnel` as its driver.
fn start_agent(tunnel: MockTunnelDriver) -> (TempDir, Agent<MockTunnelDriver>) {
    let dir = create_private_dir();
    let agent = Agent::new(StateDir::open(dir.path()).unwrap(), tunnel);
    (dir, agent)
}
