//! Platform-agnostic CLI subcommands for managing VPN connections.
//!
//! Each command translates into [`IpcRequest`] calls dispatched through a [`CliBackend`]
//! (in-process on Linux, or over the named pipe on Windows).

use crate::{
    agent::{ConnectionStatus, ConnectionSummary, LoginOutcome},
    ipc::IpcRequest,
    login::LoginTicket,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde_json::Value;

// --- CLI arguments and subcommands ---

#[derive(clap::Subcommand)]
pub enum Command {
    /// Logs in through the portal, prints the approval link, and waits for approval
    Login {
        /// Portal base URL, such as https://vpn.example.com
        portal: String,
        /// Device ID preselected in the portal; if omitted, select or create one during approval
        #[arg(long)]
        device: Option<String>,
        /// Bring the tunnel up immediately after login
        #[arg(long)]
        connect: bool,
        /// Save the connection without modifying host DNS
        #[arg(long)]
        no_dns: bool,
        /// Log out existing connections to the same portal without prompting
        #[arg(long, conflicts_with = "keep_others")]
        logout_others: bool,
        /// Keep existing connections to the same portal without prompting
        #[arg(long)]
        keep_others: bool,
        /// Print the login ticket and outcome as newline-delimited JSON
        #[arg(long)]
        json: bool,
    },
    /// Lists saved connections
    List {
        #[arg(long)]
        json: bool,
    },
    /// Shows local and controller tunnel status for a connection
    Status {
        name: String,
        #[arg(long)]
        json: bool,
    },
    /// Brings a connection's tunnel up
    Up { name: String },
    /// Takes a connection's tunnel down
    Down { name: String },
    /// Selects a server route profile or sets a local AllowedIPs override
    Profile {
        name: String,
        #[arg(required_unless_present = "allowed_ips")]
        profile: Option<String>,
        /// Comma-separated CIDR prefixes; pass without values to clear all routes
        #[arg(long, value_delimiter = ',', num_args = 0.., conflicts_with = "profile")]
        allowed_ips: Option<Vec<String>>,
    },
    /// Enables or disables controller-provided DNS settings
    Dns {
        name: String,
        #[arg(value_parser = ["on", "off"])]
        mode: String,
    },
    /// Generates a new local WireGuard key pair and uploads the public key
    RotateKey { name: String },
    /// Requests that the controller generate a new preshared key
    RotatePsk { name: String },
    /// Removes a connection and revokes its device's credential and key on the controller
    Logout { name: String },
}

// --- Command execution ---

/// Transport used by the CLI to execute [`IpcRequest`] operations.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait CliBackend: Sync {
    async fn call(&self, request: IpcRequest) -> Result<Value, String>;
}

/// Sends `request` to `backend` and deserializes the JSON response.
async fn ask<V: DeserializeOwned>(
    backend: &dyn CliBackend,
    request: IpcRequest,
) -> Result<V, String> {
    let answer = backend.call(request).await?;
    serde_json::from_value(answer).map_err(|e| format!("unexpected answer: {e}"))
}

/// Executes `command` against `backend` and prints the result to stdout.
pub async fn run(
    command: Command,
    backend: &dyn CliBackend,
    host_name: &str,
) -> Result<(), String> {
    let summary: ConnectionSummary = match command {
        Command::Login {
            portal,
            device,
            connect,
            no_dns,
            logout_others,
            keep_others,
            json,
        } => {
            let start = IpcRequest::LoginStart {
                portal,
                device,
                host_name: host_name.into(),
                no_dns,
            };
            let ticket: LoginTicket = ask(backend, start).await?;
            if json {
                println!("{}", serde_json::to_string(&ticket).expect("serializable"));
            } else {
                println!(
                    "Open this URL to sign in to the portal and approve this computer \
                     (confirmation code: {}):\n\n  {}\n\nWaiting for approval…",
                    ticket.code, ticket.url
                );
            }
            let finish = IpcRequest::LoginFinish {
                request: ticket.request,
                connect,
            };
            let outcome: LoginOutcome = ask(backend, finish).await?;
            let others = if logout_others {
                OtherConnectionsPolicy::LogOut
            } else if keep_others || json {
                OtherConnectionsPolicy::Keep
            } else {
                OtherConnectionsPolicy::Ask
            };
            return settle_login(backend, &outcome, others, json).await;
        }
        Command::List { json } => {
            let all: Vec<ConnectionSummary> = ask(backend, IpcRequest::List).await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&all).expect("serializable")
                );
            } else {
                all.iter()
                    .for_each(|s| println!("{}", format_summary_line(s)));
            }
            return Ok(());
        }
        Command::Status { name, json } => {
            let status: ConnectionStatus = ask(backend, IpcRequest::Status { name }).await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&status).expect("serializable")
                );
            } else {
                print_status(&status);
            }
            return Ok(());
        }
        Command::Logout { name } => {
            logout(backend, &name, false).await?;
            return Ok(());
        }
        Command::Up { name } => ask(backend, IpcRequest::Connect { name }).await?,
        Command::Down { name } => ask(backend, IpcRequest::Disconnect { name }).await?,
        Command::Profile {
            name,
            profile,
            allowed_ips,
        } => {
            ask(
                backend,
                IpcRequest::SetProfile {
                    name,
                    profile,
                    allowed_ips,
                },
            )
            .await?
        }
        Command::Dns { name, mode } => {
            ask(
                backend,
                IpcRequest::SetDns {
                    name,
                    enabled: mode == "on",
                },
            )
            .await?
        }
        Command::RotateKey { name } => ask(backend, IpcRequest::RotateKey { name }).await?,
        Command::RotatePsk { name } => ask(backend, IpcRequest::RotatePsk { name }).await?,
    };
    println!("{}", format_summary_line(&summary));
    if let Some(e) = &summary.last_error {
        eprintln!("{}: {e}", summary.name);
    }
    Ok(())
}

/// Policy for handling existing connections to the same portal after login.
#[derive(Clone, Copy, PartialEq)]
enum OtherConnectionsPolicy {
    Ask,
    LogOut,
    Keep,
}

/// Prints the login outcome and optionally logs out other connections to the same portal.
async fn settle_login(
    backend: &dyn CliBackend,
    outcome: &LoginOutcome,
    others: OtherConnectionsPolicy,
    json: bool,
) -> Result<(), String> {
    if !json {
        print_login_outcome(outcome);
    }
    let log_out = !outcome.others.is_empty()
        && match others {
            OtherConnectionsPolicy::LogOut => true,
            OtherConnectionsPolicy::Keep => false,
            OtherConnectionsPolicy::Ask => confirm("Log out these connections? [y/N] "),
        };
    if log_out {
        for o in &outcome.others {
            logout(backend, &o.name, json).await?;
        }
    }
    let s = &outcome.summary;
    // Connect the new tunnel if logging out the other connections cleared a route overlap.
    let overlap = outcome.overlap.as_ref();
    let waited = log_out && overlap.is_some_and(|x| outcome.others.iter().any(|o| &o.name == x));
    let mut summary = s.clone();
    if waited {
        let connect = IpcRequest::Connect {
            name: s.name.clone(),
        };
        match ask::<ConnectionSummary>(backend, connect).await {
            Ok(connected) => summary = connected,
            Err(e) if json => return Err(format!("{}: not connected: {e}", s.name)),
            Err(e) => println!("{}: not connected: {e}", s.name),
        }
    }
    if json {
        let outcome = LoginOutcome {
            summary,
            ..outcome.clone()
        };
        println!("{}", serde_json::to_string(&outcome).expect("serializable"));
    } else if waited {
        println!("{}", format_summary_line(&summary));
    } else if !outcome.others.is_empty() && !log_out {
        println!("Kept existing connections.");
    }
    Ok(())
}

// --- Output formatting ---

/// Prints a human-readable summary of `outcome` and lists other connections to the same portal.
fn print_login_outcome(outcome: &LoginOutcome) {
    let s = &outcome.summary;
    let how = if outcome.reauthenticated {
        "logged in again"
    } else {
        "added"
    };
    println!("{}: {how}, as {}", s.name, s.device.name);
    if let Some(other) = &outcome.overlap {
        println!(
            "Not connected: conflicting route prefix already in use by active connection '{other}'."
        );
    }
    if outcome.others.is_empty() {
        return;
    }
    println!("\nThis computer has other connections to {}:", s.portal);
    for o in &outcome.others {
        let state = if o.state.wants_connection() {
            "connected"
        } else {
            "disconnected"
        };
        println!(
            "  {}\t{}\t{}\t{state}",
            o.device.name, o.device.interface_id, o.name
        );
    }
}

/// Logs out connection `name` and prints the result unless `quiet` is set.
async fn logout(backend: &dyn CliBackend, name: &str, quiet: bool) -> Result<(), String> {
    let answer = backend
        .call(IpcRequest::Logout { name: name.into() })
        .await?;
    if quiet {
    } else if answer["revoked"] == true {
        println!("{name}: removed and credential revoked on controller");
    } else {
        println!("{name}: removed locally; could not reach controller to revoke device");
    }
    Ok(())
}

/// Formats a tab-separated summary line for `s`.
pub fn format_summary_line(s: &ConnectionSummary) -> String {
    let state = s.describe_state();
    let profile = s
        .profile_id
        .as_deref()
        .unwrap_or(if s.custom_allowed_ips.is_some() {
            "custom"
        } else {
            "-"
        });
    format!(
        "{}\t{}\t{state}\tprofile {profile}\t{}",
        s.name, s.device.name, s.portal
    )
}

fn print_status(status: &ConnectionStatus) {
    let s = &status.summary;
    let format_timestamp =
        |t: Option<DateTime<Utc>>| t.map_or("never".to_string(), |t| t.to_string());
    println!("{}", format_summary_line(s));
    println!("  device       {} ({})", s.device.name, s.device.id);
    if let Some(dns) = &s.device.dns_name {
        println!("  dns label    {dns}");
    }
    if !s.device.note.is_empty() {
        println!("  note         {}", s.device.note);
    }
    let profiles: Vec<&str> = s.profiles.iter().map(|p| p.id.as_str()).collect();
    println!("  profiles     {}", profiles.join(", "));
    if let Some(routes) = &s.custom_allowed_ips {
        println!("  custom routes {}", routes.join(", "));
    }
    println!("  DNS          {}", if s.no_dns { "off" } else { "on" });
    println!(
        "  key expires  {}",
        format_timestamp(s.device.key_expires_at)
    );
    match &status.local {
        Some(link) => {
            for peer in &link.peers {
                println!(
                    "  local        endpoint {}, handshake {}",
                    peer.endpoint,
                    format_timestamp(peer.handshake)
                );
                println!(
                    "               {} B received, {} B sent",
                    peer.receive_bytes, peer.transmit_bytes
                );
            }
        }
        None => println!("  local        down"),
    }
    match (&status.server, &status.server_error) {
        (Some(server), _) => println!(
            "  server       peer {}, handshake {}, {} B received, {} B sent",
            if server.peer_present {
                "present"
            } else {
                "absent"
            },
            format_timestamp(server.handshake),
            server.receive_bytes,
            server.transmit_bytes
        ),
        (None, Some(e)) => println!("  server       {e}"),
        (None, None) => {}
    }
    if let Some(e) = &s.last_error {
        println!("  last error   {e}");
    }
}

/// Prompts the user with `question` on the terminal and returns `true` for a yes answer.
///
/// Returns `false` immediately when stdin is not a terminal.
fn confirm(question: &str) -> bool {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return false;
    }
    print!("{question}");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    let _ = std::io::stdin().read_line(&mut answer);
    matches!(answer.trim(), "y" | "Y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use mockall::{Sequence, predicate::eq};
    use serde_json::json;

    /// The command line of an agent with only the connection subcommands.
    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    fn build_summary_json(name: &str, device: &str) -> Value {
        json!({
            "name": name, "portal": "https://vpn.test", "state": "connected", "no_dns": false,
            "revoked": false, "profile_id": null, "profiles": [], "disabled_reason": null,
            "last_error": null,
            "device": {
                "id": device, "name": device, "note": "", "dns_name": null, "interface_id": "wg0",
                "revision": 1, "key_expires_at": null, "disabled_reason": null,
            },
        })
    }

    /// Builds a mock backend expecting `exchanges` in order and no other calls.
    fn build_mock_backend(exchanges: Vec<(IpcRequest, Result<Value, String>)>) -> MockCliBackend {
        let mut backend = MockCliBackend::new();
        let mut order = Sequence::new();
        for (request, answer) in exchanges {
            backend
                .expect_call()
                .with(eq(request))
                .times(1)
                .in_sequence(&mut order)
                .returning(move |_| answer.clone());
        }
        backend
    }

    /// Builds the exchanges of a login that added `ito-2` but left it disconnected, because
    /// `ito-1` on the same portal uses identical routes.
    fn build_overlapping_login_exchanges() -> Vec<(IpcRequest, Result<Value, String>)> {
        let ticket = json!({
            "request": "r1", "url": "https://vpn.test/connect", "code": "AAAA-BBBB",
            "requested_at": 1,
        });
        let outcome = json!({
            "summary": build_summary_json("ito-2", "d2"),
            "reauthenticated": false,
            "others": [build_summary_json("ito-1", "d1")],
            "overlap": "ito-1",
        });
        let start = IpcRequest::LoginStart {
            portal: "https://vpn.test".into(),
            device: None,
            host_name: "host".into(),
            no_dns: false,
        };
        let finish = IpcRequest::LoginFinish {
            request: "r1".into(),
            connect: true,
        };
        vec![(start, Ok(ticket)), (finish, Ok(outcome))]
    }

    /// Builds the exchanges that log out `ito-1` and then connect `ito-2`, answering the connect
    /// with `connected`.
    fn build_logout_exchanges(
        connected: Result<Value, String>,
    ) -> Vec<(IpcRequest, Result<Value, String>)> {
        let logout = IpcRequest::Logout {
            name: "ito-1".into(),
        };
        let connect = IpcRequest::Connect {
            name: "ito-2".into(),
        };
        vec![
            (logout, Ok(json!({ "revoked": true }))),
            (connect, connected),
        ]
    }

    fn build_login_command(logout_others: bool, keep_others: bool, json: bool) -> Command {
        Command::Login {
            portal: "https://vpn.test".into(),
            device: None,
            connect: true,
            no_dns: false,
            logout_others,
            keep_others,
            json,
        }
    }

    #[tokio::test]
    async fn profile_commands_select_server_or_local_routes() {
        for (args, profile, allowed_ips) in [
            (vec!["all"], Some("all".into()), None),
            (
                vec!["--allowed-ips", "10.2.0.0/24,fd20::/64"],
                None,
                Some(vec!["10.2.0.0/24".into(), "fd20::/64".into()]),
            ),
            (vec!["--allowed-ips"], None, Some(vec![])),
        ] {
            let line = ["agent", "profile", "ito-a"].into_iter().chain(args);
            let command = Cli::try_parse_from(line).unwrap().command;
            let request = IpcRequest::SetProfile {
                name: "ito-a".into(),
                profile,
                allowed_ips,
            };
            let answer = Ok(build_summary_json("ito-a", "d"));
            let backend = build_mock_backend(vec![(request, answer)]);
            run(command, &backend, "host").await.unwrap();
        }
    }

    #[test]
    fn profile_commands_need_exactly_one_selection() {
        for args in [vec![], vec!["all", "--allowed-ips", "10.0.0.0/8"]] {
            let line = ["agent", "profile", "ito-a"]
                .into_iter()
                .chain(args.clone());
            assert!(Cli::try_parse_from(line).is_err(), "{args:?}");
        }
    }

    #[tokio::test]
    async fn dns_commands_turn_controller_dns_on_or_off() {
        for (mode, enabled) in [("on", true), ("off", false)] {
            let command = Cli::try_parse_from(["agent", "dns", "ito-a", mode])
                .unwrap()
                .command;
            let request = IpcRequest::SetDns {
                name: "ito-a".into(),
                enabled,
            };
            let answer = Ok(build_summary_json("ito-a", "d"));
            let backend = build_mock_backend(vec![(request, answer)]);
            run(command, &backend, "host").await.unwrap();
        }
    }

    #[tokio::test]
    async fn logins_log_out_other_connections_and_connect_the_new_one_when_asked() {
        let mut exchanges = build_overlapping_login_exchanges();
        exchanges.extend(build_logout_exchanges(Ok(build_summary_json(
            "ito-2", "d2",
        ))));
        let command = build_login_command(true, false, false);
        run(command, &build_mock_backend(exchanges), "host")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn logins_keep_other_connections_when_told() {
        // The backend expects only the login exchanges, so a logout would fail the mock.
        let backend = build_mock_backend(build_overlapping_login_exchanges());
        let command = build_login_command(false, true, false);
        run(command, &backend, "host").await.unwrap();
    }

    #[tokio::test]
    async fn json_logins_keep_other_connections_without_asking() {
        // The backend expects only the login exchanges, so a logout would fail the mock.
        let backend = build_mock_backend(build_overlapping_login_exchanges());
        let command = build_login_command(false, false, true);
        run(command, &backend, "host").await.unwrap();
    }

    #[tokio::test]
    async fn only_json_logins_fail_when_the_freed_connection_cannot_connect() {
        for json in [false, true] {
            let mut exchanges = build_overlapping_login_exchanges();
            exchanges.extend(build_logout_exchanges(Err("tunnel failed".into())));
            let command = build_login_command(true, false, json);
            let result = run(command, &build_mock_backend(exchanges), "host").await;
            assert_eq!(result.is_err(), json, "json: {json}");
        }
    }

    #[test]
    fn summary_lines_name_the_profile_or_custom_routes() {
        let summary: ConnectionSummary =
            serde_json::from_value(build_summary_json("ito-a", "d")).unwrap();
        for (profile_id, custom_allowed_ips, expected) in [
            (Some("all"), None, "profile all"),
            (
                None,
                Some(vec!["10.2.0.0/24".to_string()]),
                "profile custom",
            ),
            (None, None, "profile -"),
        ] {
            let s = ConnectionSummary {
                profile_id: profile_id.map(Into::into),
                custom_allowed_ips,
                ..summary.clone()
            };
            let line = format_summary_line(&s);
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields[3], expected, "{line}");
        }
    }
}
