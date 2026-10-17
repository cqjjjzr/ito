//! Windows agent service and tunnel management built on WireGuard for Windows.
//!
//! For each connection, the agent writes a DPAPI-encrypted configuration into WireGuard's
//! configuration store and installs or removes the corresponding `WireGuardTunnel$<name>` Windows
//! service. Unit tests use a mock driver; [`wireguard::FakeWireGuard`] backs
//! `console --fake` and the socket integration test.

pub mod daemon;
pub mod tunnel;
pub mod wireguard;

#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod system;

use ito_agent_core::{agent::Agent, state::StateDir};
use std::{path::Path, sync::Arc};
use tokio::sync::Notify;
use tunnel::WindowsTunnel;
use wireguard::FakeWireGuard;

/// Reads the local computer name from `COMPUTERNAME`, falling back to `"windows"`.
pub fn read_host_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "windows".into())
}

/// Formats an IPC connection failure when a front end cannot reach the Windows agent service.
pub fn format_service_unreachable_error(e: std::io::Error) -> String {
    format!("cannot reach Ito agent service: {e}")
}

/// Runs the production Windows agent until `stop` is signaled, storing connections in
/// `INSTALLFOLDER\Data\connections` and serving IPC requests on [`pipe::PIPE`]. Invokes `ready`
/// once the directory and named pipe listener are initialized.
#[cfg(windows)]
pub async fn run_system(
    stop: Arc<Notify>,
    log: fn(&str),
    ready: impl FnOnce(),
) -> Result<(), String> {
    let dir = service::data_dir()?;
    let connections = dir.join("connections");
    for d in [&dir, &connections] {
        system::create_private_dir(d, system::PRIVATE_DIR_SDDL)
            .map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let state =
        StateDir::open(&connections).map_err(|e| format!("{}: {e}", connections.display()))?;
    let wireguard = system::SystemWireGuard::locate()?;
    let agent = Arc::new(Agent::new(state, WindowsTunnel::new(wireguard)));
    let listener = pipe::listen().map_err(|e| format!("{}: {e}", pipe::PIPE))?;
    ready();
    tokio::select! {
        () = daemon::run(agent.clone(), stop, log) => Ok(()),
        e = pipe::serve(listener, agent) => Err(format!("{}: {e}", pipe::PIPE)),
    }
}

/// Runs the agent with [`FakeWireGuard`] storing tunnel configurations in `dir/store` and
/// connections in `dir/connections`, listening on [`pipe::PIPE`] on Windows or `dir/agent.sock` on
/// Unix.
pub async fn run_fake(dir: &Path, stop: Arc<Notify>, log: fn(&str)) -> Result<(), String> {
    let format_directory_error = |e: std::io::Error| format!("{}: {e}", dir.display());
    let wireguard = FakeWireGuard::new(dir.join("store")).map_err(format_directory_error)?;
    let state = StateDir::open(&dir.join("connections")).map_err(format_directory_error)?;
    let agent = Arc::new(Agent::new(state, WindowsTunnel::new(wireguard)));
    #[cfg(windows)]
    let served = {
        let listener = pipe::listen().map_err(|e| format!("{}: {e}", pipe::PIPE))?;
        tokio::spawn(pipe::serve(listener, agent.clone()))
    };
    #[cfg(unix)]
    let served = {
        let path = dir.join("agent.sock");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).map_err(format_directory_error)?;
        log(&format!("front ends: {}", path.display()));
        let agent = agent.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let agent = agent.clone();
                tokio::spawn(async move { ito_agent_core::ipc::serve(stream, &agent).await });
            }
        })
    };
    daemon::run(agent, stop, log).await;
    served.abort();
    Ok(())
}
