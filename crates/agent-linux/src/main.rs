mod linux;

use async_trait::async_trait;
use ito_agent_core::{
    agent::{Agent, CLAIM_INTERVAL},
    cli::{self, CliBackend, format_summary_line},
    ipc::{self, IpcRequest, IpcResponse},
    state::StateDir,
    tunnel::TunnelDriver,
};
use linux::{LinuxTunnel, SystemCommandExecutor, is_on_path};
use serde_json::Value;
use std::{
    collections::BTreeMap, fs::File, path::PathBuf, process::ExitCode, sync::Arc, time::Duration,
};
use tokio::{io::AsyncBufReadExt, sync::Notify};

/// Linux agent daemon and CLI for managing Ito WireGuard connections.
#[derive(clap::Parser)]
#[command(name = "ito-agent", version)]
struct Args {
    /// Directory storing saved connection files
    #[arg(
        long = "state-dir",
        value_name = "DIR",
        env = "ITO_AGENT_STATE",
        default_value = "/var/lib/ito-agent"
    )]
    state_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    #[command(flatten)]
    Connections(cli::Command),
    /// Synchronizes all saved connections every minute and on network changes until stopped
    Run,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = <Args as clap::Parser>::parse();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ito-agent: {e}");
            ExitCode::FAILURE
        }
    }
}

type Result<T, E = String> = std::result::Result<T, E>;

async fn run(args: Args) -> Result<()> {
    if !is_root() {
        return Err("root privileges required to manage WireGuard interfaces".into());
    }
    let state = StateDir::open(&args.state_dir)
        .map_err(|e| format!("{}: {e}", args.state_dir.display()))?;
    let lock = state.path().join(".lock");
    let resolvectl = is_on_path("resolvectl");
    let tunnel = LinuxTunnel::new(
        SystemCommandExecutor,
        state.path().join("tunnels"),
        resolvectl,
        is_on_path("nft"),
    );
    let lock = File::create(&lock).map_err(|e| format!("{}: {e}", lock.display()))?;
    // Hold the state lock while sweeping stale routing rules so a concurrent CLI command cannot
    // race.
    if matches!(args.command, Command::Run) {
        let _held = hold(&lock)?;
        if let Err(e) = tunnel.sweep().await {
            eprintln!("cleanup: {e}");
        }
    }
    let agent = Agent::new(state, tunnel);
    match args.command {
        Command::Run => {
            let changed = Arc::new(Notify::new());
            let watched = changed.clone();
            let watcher = tokio::spawn(async move {
                if let Err(e) = watch_network(&watched).await {
                    eprintln!("network monitor: {e}; using periodic sync");
                }
            });
            let result = tokio::select! {
                result = sync_until_stopped(&agent, &lock, &changed) => result,
                () = agent.expire_logins() => Ok(()),
            };
            watcher.abort();
            result
        }
        Command::Connections(command) => {
            cli::run(command, &LocalCliBackend { agent, lock }, &read_host_name()).await
        }
    }
}

// --- In-process CLI backend and file locking ---

/// Dispatches CLI commands to an in-process [`Agent`], coordinating with a running `ito-agent run`
/// daemon via an advisory file lock on `<state_dir>/.lock`.
struct LocalCliBackend<T> {
    agent: Agent<T>,
    lock: File,
}

#[async_trait]
impl<T: TunnelDriver + Send + Sync> CliBackend for LocalCliBackend<T> {
    async fn call(&self, request: IpcRequest) -> Result<Value> {
        let response = match request {
            IpcRequest::List | IpcRequest::Status { .. } => ipc::handle(&self.agent, request).await,
            // Poll for login approval without holding the file lock so the daemon can continue
            // syncing.
            IpcRequest::LoginFinish { request, connect } => {
                let claimed = self
                    .agent
                    .await_claim(&request, CLAIM_INTERVAL)
                    .await
                    .map_err(|e| e.to_string())?;
                let _held = hold(&self.lock)?;
                let outcome = self
                    .agent
                    .install_claim(claimed, connect)
                    .await
                    .map_err(|e| e.to_string())?;
                return Ok(serde_json::to_value(outcome).expect("serializable"));
            }
            request => {
                let _held = hold(&self.lock)?;
                ipc::handle(&self.agent, request).await
            }
        };
        match response {
            IpcResponse::Ok(value) => Ok(value),
            IpcResponse::Error(e) => Err(e),
        }
    }
}

/// Acquires an exclusive advisory lock on `lock` until the returned guard is dropped.
fn hold(lock: &File) -> Result<impl Drop + '_> {
    struct Held<'a>(&'a File);

    impl Drop for Held<'_> {
        fn drop(&mut self) {
            let _ = self.0.unlock();
        }
    }
    lock.lock().map_err(|e| format!("lock: {e}"))?;
    Ok(Held(lock))
}

// --- Background sync loop and network monitoring ---

/// Synchronizes all connections immediately, every minute, and whenever `changed` fires until
/// `SIGINT` or `SIGTERM` is received.
async fn sync_until_stopped<T: TunnelDriver>(
    agent: &Agent<T>,
    lock: &File,
    changed: &Notify,
) -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| e.to_string())?;
    // Log each connection's state or error only when it changes so persistent outages do not spam
    // stderr.
    let mut reported: BTreeMap<String, Option<String>> = BTreeMap::new();
    loop {
        let held = hold(lock)?;
        let synced = agent.sync_all().await;
        drop(held);
        if let Err(e) = synced {
            eprintln!("sync failed: {e}");
        }
        let listed = match agent.list().await {
            Ok(all) => all,
            Err(e) => {
                eprintln!("list failed: {e}");
                Vec::new()
            }
        };
        for s in listed {
            let error = s.last_error.clone();
            if reported.get(&s.name) != Some(&error) {
                match &error {
                    Some(e) => eprintln!("{}: {e}", s.name),
                    None => eprintln!("{}", format_summary_line(&s)),
                }
                reported.insert(s.name.clone(), error);
            }
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_secs(60)) => {}
            () = changed.notified() => {}
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = terminate.recv() => return Ok(()),
        }
    }
}

/// Reads the system hostname from `/proc/sys/kernel/hostname`, falling back to `"linux"`.
fn read_host_name() -> String {
    let name = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let name = name.trim();
    if name.is_empty() {
        "linux".into()
    } else {
        name.into()
    }
}

#[expect(unsafe_code, reason = "geteuid has no safe std wrapper")]
fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Spawns `ip monitor route address` and notifies `changed` on each netlink route or address event.
async fn watch_network(changed: &Notify) -> Result<()> {
    let mut child = tokio::process::Command::new("ip")
        .args(["monitor", "route", "address"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut lines = tokio::io::BufReader::new(child.stdout.take().expect("piped stdout")).lines();
    while lines
        .next_line()
        .await
        .map_err(|e| e.to_string())?
        .is_some()
    {
        changed.notify_one();
    }
    Err("ip monitor stopped".into())
}
