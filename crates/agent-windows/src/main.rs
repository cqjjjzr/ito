//! Windows agent CLI and service entry point (`ito-agent`).
//!
//! Connection subcommands (`login`, `list`, `up`, `down`, etc.) forward IPC requests to the
//! running `ItoAgent` Windows service over its named pipe.

use async_trait::async_trait;
use ito_agent_core::{
    cli::{self, CliBackend},
    ipc::{self, IpcRequest, IpcResponse},
};
use serde_json::Value;
use std::{path::PathBuf, process::ExitCode};

/// Windows agent service and CLI for managing Ito WireGuard connections.
#[derive(clap::Parser)]
#[command(name = "ito-agent", version)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    #[command(flatten)]
    Connections(cli::Command),
    /// Registers and starts the ItoAgent Windows service (requires Administrator)
    #[cfg(windows)]
    Install,
    /// Stops and removes the ItoAgent Windows service
    #[cfg(windows)]
    Uninstall,
    /// Invoked by the Windows Service Control Manager to run the ItoAgent service
    #[cfg(windows)]
    #[command(hide = true)]
    Service,
    /// Runs the agent in the foreground, logging to stderr (requires LocalSystem on Windows)
    Console {
        /// Run with an in-memory/file-backed fake WireGuard driver rooted at DIR
        #[arg(long, value_name = "DIR")]
        fake: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let args = <Args as clap::Parser>::parse();
    let result = match args.command {
        #[cfg(windows)]
        Command::Service => ito_agent_windows::service::dispatch(),
        #[cfg(windows)]
        Command::Install => ito_agent_windows::service::install(),
        #[cfg(windows)]
        Command::Uninstall => ito_agent_windows::service::uninstall(),
        Command::Console { fake } => run_console(fake),
        Command::Connections(command) => tokio::runtime::Runtime::new()
            .map_err(|e| e.to_string())
            .and_then(|runtime| {
                let host_name = ito_agent_windows::read_host_name();
                let backend = PipeCliBackend {
                    #[cfg(unix)]
                    socket: std::env::var_os("ITO_AGENT_SOCKET"),
                };
                runtime.block_on(cli::run(command, &backend, &host_name))
            }),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ito-agent: {e}");
            ExitCode::FAILURE
        }
    }
}

/// CLI backend that connects to the agent over its named pipe (or Unix socket in `--fake` mode).
struct PipeCliBackend {
    /// Path to `agent.sock` when testing against `console --fake` on Unix.
    #[cfg(unix)]
    socket: Option<std::ffi::OsString>,
}

#[async_trait]
impl CliBackend for PipeCliBackend {
    async fn call(&self, request: IpcRequest) -> Result<Value, String> {
        let format_error = ito_agent_windows::format_service_unreachable_error;
        #[cfg(windows)]
        let mut stream = ito_agent_windows::pipe::open().map_err(format_error)?;
        #[cfg(unix)]
        let mut stream = {
            let path = self.socket.as_ref();
            let path = path.ok_or("set ITO_AGENT_SOCKET to the agent's socket")?;
            tokio::net::UnixStream::connect(path)
                .await
                .map_err(format_error)?
        };
        match ipc::call(&mut stream, &request)
            .await
            .map_err(format_error)?
        {
            IpcResponse::Ok(value) => Ok(value),
            IpcResponse::Error(e) => Err(e),
        }
    }
}

fn run_console(fake: Option<PathBuf>) -> Result<(), String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let stop = std::sync::Arc::new(tokio::sync::Notify::new());
        let on_signal = stop.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            on_signal.notify_one();
        });
        let log = |line: &str| eprintln!("{line}");
        match fake {
            Some(dir) => ito_agent_windows::run_fake(&dir, stop, log).await,
            #[cfg(windows)]
            None => ito_agent_windows::run_system(stop, log, || log("running")).await,
            #[cfg(not(windows))]
            None => Err("only Windows has WireGuard for Windows; use console --fake DIR".into()),
        }
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{sync::Arc, time::Duration};
    use tokio::sync::Notify;

    /// Notified when the fake agent logs that its front-end socket is listening.
    static SOCKET_BOUND: Notify = Notify::const_new();

    #[tokio::test]
    async fn commands_reach_a_fake_agent_through_its_socket() {
        let dir = tempfile::tempdir().unwrap();
        let stop = Arc::new(Notify::new());
        let agent = tokio::spawn({
            let (dir, stop) = (dir.path().to_owned(), stop.clone());
            async move {
                let log = |line: &str| {
                    if line.starts_with("front ends: ") {
                        SOCKET_BOUND.notify_one();
                    }
                };
                ito_agent_windows::run_fake(&dir, stop, log).await
            }
        });
        tokio::time::timeout(Duration::from_secs(10), SOCKET_BOUND.notified())
            .await
            .expect("the fake agent did not start listening");
        let backend = PipeCliBackend {
            socket: Some(dir.path().join("agent.sock").into()),
        };
        assert_eq!(backend.call(IpcRequest::List).await, Ok(json!([])));
        let missing = IpcRequest::Connect {
            name: "ito-1".into(),
        };
        assert!(backend.call(missing).await.is_err());
        stop.notify_one();
        agent.await.unwrap().unwrap();
    }
}
