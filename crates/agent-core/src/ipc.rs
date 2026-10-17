//! Line-delimited JSON IPC protocol between an agent service and local front ends.

use crate::{
    agent::{Agent, AgentError},
    tunnel::TunnelDriver,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    List,
    Status {
        name: String,
    },
    Connect {
        name: String,
    },
    Disconnect {
        name: String,
    },
    Logout {
        name: String,
    },
    RotateKey {
        name: String,
    },
    RotatePsk {
        name: String,
    },
    SetProfile {
        name: String,
        profile: Option<String>,
        allowed_ips: Option<Vec<String>>,
    },
    SetDns {
        name: String,
        enabled: bool,
    },
    /// Starts a login flow and returns the [`LoginTicket`](crate::login::LoginTicket).
    LoginStart {
        portal: String,
        device: Option<String>,
        host_name: String,
        no_dns: bool,
    },
    /// Waits for login approval and returns the [`LoginOutcome`](crate::agent::LoginOutcome).
    LoginFinish {
        request: String,
        connect: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcResponse {
    Ok(Value),
    Error(String),
}

fn respond<V: Serialize>(result: Result<V, AgentError>) -> IpcResponse {
    match result {
        Ok(value) => IpcResponse::Ok(serde_json::to_value(value).expect("serializable")),
        Err(e) => IpcResponse::Error(e.to_string()),
    }
}

/// Dispatches `request` against `agent` and wraps the result in an [`IpcResponse`].
pub async fn handle<T: TunnelDriver>(agent: &Agent<T>, request: IpcRequest) -> IpcResponse {
    match request {
        IpcRequest::List => respond(agent.list().await),
        IpcRequest::Status { name } => respond(agent.status(&name).await),
        IpcRequest::Connect { name } => respond(agent.connect(&name).await),
        IpcRequest::Disconnect { name } => respond(agent.disconnect(&name).await),
        IpcRequest::Logout { name } => respond(
            agent
                .logout(&name)
                .await
                .map(|revoked| json!({ "revoked": revoked })),
        ),
        IpcRequest::RotateKey { name } => respond(agent.rotate_key(&name).await),
        IpcRequest::RotatePsk { name } => respond(agent.rotate_psk(&name).await),
        IpcRequest::SetProfile {
            name,
            profile,
            allowed_ips,
        } => respond(
            agent
                .set_profile(&name, profile.as_deref(), allowed_ips)
                .await,
        ),
        IpcRequest::SetDns { name, enabled } => respond(agent.set_dns(&name, enabled).await),
        IpcRequest::LoginStart {
            portal,
            device,
            host_name,
            no_dns,
        } => respond(Ok(agent.begin_login(
            &portal,
            device.as_deref(),
            &host_name,
            no_dns,
        ))),
        IpcRequest::LoginFinish { request, connect } => {
            respond(agent.finish_login(&request, connect).await)
        }
    }
}

/// Reads newline-delimited JSON requests from `stream` and writes responses until EOF.
pub async fn serve<S, T>(stream: S, agent: &Agent<T>) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: TunnelDriver,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let response = match serde_json::from_str(&line) {
            Ok(request) => handle(agent, request).await,
            Err(e) => IpcResponse::Error(format!("bad request: {e}")),
        };
        let mut text = serde_json::to_string(&response).expect("serializable");
        text.push('\n');
        writer.write_all(text.as_bytes()).await?;
    }
    Ok(())
}

/// Sends `request` over `stream` and reads a single newline-terminated response.
pub async fn call<S>(stream: &mut S, request: &IpcRequest) -> io::Result<IpcResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut text = serde_json::to_string(request).map_err(io::Error::other)?;
    text.push('\n');
    stream.write_all(text.as_bytes()).await?;
    // Read byte-by-byte up to the newline so subsequent responses on the stream are not buffered
    // and dropped.
    let mut line = Vec::new();
    loop {
        let byte = tokio::io::AsyncReadExt::read_u8(stream).await?;
        if byte == b'\n' {
            break;
        }
        line.push(byte);
    }
    serde_json::from_slice(&line).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        state::{
            StateDir,
            tests::{build_sample_connection, create_private_dir},
        },
        tunnel::MockTunnelDriver,
    };
    use tokio::io::AsyncReadExt;

    /// Starts an agent with saved connection `ito-a` whose tunnel driver expects no calls.
    fn start_agent() -> (tempfile::TempDir, Agent<MockTunnelDriver>) {
        let dir = create_private_dir();
        let state = StateDir::open(dir.path()).unwrap();
        state.save(&build_sample_connection("ito-a")).unwrap();
        (dir, Agent::new(state, MockTunnelDriver::new()))
    }

    #[test]
    fn every_request_survives_the_wire() {
        let name = || "ito-a".to_string();
        for request in [
            IpcRequest::List,
            IpcRequest::Status { name: name() },
            IpcRequest::Connect { name: name() },
            IpcRequest::Disconnect { name: name() },
            IpcRequest::Logout { name: name() },
            IpcRequest::RotateKey { name: name() },
            IpcRequest::RotatePsk { name: name() },
            IpcRequest::SetProfile {
                name: name(),
                profile: Some("all".into()),
                allowed_ips: Some(vec!["10.0.0.0/24".into()]),
            },
            IpcRequest::SetDns {
                name: name(),
                enabled: true,
            },
            IpcRequest::LoginStart {
                portal: "https://vpn.test".into(),
                device: Some("d".into()),
                host_name: "box".into(),
                no_dns: true,
            },
            IpcRequest::LoginFinish {
                request: "0123".into(),
                connect: true,
            },
        ] {
            let text = serde_json::to_string(&request).unwrap();
            assert!(!text.contains('\n'), "{text}");
            let parsed: IpcRequest = serde_json::from_str(&text).unwrap();
            assert_eq!(parsed, request);
        }
    }

    #[tokio::test]
    async fn requests_get_one_response_each() {
        let (_dir, agent) = start_agent();
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let talk = async {
            let list = call(&mut client, &IpcRequest::List).await.unwrap();
            let IpcResponse::Ok(list) = list else {
                panic!("{list:?}")
            };
            assert_eq!(list[0]["name"], "ito-a");
            let unknown = IpcRequest::Connect {
                name: "ito-0".into(),
            };
            let answer = call(&mut client, &unknown).await.unwrap();
            assert_eq!(
                answer,
                IpcResponse::Error("no connection named ito-0".into())
            );
            drop(client);
        };
        let (served, ()) = tokio::join!(serve(server, &agent), talk);
        served.unwrap();
    }

    #[tokio::test]
    async fn unknown_requests_are_refused_and_the_stream_continues() {
        let (_dir, agent) = start_agent();
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let talk = async {
            client.write_all(b"{\"op\":\"reboot\"}\n").await.unwrap();
            let mut line = Vec::new();
            loop {
                match client.read_u8().await.unwrap() {
                    b'\n' => break,
                    byte => line.push(byte),
                }
            }
            let refused: IpcResponse = serde_json::from_slice(&line).unwrap();
            assert!(
                matches!(&refused, IpcResponse::Error(e) if e.starts_with("bad request")),
                "{refused:?}"
            );
            let list = call(&mut client, &IpcRequest::List).await.unwrap();
            assert!(matches!(list, IpcResponse::Ok(_)), "{list:?}");
            drop(client);
        };
        let (served, ()) = tokio::join!(serve(server, &agent), talk);
        served.unwrap();
    }
}
