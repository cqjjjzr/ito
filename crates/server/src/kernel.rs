use crate::error::{Code, Result, internal, unavailable};
use serde_json::Value;
use std::{collections::BTreeMap, process::Stdio, time::Duration};
use tokio::io::AsyncWriteExt;

pub use ito_shared::dump::{Link, Peer};

#[async_trait::async_trait]
pub trait KernelDriver: Send + Sync {
    /// Reads the WireGuard interface `name` from the kernel, returning `None` if it does not exist
    /// or `InterfaceNameInUse` if a non-WireGuard interface holds that name.
    async fn read_link(&self, name: &str) -> Result<Option<Link>>;

    /// Lists all WireGuard interfaces in the kernel as a map from interface name to `ifalias`.
    async fn list_links(&self) -> Result<BTreeMap<String, String>>;

    /// Executes an `ip` or `wg` command vector, optionally writing `input` followed by a newline to
    /// stdin, and returns stdout.
    async fn run(&self, line: Vec<String>, input: Option<String>) -> Result<Vec<u8>>;
}

/// Runs an `ip` or `wg` command on a [`KernelDriver`].
///
/// The command template is split into arguments at compile time by [`xshell::cmd!`], and each
/// `{var}` interpolation supplies a single argument without invoking a shell. Pass secret keys via
/// `stdin = key` so they do not appear in process argument lists.
macro_rules! run {
    ($kernel:expr, $template:literal) => {
        $crate::kernel::run!(@line $kernel, $template, None)
    };
    ($kernel:expr, $template:literal, stdin = $input:expr) => {
        $crate::kernel::run!(@line $kernel, $template, Some($input))
    };
    (@line $kernel:expr, $template:literal, $input:expr) => {{
        let sh = $crate::kernel::create_shell()?;
        let line = $crate::kernel::build_command_line(xshell::cmd!(sh, $template));
        $kernel.run(line, $input)
    }};
}
pub(crate) use run;

pub fn create_shell() -> Result<xshell::Shell> {
    xshell::Shell::new().map_err(|e| internal(format!("command setup: {e}")))
}

/// Extracts the program name and arguments from an [`xshell::Cmd`].
pub fn build_command_line(cmd: xshell::Cmd<'_>) -> Vec<String> {
    let cmd = std::process::Command::from(cmd);
    std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

/// Production [`KernelDriver`] that executes `ip` and `wg` directly as child processes.
pub struct LocalKernelDriver;

impl LocalKernelDriver {
    pub async fn new() -> Result<Self> {
        run!(Self, "ip -Version").await?;
        run!(Self, "wg --version").await?;
        Ok(Self)
    }
}

fn parse_json(raw: &[u8]) -> Result<Vec<Value>> {
    serde_json::from_slice(raw).map_err(|e| internal(format!("unexpected ip output: {e}")))
}

#[async_trait::async_trait]
impl KernelDriver for LocalKernelDriver {
    async fn read_link(&self, name: &str) -> Result<Option<Link>> {
        // Query link flags, MTU, alias, link kind, and IP addresses in a single `ip` invocation.
        let links = match run!(self, "ip -details -json address show dev {name}").await {
            Ok(raw) => parse_json(&raw)?,
            Err(e) if e.cause_contains("does not exist") => return Ok(None),
            Err(e) => return Err(e),
        };
        let Some(link) = links.first() else {
            return Ok(None);
        };
        if link["linkinfo"]["info_kind"] != "wireguard" {
            return Err(unavailable(
                Code::InterfaceNameInUse,
                format!("{name} exists and is not a WireGuard link"),
            ));
        }
        let addresses = link["addr_info"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| {
                Some(format!(
                    "{}/{}",
                    a["local"].as_str()?,
                    a["prefixlen"].as_u64()?
                ))
            })
            .collect();
        let dump = run!(self, "wg show {name} dump").await?;
        let mut state = parse_dump(&String::from_utf8_lossy(&dump))?;
        state.alias = link["ifalias"].as_str().unwrap_or_default().into();
        state.up = link["flags"]
            .as_array()
            .is_some_and(|f| f.iter().any(|v| v == "UP"));
        state.mtu = link["mtu"].as_i64().unwrap_or_default() as i32;
        state.addresses = addresses;
        Ok(Some(state))
    }

    async fn list_links(&self) -> Result<BTreeMap<String, String>> {
        let raw = run!(self, "ip -json link show type wireguard").await?;
        let links = parse_json(&raw)?;
        let named = links.iter().filter_map(|l| {
            let alias = l["ifalias"].as_str().unwrap_or_default();
            Some((l["ifname"].as_str()?.to_string(), alias.to_string()))
        });
        Ok(named.collect())
    }

    async fn run(&self, line: Vec<String>, input: Option<String>) -> Result<Vec<u8>> {
        let describe = || line.join(" ");
        let mut child = tokio::process::Command::new(&line[0])
            .args(&line[1..])
            .env("LC_ALL", "C")
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| unavailable(Code::KernelUnavailable, format!("{}: {e}", describe())))?;
        // Write stdin concurrently with reading stdout/stderr so neither pipe can deadlock when
        // full.
        let stdin = child.stdin.take();
        let feed = async {
            if let (Some(mut stdin), Some(input)) = (stdin, &input) {
                let _ = stdin.write_all(format!("{input}\n").as_bytes()).await;
            }
        };
        let run = async { tokio::join!(feed, child.wait_with_output()).1 };
        let output = tokio::time::timeout(Duration::from_secs(15), run)
            .await
            .map_err(|_| unavailable(Code::KernelUnavailable, format!("{} timed out", describe())))?
            .map_err(|e| internal(format!("{}: {e}", describe())))?;
        if !output.status.success() {
            let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            // Redact any secret passed via stdin if `wg` echoed it into stderr.
            if let Some(secret) = input.as_deref().filter(|s| !s.is_empty()) {
                stderr = stderr.replace(secret, "[redacted]");
            }
            return Err(unavailable(
                Code::KernelCommandFailed,
                format!("{}: {}", describe(), stderr.trim()),
            ));
        }
        Ok(output.stdout)
    }
}

fn parse_dump(text: &str) -> Result<Link> {
    ito_shared::dump::parse_dump(text).map_err(|_| internal("unexpected wg dump output"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn build_bash_command(script: &str) -> Vec<String> {
        vec!["bash".into(), "-c".into(), script.into()]
    }

    #[tokio::test]
    async fn commands_do_not_block_on_full_pipes() {
        // The command fills stdout before it reads 1 MiB from stdin, which deadlocks unless both
        // pipes are served at once.
        let script = "printf %1048576s ''; cat >/dev/null";
        let input = "x".repeat(1 << 20);
        let out = LocalKernelDriver
            .run(build_bash_command(script), Some(input))
            .await
            .unwrap();
        assert_eq!(out.len(), 1 << 20);
    }

    #[tokio::test]
    async fn commands_that_exit_early_report_their_error() {
        // The command exits without reading the 1 MiB offered on stdin.
        let script = "echo refused >&2; exit 1";
        let input = "x".repeat(1 << 20);
        let e = LocalKernelDriver
            .run(build_bash_command(script), Some(input))
            .await
            .unwrap_err();
        assert_eq!(e.code, Code::KernelCommandFailed);
        assert!(e.cause.unwrap().ends_with("refused"));
    }

    /// Run with `just test-kernel`, which provides an isolated network namespace.
    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN in a disposable network namespace"]
    async fn real_kernel_round_trip() -> Result<()> {
        assert_eq!(std::env::var("ITO_KERNEL_TEST").as_deref(), Ok("1"));
        let k = LocalKernelDriver::new().await?;
        let name = "ito-test0";
        let [key, peer, psk, zero] =
            [1u8, 2, 4, 0].map(|b| base64::engine::general_purpose::STANDARD.encode([b; 32]));
        run!(k, "ip link add dev {name} mtu 1420 type wireguard").await?;
        run!(k, "ip link set dev {name} alias ito:test").await?;
        run!(
            k,
            "wg set {name} private-key /dev/stdin listen-port 51820",
            stdin = key
        )
        .await?;
        run!(k, "ip address replace 10.99.0.1/24 dev {name}").await?;
        run!(
            k,
            "wg set {name} peer {peer} preshared-key /dev/stdin allowed-ips 10.99.0.10/32",
            stdin = psk.clone()
        )
        .await?;
        let link = k.read_link(name).await?.unwrap();
        assert_eq!(link.alias, "ito:test");
        assert_eq!(k.list_links().await?[name], "ito:test");
        assert_eq!(link.addresses, ["10.99.0.1/24"]);
        assert_eq!(link.peers[0].preshared_key, psk);
        // An all-zero preshared key clears it.
        run!(
            k,
            "wg set {name} peer {peer} preshared-key /dev/stdin",
            stdin = zero
        )
        .await?;
        assert!(
            k.read_link(name).await?.unwrap().peers[0]
                .preshared_key
                .is_empty()
        );
        run!(k, "wg set {name} peer {peer} remove").await?;
        run!(k, "ip link delete dev {name}").await?;
        assert_eq!(k.read_link(name).await?, None);
        Ok(())
    }
}
