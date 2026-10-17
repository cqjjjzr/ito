//! Linux WireGuard tunnel driver backed by `ip`, `wg`, `nft`, and `resolvectl`.

use ipnet::IpNet;
use ito_agent_core::{
    spec::TunnelSpec,
    tunnel::{TunnelDriver, TunnelError},
};
use ito_shared::dump::{Link, parse_dump};
use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
    process::Stdio,
};
use tokio::io::AsyncWriteExt;

// --- Command execution ---

/// Runs an `xshell::cmd!` template through a [`CommandExecutor`], optionally piping `stdin = …`.
///
/// The template is split into program and arguments at compile time without invoking a shell.
macro_rules! run {
    ($exec:expr, $template:literal) => {
        run!($exec, $template, None)
    };
    ($exec:expr, $template:literal, stdin = $input:expr) => {
        run!($exec, $template, Some(String::from($input)))
    };
    ($exec:expr, $template:literal, $input:expr) => {{
        let sh = xshell::Shell::new().map_err(|e| TunnelError(format!("command setup: {e}")))?;
        $exec.run(build_command_line(xshell::cmd!(sh, $template)), $input)
    }};
}

/// Extracts the program name and argument list from an `xshell::Cmd`.
fn build_command_line(cmd: xshell::Cmd<'_>) -> Vec<String> {
    let cmd = std::process::Command::from(cmd);
    std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

/// Executes external processes without a shell.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait CommandExecutor: Send + Sync {
    /// Runs `line` with optional `stdin` and returns stdout, or an error if the process exits
    /// non-zero.
    async fn run(&self, line: Vec<String>, stdin: Option<String>) -> Result<String, TunnelError>;
}

/// Spawns external commands directly via `tokio::process::Command`.
///
/// Sensitive keys are always passed through `stdin` rather than command-line arguments.
pub struct SystemCommandExecutor;

#[async_trait::async_trait]
impl CommandExecutor for SystemCommandExecutor {
    async fn run(&self, line: Vec<String>, stdin: Option<String>) -> Result<String, TunnelError> {
        let describe_command_error = |e: io::Error| TunnelError(format!("{}: {e}", line[0]));
        let mut child = tokio::process::Command::new(&line[0])
            .args(&line[1..])
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(describe_command_error)?;
        if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(input.as_bytes())
                .await
                .map_err(describe_command_error)?;
        }
        let output = child
            .wait_with_output()
            .await
            .map_err(describe_command_error)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunnelError(format!(
                "{}: {}",
                line.join(" "),
                stderr.trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// Returns `true` if `program` exists on the executable `PATH`.
pub fn is_on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

// --- Linux WireGuard driver ---

/// Starting routing table number for full-tunnel (`0.0.0.0/0` or `::/0`) policy routing, matching
/// `wg-quick`.
const FIRST_TABLE: u32 = 51820;

/// `ip` flags for IPv4 and IPv6 address families.
const FAMILIES: [&str; 2] = ["-4", "-6"];

/// Manages Linux kernel WireGuard interfaces, policy routing rules, `nftables` marks, and
/// `resolvectl` DNS.
///
/// Full-tunnel connections (`0.0.0.0/0` or `::/0`) allocate a dedicated routing table and `fwmark`
/// (`>= 51820`) recorded in `<dir>/<name>.table` before rules are installed, ensuring leftover
/// policy rules and `nft` tables can be cleaned up even if the process crashes or the link is
/// deleted externally.
pub struct LinuxTunnel<E> {
    exec: E,
    /// Directory storing `<name>.table` files that record allocated routing table numbers.
    dir: PathBuf,
    /// Whether `resolvectl` is available on `PATH` for per-interface DNS configuration.
    resolvectl: bool,
    /// Whether `nft` is available on `PATH` for conntrack mark preservation and anti-spoofing
    /// rules.
    nft: bool,
}

impl<E: CommandExecutor> LinuxTunnel<E> {
    pub fn new(exec: E, dir: PathBuf, resolvectl: bool, nft: bool) -> Self {
        Self {
            exec,
            dir,
            resolvectl,
            nft,
        }
    }

    // --- Default-route policy routing and nftables ---

    /// Resolves the path to the `<name>.table` record file.
    fn resolve_record_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.table"))
    }

    /// Lists tunnel names that have a `<name>.table` file in `self.dir`.
    fn list_recorded_names(&self) -> io::Result<Vec<String>> {
        Ok(fs::read_dir(&self.dir)?
            .filter_map(|e| {
                e.ok()?
                    .file_name()
                    .to_str()?
                    .strip_suffix(".table")
                    .map(String::from)
            })
            .collect())
    }

    /// Reads the routing table number recorded for tunnel `name`, if present.
    fn read_record(&self, name: &str) -> Option<u32> {
        fs::read_to_string(self.resolve_record_path(name))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// Finds the first unused routing table number starting at [`FIRST_TABLE`] and records it in
    /// `<name>.table`.
    async fn take_table(&self, name: &str) -> Result<u32, TunnelError> {
        let build_directory_error =
            |e: io::Error| TunnelError(format!("{}: {e}", self.dir.display()));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(build_directory_error)?;
        let recorded: Vec<u32> = (self
            .list_recorded_names()
            .map_err(build_directory_error)?
            .iter())
        .filter_map(|other| self.read_record(other))
        .collect();
        let mut table = FIRST_TABLE;
        loop {
            let mut used = recorded.contains(&table);
            let number = table.to_string();
            for family in FAMILIES {
                // `ip route show table <N>` exits non-zero or prints nothing when table N is empty.
                let shown = run!(self.exec, "ip {family} route show table {number}").await;
                used |= shown.is_ok_and(|routes| !routes.trim().is_empty());
            }
            if !used {
                break;
            }
            table += 1;
        }
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.resolve_record_path(name))
            .and_then(|mut f| io::Write::write_all(&mut f, table.to_string().as_bytes()))
            .map_err(build_directory_error)?;
        Ok(table)
    }

    /// Installs policy routing rules and optional `nftables` rules for default routes (`0.0.0.0/0`
    /// or `::/0`).
    async fn route_defaults(
        &self,
        name: &str,
        spec: &TunnelSpec,
        defaults: &[IpNet],
    ) -> Result<(), TunnelError> {
        let table = self.take_table(name).await?;
        let number = table.to_string();
        run!(self.exec, "wg set {name} fwmark {number}").await?;
        for default in defaults {
            let family = if default.addr().is_ipv4() { "-4" } else { "-6" };
            let route = default.to_string();
            run!(
                self.exec,
                "ip {family} route add {route} dev {name} table {number}"
            )
            .await?;
            run!(
                self.exec,
                "ip {family} rule add not fwmark {number} table {number}"
            )
            .await?;
            run!(
                self.exec,
                "ip {family} rule add table main suppress_prefixlength 0"
            )
            .await?;
        }
        if self.nft {
            // Enable `src_valid_mark` so reverse-path filtering accepts marked packets routed via
            // `main`.
            fs::write("/proc/sys/net/ipv4/conf/all/src_valid_mark", "1")
                .map_err(|e| TunnelError(format!("src_valid_mark: {e}")))?;
            let addresses: Vec<IpNet> = spec
                .addresses
                .iter()
                .filter_map(|a| a.parse().ok())
                .collect();
            let ruleset = build_ruleset(name, table, &addresses);
            run!(self.exec, "nft -f -", stdin = ruleset).await?;
        }
        Ok(())
    }

    /// Removes policy routing rules, routes, `nft` table, and `<name>.table` record for tunnel
    /// `name`.
    async fn unroute_defaults(&self, name: &str) -> Result<(), TunnelError> {
        let Some(table) = self.read_record(name) else {
            return Ok(());
        };
        let number = table.to_string();
        for family in FAMILIES {
            let _ = run!(
                self.exec,
                "ip {family} rule del not fwmark {number} table {number}"
            )
            .await;
            let _ = run!(
                self.exec,
                "ip {family} rule del table main suppress_prefixlength 0"
            )
            .await;
            let _ = run!(self.exec, "ip {family} route flush table {number}").await;
        }
        let _ = run!(self.exec, "nft delete table inet {name}").await;
        match fs::remove_file(self.resolve_record_path(name)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(TunnelError(format!(
                "{}: {e}",
                self.resolve_record_path(name).display()
            ))),
            _ => Ok(()),
        }
    }

    /// Cleans up leftover policy routing rules for any recorded tunnel whose WireGuard link no
    /// longer exists.
    pub async fn sweep(&self) -> Result<(), TunnelError> {
        let Ok(names) = self.list_recorded_names() else {
            return Ok(());
        };
        for name in names {
            if !self.is_up(&name).await? {
                self.unroute_defaults(&name).await?;
            }
        }
        Ok(())
    }

    // --- Link configuration and TunnelDriver implementation ---

    /// Configures keys, addresses, MTU, default routes, and DNS on a newly created WireGuard link
    /// `name`.
    async fn configure(&self, name: &str, spec: &TunnelSpec) -> Result<(), TunnelError> {
        let p = &spec.peer;
        let key = &spec.private_key;
        run!(
            self.exec,
            "wg set {name} private-key /dev/stdin",
            stdin = key
        )
        .await?;
        let public_key = &p.public_key;
        let endpoint = &p.endpoint;
        let allowed = p.allowed_ips.join(",");
        let keepalive = match p.keepalive {
            0 => "off".to_string(),
            seconds => seconds.to_string(),
        };
        if p.preshared_key.is_empty() {
            run!(self.exec, "wg set {name} peer {public_key} endpoint {endpoint} allowed-ips {allowed} persistent-keepalive {keepalive}").await?;
        } else {
            let psk = &p.preshared_key;
            run!(self.exec, "wg set {name} peer {public_key} preshared-key /dev/stdin endpoint {endpoint} allowed-ips {allowed} persistent-keepalive {keepalive}", stdin = psk).await?;
        }
        for address in &spec.addresses {
            run!(self.exec, "ip address add {address} dev {name}").await?;
        }
        let mtu = if spec.mtu == 0 { 1420 } else { spec.mtu }.to_string();
        run!(self.exec, "ip link set dev {name} mtu {mtu} up").await?;
        let defaults = spec.default_routes();
        if !defaults.is_empty() {
            self.route_defaults(name, spec, &defaults).await?;
        }
        if self.resolvectl && (!spec.dns.is_empty() || !spec.dns_search.is_empty()) {
            let dns = &spec.dns;
            let mut domains = spec.dns_search.clone();
            if !defaults.is_empty() {
                domains.push("~.".into());
            }
            // Do not fail tunnel bring-up if systemd-resolved is inactive.
            let configured = async {
                run!(self.exec, "resolvectl status").await?;
                if !dns.is_empty() {
                    run!(self.exec, "resolvectl dns {name} {dns...}").await?;
                }
                if !domains.is_empty() {
                    run!(self.exec, "resolvectl domain {name} {domains...}").await?;
                }
                Ok::<_, TunnelError>(())
            }
            .await;
            if let Err(e) = configured {
                eprintln!("{name}: skipping DNS configuration: {e}");
            }
        }
        Ok(())
    }
}

/// Builds the `nft` table `name` that lets endpoint replies marked `table` pass reverse-path
/// filtering and drops packets for `addresses` arriving on other links.
fn build_ruleset(name: &str, table: u32, addresses: &[IpNet]) -> String {
    let spoofed = addresses.iter().map(|a| {
        let family = if a.addr().is_ipv4() { "ip" } else { "ip6" };
        let address = a.addr();
        format!("    iifname != {name:?} {family} daddr {address} fib saddr type != local drop\n")
    });
    format!(
        "table inet {name} {{\n  chain preraw {{\n    type filter hook prerouting priority raw; policy accept;\n{}  }}\n  chain premangle {{\n    type filter hook prerouting priority mangle; policy accept;\n    meta l4proto udp meta mark set ct mark\n  }}\n  chain postmangle {{\n    type filter hook postrouting priority mangle; policy accept;\n    meta l4proto udp meta mark {table} ct mark set meta mark\n  }}\n}}\n",
        spoofed.collect::<String>()
    )
}

#[async_trait::async_trait]
impl<E: CommandExecutor> TunnelDriver for LinuxTunnel<E> {
    async fn up(&self, name: &str, spec: &TunnelSpec) -> Result<(), TunnelError> {
        // Clear any stale routing rules left over from an unclean shutdown.
        self.unroute_defaults(name).await?;
        run!(self.exec, "ip link add dev {name} type wireguard").await?;
        let configured = self.configure(name, spec).await;
        if configured.is_err() {
            // Remove the partially configured link on error.
            let _ = self.down(name).await;
        }
        configured
    }

    async fn reconcile(&self, name: &str, spec: &TunnelSpec) -> Result<(), TunnelError> {
        // Use a high route metric so local LAN routes take precedence.
        const METRIC: &str = "51820";
        let mut conflicts = Vec::new();
        let mut wanted: Vec<IpNet> = spec
            .peer
            .allowed_ips
            .iter()
            .filter_map(|r| r.parse().ok())
            .filter(|r: &IpNet| r.prefix_len() != 0)
            .collect();
        wanted.sort();
        wanted.dedup();
        for family in FAMILIES {
            let shown = run!(self.exec, "ip {family} -j route show table main").await?;
            let routes: Vec<serde_json::Value> = serde_json::from_str(&shown)
                .map_err(|e| TunnelError(format!("cannot read host routes: {e}")))?;
            for prefix in &wanted {
                if prefix.addr().is_ipv4() != (family == "-4") {
                    continue;
                }
                let own = routes.iter().any(|r| {
                    r["dev"] == name
                        && r["dst"].as_str().and_then(|s| s.parse::<IpNet>().ok()) == Some(*prefix)
                        && r["metric"].as_u64() == Some(51820)
                });
                let conflict = routes.iter().find(|r| {
                    let Some(other) = r["dst"].as_str().and_then(|s| s.parse::<IpNet>().ok())
                    else {
                        return false;
                    };
                    let direct = r["scope"] == "link" || r["protocol"] == "kernel";
                    r["dev"].as_str().is_some_and(|dev| dev != name)
                        && (other == *prefix || (direct && other.contains(prefix)))
                });
                let route = prefix.to_string();
                if let Some(other) = conflict {
                    if own {
                        run!(
                            self.exec,
                            "ip {family} route del {route} dev {name} metric {METRIC}"
                        )
                        .await?;
                    }
                    conflicts.push(format!(
                        "{route} conflicts with host route on {}; select different AllowedIPs",
                        other["dev"].as_str().unwrap_or("another interface")
                    ));
                } else if !own
                    && let Err(e) = run!(
                        self.exec,
                        "ip {family} route add {route} dev {name} metric {METRIC}"
                    )
                    .await
                {
                    conflicts.push(format!("{route}: {e}; select different AllowedIPs"));
                }
            }
        }
        if conflicts.is_empty() {
            Ok(())
        } else {
            Err(TunnelError(conflicts.join("; ")))
        }
    }

    async fn down(&self, name: &str) -> Result<(), TunnelError> {
        if self.is_up(name).await? {
            run!(self.exec, "ip link del dev {name}").await?;
        }
        self.unroute_defaults(name).await
    }

    async fn is_up(&self, name: &str) -> Result<bool, TunnelError> {
        Ok(run!(self.exec, "ip link show dev {name}").await.is_ok())
    }

    async fn read(&self, name: &str) -> Result<Option<Link>, TunnelError> {
        let Ok(json) = run!(self.exec, "ip -json address show dev {name}").await else {
            return Ok(None);
        };
        let build_unexpected_error = || TunnelError("unexpected ip output".into());
        let links: serde_json::Value =
            serde_json::from_str(&json).map_err(|_| build_unexpected_error())?;
        let ip = links.get(0).ok_or_else(build_unexpected_error)?;
        let dump = run!(self.exec, "wg show {name} dump").await?;
        let mut link = parse_dump(&dump).map_err(|_| TunnelError("unexpected wg output".into()))?;
        link.up = ip["flags"]
            .as_array()
            .is_some_and(|f| f.iter().any(|v| v == "UP"));
        link.mtu = ip["mtu"].as_i64().unwrap_or_default() as i32;
        link.addresses = (ip["addr_info"].as_array().into_iter().flatten())
            .filter_map(|a| {
                Some(format!(
                    "{}/{}",
                    a["local"].as_str()?,
                    a["prefixlen"].as_u64()?
                ))
            })
            .collect();
        Ok(Some(link))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ito_agent_core::spec::PeerSpec;
    use std::sync::{Arc, Mutex};

    /// The command lines a mock executor received, each followed by ` < ` and its stdin if any.
    type CommandLog = Arc<Mutex<Vec<String>>>;

    /// Builds a mock executor that records each command line and answers it with `answer`.
    fn record_commands(
        answer: impl Fn(&str) -> Result<String, TunnelError> + Send + 'static,
    ) -> (MockCommandExecutor, CommandLog) {
        let log = CommandLog::default();
        let recorded = log.clone();
        let mut exec = MockCommandExecutor::new();
        exec.expect_run().returning(move |line, stdin| {
            let line = line.join(" ");
            let input = stdin.map(|s| format!(" < {s}")).unwrap_or_default();
            recorded.lock().unwrap().push(format!("{line}{input}"));
            answer(&line)
        });
        (exec, log)
    }

    /// Answers `line` like a host where the link `ito-a` exists when `up`, routing table 51820 is
    /// taken and the main routing tables are empty.
    fn answer_like_a_host(line: &str, up: bool) -> Result<String, TunnelError> {
        if line.ends_with("show dev ito-a") && !up {
            return Err(TunnelError("Device \"ito-a\" does not exist.".into()));
        }
        if line == "ip -4 route show table 51820" {
            return Ok("default dev wg0\n".into());
        }
        if line.contains("-j route show") {
            return Ok("[]".into());
        }
        Ok(String::new())
    }

    /// Answers `ip -j route show` with `routes` for IPv4 and like a host with link `ito-a` otherwise.
    fn answer_with_ipv4_routes(
        routes: &'static str,
    ) -> impl Fn(&str) -> Result<String, TunnelError> {
        move |line| match line {
            "ip -4 -j route show table main" => Ok(routes.into()),
            line => answer_like_a_host(line, true),
        }
    }

    fn build_sample_spec(allowed_ips: &[&str]) -> TunnelSpec {
        TunnelSpec {
            private_key: "KEY=".into(),
            addresses: vec!["10.0.0.2/32".into(), "fd00::2/128".into()],
            dns: vec!["10.0.0.1".into()],
            dns_search: vec!["vpn.test".into()],
            mtu: 0,
            peer: PeerSpec {
                public_key: "SERVER=".into(),
                preshared_key: "PSK=".into(),
                endpoint: "vpn.test:51820".into(),
                allowed_ips: allowed_ips.iter().map(|s| s.to_string()).collect(),
                keepalive: 25,
            },
        }
    }

    #[tokio::test]
    async fn reads_report_flags_mtu_and_addresses_of_both_families() {
        let mut exec = MockCommandExecutor::new();
        exec.expect_run().returning(|line, _| match line.join(" ").as_str() {
            "ip -json address show dev ito-a" => Ok(r#"[{"flags":["UP"],"mtu":1380,"addr_info":[{"local":"10.0.0.2","prefixlen":32},{"local":"fd00::2","prefixlen":128}]}]"#.into()),
            "wg show ito-a dump" => Ok("(none)\tPUBLIC=\t51820\t0\n".into()),
            command => panic!("unexpected command: {command}"),
        });
        let dir = tempfile::tempdir().unwrap();
        let tunnel = LinuxTunnel::new(exec, dir.path().into(), false, false);
        let link = tunnel.read("ito-a").await.unwrap().unwrap();
        assert!(link.up);
        assert_eq!(link.mtu, 1380);
        assert_eq!(link.addresses, ["10.0.0.2/32", "fd00::2/128"]);
        assert_eq!(link.public_key, "PUBLIC=");
    }

    #[tokio::test]
    async fn reads_of_absent_links_find_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (exec, log) = record_commands(|line| answer_like_a_host(line, false));
        let tunnel = LinuxTunnel::new(exec, dir.path().into(), false, false);
        assert_eq!(tunnel.read("ito-a").await.unwrap(), None);
        assert_eq!(*log.lock().unwrap(), ["ip -json address show dev ito-a"]);
    }

    #[tokio::test]
    async fn routed_tunnels_get_keys_addresses_routes_and_dns() {
        let dir = tempfile::tempdir().unwrap();
        let (exec, log) = record_commands(|line| answer_like_a_host(line, false));
        let tunnel = LinuxTunnel::new(exec, dir.path().into(), true, true);
        let spec = build_sample_spec(&["10.0.0.0/24"]);
        tunnel.up("ito-a", &spec).await.unwrap();
        tunnel.reconcile("ito-a", &spec).await.unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            [
                "ip link add dev ito-a type wireguard",
                "wg set ito-a private-key /dev/stdin < KEY=",
                "wg set ito-a peer SERVER= preshared-key /dev/stdin endpoint vpn.test:51820 \
                 allowed-ips 10.0.0.0/24 persistent-keepalive 25 < PSK=",
                "ip address add 10.0.0.2/32 dev ito-a",
                "ip address add fd00::2/128 dev ito-a",
                "ip link set dev ito-a mtu 1420 up",
                "resolvectl status",
                "resolvectl dns ito-a 10.0.0.1",
                "resolvectl domain ito-a vpn.test",
                "ip -4 -j route show table main",
                "ip -4 route add 10.0.0.0/24 dev ito-a metric 51820",
                "ip -6 -j route show table main",
            ]
        );
    }

    #[tokio::test]
    async fn default_routes_take_the_first_free_table() {
        let dir = tempfile::tempdir().unwrap();
        let (exec, log) = record_commands(|line| answer_like_a_host(line, true));
        // Without nft, the test leaves /proc/sys alone.
        let tunnel = LinuxTunnel::new(exec, dir.path().into(), false, false);
        tunnel
            .up("ito-a", &build_sample_spec(&["0.0.0.0/0", "::/0"]))
            .await
            .unwrap();
        let record = fs::read_to_string(dir.path().join("ito-a.table")).unwrap();
        assert_eq!(record, "51821");
        let commands = log.lock().unwrap();
        let start = commands.iter().position(|l| l.contains("fwmark")).unwrap();
        assert_eq!(
            commands[start..],
            [
                "wg set ito-a fwmark 51821",
                "ip -4 route add 0.0.0.0/0 dev ito-a table 51821",
                "ip -4 rule add not fwmark 51821 table 51821",
                "ip -4 rule add table main suppress_prefixlength 0",
                "ip -6 route add ::/0 dev ito-a table 51821",
                "ip -6 rule add not fwmark 51821 table 51821",
                "ip -6 rule add table main suppress_prefixlength 0",
            ]
        );
    }

    #[tokio::test]
    async fn sweeps_remove_the_rules_of_links_that_are_gone() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("ito-a.table"), "51821").unwrap();
        let (exec, log) = record_commands(|line| answer_like_a_host(line, false));
        let tunnel = LinuxTunnel::new(exec, dir.path().into(), false, true);
        tunnel.sweep().await.unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            [
                "ip link show dev ito-a",
                "ip -4 rule del not fwmark 51821 table 51821",
                "ip -4 rule del table main suppress_prefixlength 0",
                "ip -4 route flush table 51821",
                "ip -6 rule del not fwmark 51821 table 51821",
                "ip -6 rule del table main suppress_prefixlength 0",
                "ip -6 route flush table 51821",
                "nft delete table inet ito-a",
            ]
        );
        assert!(!dir.path().join("ito-a.table").exists());
    }

    #[tokio::test]
    async fn sweeps_keep_the_rules_of_running_links() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("ito-a.table"), "51821").unwrap();
        let (exec, log) = record_commands(|line| answer_like_a_host(line, true));
        let tunnel = LinuxTunnel::new(exec, dir.path().into(), false, true);
        tunnel.sweep().await.unwrap();
        assert_eq!(*log.lock().unwrap(), ["ip link show dev ito-a"]);
        assert!(dir.path().join("ito-a.table").exists());
    }

    #[test]
    fn rulesets_mark_endpoint_replies_and_drop_spoofed_packets() {
        let addresses = [
            "10.0.0.2/32".parse().unwrap(),
            "fd00::2/128".parse().unwrap(),
        ];
        let ruleset = build_ruleset("ito-a", 51820, &addresses);
        assert!(ruleset.starts_with("table inet ito-a {\n"));
        for rule in [
            "iifname != \"ito-a\" ip daddr 10.0.0.2 fib saddr type != local drop\n",
            "iifname != \"ito-a\" ip6 daddr fd00::2 fib saddr type != local drop\n",
            "meta l4proto udp meta mark 51820 ct mark set meta mark\n",
        ] {
            assert!(ruleset.contains(rule), "{rule}");
        }
    }

    #[tokio::test]
    async fn half_configured_links_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (exec, log) = record_commands(|line| {
            if line.starts_with("wg set ito-a peer") {
                return Err(TunnelError("bad endpoint".into()));
            }
            answer_like_a_host(line, true)
        });
        let tunnel = LinuxTunnel::new(exec, dir.path().into(), false, false);
        let failed = tunnel
            .up("ito-a", &build_sample_spec(&["10.0.0.0/24"]))
            .await
            .unwrap_err();
        assert_eq!(failed.0, "bad endpoint");
        let commands = log.lock().unwrap();
        assert!(commands[commands.len() - 3].starts_with("wg set ito-a peer"));
        assert_eq!(
            commands[commands.len() - 2..],
            ["ip link show dev ito-a", "ip link del dev ito-a"]
        );
    }

    #[tokio::test]
    async fn a_stopped_resolver_leaves_dns_alone_without_failing_the_tunnel() {
        let dir = tempfile::tempdir().unwrap();
        let (exec, log) = record_commands(|line| match line {
            "resolvectl status" => Err(TunnelError("resolved is stopped".into())),
            line => answer_like_a_host(line, false),
        });
        let tunnel = LinuxTunnel::new(exec, dir.path().into(), true, false);
        tunnel
            .up("ito-a", &build_sample_spec(&["10.0.0.0/24"]))
            .await
            .unwrap();
        let commands = log.lock().unwrap();
        let resolver_commands: Vec<&String> = commands
            .iter()
            .filter(|l| l.starts_with("resolvectl"))
            .collect();
        assert_eq!(resolver_commands, ["resolvectl status"]);
    }

    #[tokio::test]
    async fn taking_absent_links_down_deletes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (exec, log) = record_commands(|line| answer_like_a_host(line, false));
        let tunnel = LinuxTunnel::new(exec, dir.path().into(), false, false);
        tunnel.down("ito-a").await.unwrap();
        assert_eq!(*log.lock().unwrap(), ["ip link show dev ito-a"]);
    }

    #[tokio::test]
    async fn host_route_conflicts_are_reported_and_the_own_route_withdrawn() {
        let dir = tempfile::tempdir().unwrap();
        let routes = r#"[{"dst":"10.0.0.0/24","dev":"ito-a","metric":51820},
                         {"dst":"10.0.0.0/16","dev":"eth0","scope":"link","protocol":"kernel"}]"#;
        let (exec, log) = record_commands(answer_with_ipv4_routes(routes));
        let tunnel = LinuxTunnel::new(exec, dir.path().into(), false, false);
        let refused = tunnel
            .reconcile("ito-a", &build_sample_spec(&["10.0.0.0/24"]))
            .await
            .unwrap_err();
        assert!(
            refused
                .0
                .starts_with("10.0.0.0/24 conflicts with host route on eth0")
        );
        let withdrawn = "ip -4 route del 10.0.0.0/24 dev ito-a metric 51820";
        assert!(log.lock().unwrap().iter().any(|l| l == withdrawn));
    }

    #[tokio::test]
    async fn routes_already_in_place_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let routes = r#"[{"dst":"10.0.0.0/24","dev":"ito-a","metric":51820}]"#;
        let (exec, log) = record_commands(answer_with_ipv4_routes(routes));
        let tunnel = LinuxTunnel::new(exec, dir.path().into(), false, false);
        tunnel
            .reconcile("ito-a", &build_sample_spec(&["10.0.0.0/24"]))
            .await
            .unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            [
                "ip -4 -j route show table main",
                "ip -6 -j route show table main"
            ]
        );
    }

    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN in a disposable network namespace"]
    async fn real_kernel_lan_vpn_states_and_all_eight_transitions() -> Result<(), TunnelError> {
        assert_eq!(std::env::var("ITO_KERNEL_TEST").as_deref(), Ok("1"));
        let dir = tempfile::tempdir().unwrap();
        let tunnel = LinuxTunnel::new(SystemCommandExecutor, dir.path().into(), false, false);
        let mut s = build_sample_spec(&["10.0.0.0/24", "fd00::/64"]);
        s.private_key = ito_shared::keys::generate_key_pair().private;
        s.peer.public_key = ito_shared::keys::generate_key_pair().public;
        s.peer.preshared_key.clear();
        s.peer.endpoint = "192.0.2.1:51820".into();
        async fn set_lan_addresses(up: bool) -> Result<(), TunnelError> {
            let op = if up { "add" } else { "del" };
            run!(
                SystemCommandExecutor,
                "ip address {op} 10.0.0.3/24 dev ito-test-lan"
            )
            .await
            .unwrap();
            if up {
                run!(
                    SystemCommandExecutor,
                    "ip -6 address add fd00::3/64 dev ito-test-lan nodad"
                )
                .await
                .unwrap();
            } else {
                run!(
                    SystemCommandExecutor,
                    "ip -6 address del fd00::3/64 dev ito-test-lan"
                )
                .await
                .unwrap();
            }
            Ok(())
        }

        async fn assert_selected_route(lan: bool, vpn: bool) -> Result<(), TunnelError> {
            for (family, target) in [("-4", "10.0.0.50"), ("-6", "fd00::50")] {
                let route = run!(SystemCommandExecutor, "ip {family} -j route get {target}").await;
                let routes: serde_json::Value = serde_json::from_str(&route.unwrap()).unwrap();
                assert_eq!(
                    routes[0]["dev"],
                    if lan || !vpn {
                        "ito-test-lan"
                    } else {
                        "ito-test-vpn"
                    }
                );
                assert_eq!(routes[0]["gateway"].is_string(), !lan && !vpn);
            }
            Ok(())
        }
        for initial_lan in [false, true] {
            for initial_vpn in [false, true] {
                for flip_lan in [false, true] {
                    run!(SystemCommandExecutor, "ip link add ito-test-lan type dummy")
                        .await
                        .unwrap();
                    run!(SystemCommandExecutor, "ip link set ito-test-lan up")
                        .await
                        .unwrap();
                    run!(
                        SystemCommandExecutor,
                        "ip address add 198.51.100.3/24 dev ito-test-lan"
                    )
                    .await
                    .unwrap();
                    run!(
                        SystemCommandExecutor,
                        "ip -6 address add 2001:db8:1::3/64 dev ito-test-lan nodad"
                    )
                    .await
                    .unwrap();
                    run!(
                        SystemCommandExecutor,
                        "ip route add default via 198.51.100.1 dev ito-test-lan"
                    )
                    .await
                    .unwrap();
                    run!(
                        SystemCommandExecutor,
                        "ip -6 route add default via 2001:db8:1::1 dev ito-test-lan"
                    )
                    .await
                    .unwrap();
                    if initial_lan {
                        set_lan_addresses(true).await.unwrap();
                    }
                    if initial_vpn {
                        tunnel.up("ito-test-vpn", &s).await.unwrap();
                        assert_eq!(
                            tunnel.reconcile("ito-test-vpn", &s).await.is_err(),
                            initial_lan
                        );
                    }
                    assert_selected_route(initial_lan, initial_vpn)
                        .await
                        .unwrap();
                    let (next_lan, next_vpn) = if flip_lan {
                        set_lan_addresses(!initial_lan).await.unwrap();
                        // The lower-metric LAN route takes precedence immediately, even before
                        // reconcile runs.
                        if !initial_lan {
                            assert_selected_route(true, initial_vpn).await.unwrap();
                        }
                        (!initial_lan, initial_vpn)
                    } else {
                        if initial_vpn {
                            tunnel.down("ito-test-vpn").await.unwrap();
                        } else {
                            tunnel.up("ito-test-vpn", &s).await.unwrap();
                        }
                        (initial_lan, !initial_vpn)
                    };
                    if next_vpn {
                        assert_eq!(
                            tunnel.reconcile("ito-test-vpn", &s).await.is_err(),
                            next_lan
                        );
                    }
                    assert_selected_route(next_lan, next_vpn).await.unwrap();
                    if next_vpn {
                        tunnel.down("ito-test-vpn").await.unwrap();
                    }
                    run!(SystemCommandExecutor, "ip link del ito-test-lan")
                        .await
                        .unwrap();
                }
            }
        }
        Ok(())
    }

    /// Returns all `ip rule` and `nft list tables` lines containing `needle`.
    async fn find_rules(needle: &str) -> Vec<String> {
        let mut found = Vec::new();
        for line in [
            vec!["ip", "-4", "rule"],
            vec!["ip", "-6", "rule"],
            vec!["nft", "list", "tables"],
        ] {
            let line = line.into_iter().map(String::from).collect();
            let shown = SystemCommandExecutor
                .run(line, None)
                .await
                .unwrap_or_default();
            found.extend(
                shown
                    .lines()
                    .filter(|l| l.contains(needle))
                    .map(String::from),
            );
        }
        found
    }

    #[tokio::test]
    #[ignore = "needs CAP_NET_ADMIN in a disposable network namespace"]
    async fn real_kernel_default_routes_come_and_go() {
        assert_eq!(std::env::var("ITO_KERNEL_TEST").as_deref(), Ok("1"));
        let dir = tempfile::tempdir().unwrap();
        let tunnel = LinuxTunnel::new(
            SystemCommandExecutor,
            dir.path().into(),
            false,
            is_on_path("nft"),
        );
        let mut first = build_sample_spec(&["0.0.0.0/0", "::/0"]);
        first.private_key = ito_shared::keys::generate_key_pair().private;
        first.peer.public_key = ito_shared::keys::generate_key_pair().public;
        first.peer.preshared_key = ito_shared::keys::generate_key_pair().public;
        first.peer.endpoint = "192.0.2.1:51820".into();
        let mut second = first.clone();
        second.addresses = vec!["10.0.1.2/32".into(), "fd00:1::2/128".into()];
        tunnel.up("ito-k1", &first).await.unwrap();
        tunnel.up("ito-k2", &second).await.unwrap();
        let read_fwmark = |name: &'static str| async move {
            SystemCommandExecutor
                .run(
                    vec!["wg".into(), "show".into(), name.into(), "fwmark".into()],
                    None,
                )
                .await
                .unwrap()
        };
        assert_eq!(read_fwmark("ito-k1").await.trim(), "0xca6c");
        assert_eq!(read_fwmark("ito-k2").await.trim(), "0xca6d");
        assert_eq!(find_rules("lookup 51821").await.len(), 2);
        if is_on_path("nft") {
            assert_eq!(find_rules("table inet ito-k").await.len(), 2);
        }
        // Deleting a link directly leaves its policy rules until `sweep()` runs.
        SystemCommandExecutor
            .run(
                vec![
                    "ip".into(),
                    "link".into(),
                    "del".into(),
                    "dev".into(),
                    "ito-k1".into(),
                ],
                None,
            )
            .await
            .unwrap();
        tunnel.sweep().await.unwrap();
        assert!(find_rules("lookup 51820").await.is_empty());
        assert!(find_rules("ito-k1").await.is_empty());
        assert_eq!(find_rules("lookup 51821").await.len(), 2);
        tunnel.down("ito-k2").await.unwrap();
        assert!(find_rules("lookup 5182").await.is_empty());
        assert!(find_rules("suppress_prefixlength").await.is_empty());
        assert!(find_rules("ito-k").await.is_empty());
    }
}
