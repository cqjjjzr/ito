use crate::addressing::{Quota, prefix};
use ipnet::IpNet;
use ito_shared::names::{is_dns_domain, is_dns_label, is_endpoint};
use reqwest::Url;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

// --- Top-level configuration ---

/// Controller configuration loaded from TOML.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(extend("required" = ["public_url", "oidc"]))]
pub struct Config {
    /// Socket address for the HTTP listener. Deploy a TLS-terminating reverse proxy in front of
    /// this address.
    pub listen: SocketAddr,
    /// Socket address for the Prometheus `/metrics` listener. Leave unset to disable the metrics
    /// listener.
    #[schemars(example = &"127.0.0.1:8001")]
    pub metrics_listen: Option<SocketAddr>,
    /// External browser origin of the service: scheme, lowercase host, and optional non-default
    /// port, with no path or trailing slash. Used to validate the `Origin` header on state-changing
    /// requests and to construct the OIDC redirect URI.
    #[schemars(url, example = &"https://vpn.example.com")]
    pub public_url: String,
    /// Whether session and login cookies set the `Secure` attribute and `__Host-` prefix. Set to
    /// `false` only for local plain-HTTP testing.
    pub cookie_secure: bool,
    /// Absolute path to the SQLite database file. The controller holds an exclusive file lock on
    /// this path while running.
    pub database: PathBuf,
    /// Maximum lifetime of a browser session before the user must sign in again.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub session_lifetime: Duration,
    /// Maximum idle time between requests for a browser session. Must not exceed
    /// `session_lifetime`.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub session_idle: Duration,
    /// Validity period of a device's WireGuard public key after it is set or renewed, at least 4
    /// days. When a key expires, the reconciler removes the peer from the kernel until a key is set
    /// again.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub key_lifetime: Duration,
    pub oidc: Oidc,
    pub scim: Option<Scim>,
    /// Managed WireGuard interfaces keyed by Linux interface name (which also serves as the
    /// interface ID in the API).
    pub interfaces: BTreeMap<String, Interface>,
    pub dns: Option<Dns>,
    pub quota: DefaultQuota,
    pub log: Log,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8000)),
            metrics_listen: None,
            public_url: String::new(),
            cookie_secure: true,
            database: "/var/lib/ito/ito.db".into(),
            session_lifetime: Duration::from_hours(12),
            session_idle: Duration::from_hours(1),
            key_lifetime: Duration::from_hours(365 * 24),
            oidc: Oidc::default(),
            scim: None,
            interfaces: BTreeMap::new(),
            dns: None,
            quota: DefaultQuota::default(),
            log: Log::default(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<(), String> {
        let origin = Url::parse(&self.public_url)
            .ok()
            .filter(|u| u.path() == "/" && u.origin().ascii_serialization() == self.public_url);
        if origin.is_none() {
            return Err(
                "public_url must be the browser origin: scheme, lowercase host and optional \
                 non-default port, with no path or trailing slash"
                    .into(),
            );
        }
        validate_absolute("database", &self.database)?;
        validate_lifetime("session_lifetime", self.session_lifetime)?;
        validate_lifetime("session_idle", self.session_idle)?;
        validate_lifetime("key_lifetime", self.key_lifetime)?;
        // Agents renew keys 3 days before they expire, so a shorter lifetime would have them
        // renew on every sync.
        if self.key_lifetime < Duration::from_hours(4 * 24) {
            return Err("key_lifetime must be at least 4 days".into());
        }
        if self.session_idle > self.session_lifetime {
            return Err("session_idle must not exceed session_lifetime".into());
        }
        self.oidc.validate()?;
        if let Some(scim) = &self.scim {
            scim.validate()?;
        }
        for (name, interface) in &self.interfaces {
            interface.validate(name)?;
        }
        validate_interfaces_apart(&self.interfaces)?;
        let zones: std::collections::BTreeSet<&str> = self
            .interfaces
            .values()
            .map(|i| i.dns_zone.as_str())
            .filter(|z| !z.is_empty())
            .collect();
        match &self.dns {
            Some(dns) => dns.validate(&zones)?,
            None if !zones.is_empty() => {
                return Err("an interface's dns_zone needs the [dns] section".into());
            }
            None => {}
        }
        self.quota.validate()?;
        self.log.validate()
    }
}

// --- WireGuard interfaces and pools ---

/// WireGuard interface configuration, address pools, and client configuration hints.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, utoipa::ToSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(extend("required" = ["private_key_file", "listen_port", "endpoint"]))]
#[schema(as = InterfaceSettings)]
pub struct Interface {
    /// Absolute path to the server's WireGuard private key file (as generated by `wg genkey`). Read
    /// once at startup.
    #[serde(skip_serializing)]
    #[schema(ignore)]
    #[schemars(example = &"/etc/ito/keys/wg0.key")]
    pub private_key_file: PathBuf,
    /// UDP port the server interface listens on.
    #[schemars(example = 51820)]
    pub listen_port: i32,
    /// External `host:port` endpoint that clients connect to.
    #[schemars(example = &"vpn.example.com:51820")]
    pub endpoint: String,
    /// CIDR addresses assigned to the server interface, such as `10.0.0.1/24`.
    #[schemars(example = ["10.0.0.1/24", "fd00::1/64"])]
    pub addresses: Vec<String>,
    /// MTU of the server interface.
    pub mtu: i32,
    /// When `true`, the reconciler brings the interface down and removes all peers.
    pub disabled: bool,
    /// Suggested MTU for client configs, or `0` to let the client choose automatically.
    pub client_mtu: i32,
    /// DNS server IP addresses included in client configs.
    pub dns: Vec<String>,
    /// DNS search domains included in client configs.
    pub dns_search: Vec<String>,
    /// Authoritative DNS zone served by `[dns]` for devices on this interface, or empty to disable.
    /// Multiple interfaces can share a zone. Also appended to the client's DNS search domains after
    /// `dns_search`.
    #[serde(deserialize_with = "deserialize_domain_name")]
    #[schemars(example = &"vpn.example.com")]
    pub dns_zone: String,
    /// PersistentKeepalive interval in seconds for client configs, or `0` to disable.
    pub keepalive: i32,
    /// ID of the default route profile for clients, or empty when `route_profiles` is empty.
    pub default_profile_id: String,
    /// Named sets of client-side `AllowedIPs` that users can choose between.
    pub route_profiles: Vec<RouteProfile>,
    /// Address pools from which device addresses and prefix grants are allocated.
    pub pools: Vec<Pool>,
}

impl Default for Interface {
    fn default() -> Self {
        Self {
            private_key_file: PathBuf::new(),
            listen_port: 0,
            endpoint: String::new(),
            addresses: Vec::new(),
            mtu: 1420,
            disabled: false,
            client_mtu: 0,
            dns: Vec::new(),
            dns_search: Vec::new(),
            dns_zone: String::new(),
            keepalive: 0,
            default_profile_id: String::new(),
            route_profiles: Vec::new(),
            pools: Vec::new(),
        }
    }
}

impl Interface {
    fn validate(&self, name: &str) -> Result<(), String> {
        let format_key = |k: &str| format!("interfaces.{name}.{k}");
        // Validate against Linux kernel network device naming rules.
        let name_ok = !name.is_empty()
            && name.len() <= 15
            && name != "."
            && name != ".."
            && !name
                .bytes()
                .any(|b| matches!(b, b'/' | b':' | b' ' | b'\t'..=b'\r'));
        if !name_ok {
            return Err(format!(
                "interfaces.{name} must be named as a Linux interface"
            ));
        }
        validate_absolute(&format_key("private_key_file"), &self.private_key_file)?;
        // Port 0 would let the kernel pick an ephemeral port that clients cannot know in advance.
        if !(1..=65535).contains(&self.listen_port) {
            return Err(format!(
                "{} must be a port from 1 to 65535",
                format_key("listen_port")
            ));
        }
        if !is_endpoint(&self.endpoint) {
            return Err(format!("{} must be host:port", format_key("endpoint")));
        }
        for a in &self.addresses {
            prefix::parse_interface_address(a).map_err(|e| {
                format!(
                    "{}: {}",
                    format_key("addresses"),
                    e.detail.unwrap_or_default()
                )
            })?;
        }
        if self.mtu <= 0 {
            return Err(format!("{} must be positive", format_key("mtu")));
        }
        if self.client_mtu < 0 {
            return Err(format!("{} must not be negative", format_key("client_mtu")));
        }
        if !(0..=65535).contains(&self.keepalive) {
            return Err(format!(
                "{} must be from 0 to 65535",
                format_key("keepalive")
            ));
        }
        if let Some(d) = self.dns.iter().find(|d| d.parse::<IpAddr>().is_err()) {
            return Err(format!("{}: {d} is not an IP address", format_key("dns")));
        }
        if let Some(d) = self.dns_search.iter().find(|d| !is_dns_domain(d)) {
            return Err(format!("{}: {d} is not a domain", format_key("dns_search")));
        }
        if !self.dns_zone.is_empty() && !is_dns_domain(&self.dns_zone) {
            return Err(format!("{} must be a domain", format_key("dns_zone")));
        }
        let mut ids = std::collections::BTreeSet::new();
        for p in &self.route_profiles {
            let ok = is_dns_label(&p.id)
                && ids.insert(&p.id)
                && !p.name.is_empty()
                && !p.name.contains(['\r', '\n', '\0'])
                && prefix::remove_covered_prefixes(&p.allowed_ips).is_ok();
            if !ok {
                return Err(format!(
                    "{} need unique label IDs, names and valid prefixes",
                    format_key("route_profiles")
                ));
            }
        }
        if !(ids.is_empty() && self.default_profile_id.is_empty()
            || ids.contains(&self.default_profile_id))
        {
            return Err(format!(
                "{} must name a route profile",
                format_key("default_profile_id")
            ));
        }
        for pool in &self.pools {
            pool.validate()
                .map_err(|e| format!("{} {}: {e}", format_key("pools"), pool.prefix))?;
        }
        Ok(())
    }
}

/// Named set of `AllowedIPs` that a client can select for its local tunnel routes. Selecting a
/// profile changes only the client's `AllowedIPs`, leaving the server's peer routes unchanged.
#[derive(
    Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, utoipa::ToSchema, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct RouteProfile {
    /// Profile identifier: a DNS label that is unique within the interface.
    #[schemars(example = &"all")]
    pub id: String,
    /// Display name shown to users in the portal and agent UI.
    #[schemars(example = &"All traffic")]
    pub name: String,
    /// Client-side `AllowedIPs` prefixes routed through the tunnel when this profile is active.
    #[schemars(example = ["0.0.0.0/0", "::/0"])]
    pub allowed_ips: Vec<String>,
}

/// Address pool from which device addresses and routed prefixes are allocated.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Pool {
    /// CIDR prefix of the pool, such as `10.0.0.0/24`. Pools must not overlap within or across
    /// interfaces.
    #[serde(deserialize_with = "deserialize_prefix")]
    #[schemars(with = "String", example = &"10.0.0.0/24")]
    #[schema(value_type = String)]
    pub prefix: IpNet,
    /// Minimum prefix length (largest block size) a single grant from this pool may have. When
    /// unset, only single-host grants (`/32` or `/128`) are allowed.
    #[serde(default)]
    #[schemars(example = 28)]
    pub min_prefix_length: Option<u8>,
    /// Maximum number of grants a single device may hold from this pool.
    #[serde(default = "default_max_prefixes")]
    pub max_prefixes: u32,
    /// Sub-prefixes inside the pool that are reserved and never allocated to devices.
    #[serde(default, deserialize_with = "deserialize_prefixes")]
    #[schemars(with = "Vec<String>")]
    #[schema(value_type = Vec<String>)]
    pub exclusions: Vec<IpNet>,
}

fn default_max_prefixes() -> u32 {
    1
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            prefix: IpNet::default(),
            min_prefix_length: None,
            max_prefixes: default_max_prefixes(),
            exclusions: Vec::new(),
        }
    }
}

impl Pool {
    /// Returns the minimum prefix length allowed for a grant from this pool.
    pub fn min_length(&self) -> u8 {
        self.min_prefix_length
            .unwrap_or_else(|| prefix::count_address_bits(self.prefix))
    }

    fn validate(&self) -> Result<(), String> {
        let lengths = self.prefix.prefix_len()..=prefix::count_address_bits(self.prefix);
        if !lengths.contains(&self.min_length()) {
            return Err("min_prefix_length lies outside the prefix".into());
        }
        if self.max_prefixes == 0 {
            return Err("max_prefixes must be at least 1".into());
        }
        for e in &self.exclusions {
            if !self.prefix.contains(e) {
                return Err(format!("exclusion {e} lies outside the pool"));
            }
        }
        Ok(())
    }
}

/// Validates cross-interface constraints: distinct listen ports, distinct interface addresses, and
/// non-overlapping address pools.
fn validate_interfaces_apart(interfaces: &BTreeMap<String, Interface>) -> Result<(), String> {
    let mut ports = BTreeMap::new();
    for (name, i) in interfaces {
        if let Some(other) = ports.insert(i.listen_port, name) {
            return Err(format!(
                "interfaces {other} and {name} share listen_port {}",
                i.listen_port
            ));
        }
    }
    let mut hosts: Vec<(&str, ipnet::IpNet)> = Vec::new();
    let mut pools: Vec<(&str, ipnet::IpNet)> = Vec::new();
    for (name, i) in interfaces {
        for a in &i.addresses {
            let host = prefix::parse_interface_address(a).map_err(|e| e.to_string())?;
            if let Some((other, _)) = hosts.iter().find(|(_, h)| *h == host) {
                return Err(format!(
                    "interfaces {other} and {name} share address {host}"
                ));
            }
            hosts.push((name, host));
        }
        for p in &i.pools {
            let net = p.prefix;
            if let Some((other, o)) = pools.iter().find(|(_, o)| prefix::overlaps(*o, net)) {
                return Err(format!("pool {net} of {name} overlaps pool {o} of {other}"));
            }
            pools.push((name, net));
        }
    }
    Ok(())
}

// --- Identity providers (OIDC and SCIM) ---

/// OpenID Connect relying-party settings for browser sign-in.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(extend("required" = ["issuer", "client_id", "secret_file"]))]
pub struct Oidc {
    /// OpenID Connect issuer URL.
    #[schemars(url, example = &"https://id.example.com/realms/ito")]
    pub issuer: String,
    /// OAuth 2.0 client ID for browser sign-in.
    #[schemars(example = &"ito")]
    pub client_id: String,
    /// Absolute path to the file containing the OIDC client secret. Re-read on each use so secret
    /// rotation does not require a restart.
    #[schemars(example = &"/etc/ito/oidc.secret")]
    pub secret_file: PathBuf,
    /// Group names in the ID token's `groups` claim that grant administrator privileges for the
    /// session.
    #[schemars(example = ["ito-admins"])]
    pub admin_groups: Vec<String>,
}

impl Oidc {
    fn validate(&self) -> Result<(), String> {
        validate_http_url("oidc.issuer", &self.issuer)?;
        if self.client_id.is_empty() {
            return Err("oidc.client_id is required".into());
        }
        validate_absolute("oidc.secret_file", &self.secret_file)?;
        if self.admin_groups.iter().any(String::is_empty) {
            return Err("oidc.admin_groups must not contain empty names".into());
        }
        Ok(())
    }
}

/// Optional SCIM 2.0 user status polling. When configured, the controller checks user status at
/// sign-in and periodically on `interval`, revoking sessions and device keys when an account is
/// disabled or deleted at the identity provider.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(extend("required" = ["url", "client_id", "secret_file"]))]
pub struct Scim {
    /// Base URL of the SCIM 2.0 service.
    #[schemars(url, example = &"https://id.example.com/realms/ito/scim/v2")]
    pub url: String,
    /// OAuth 2.0 client ID used for client-credentials token requests to the SCIM API.
    #[schemars(example = &"ito-status")]
    pub client_id: String,
    /// Absolute path to the file containing the SCIM client secret.
    #[schemars(example = &"/etc/ito/status.secret")]
    pub secret_file: PathBuf,
    /// SCIM User ID of a canary account that remains permanently enabled. Before acting on a
    /// negative lookup result (disabled or 404), the controller verifies that this canary user is
    /// still reported as active, preventing upstream directory outages from mass-revoking accounts.
    #[schemars(example = &"00000000-0000-0000-0000-000000000000")]
    pub health_subject: String,
    /// Interval between background SCIM status sweeps across all accounts.
    #[serde(with = "duration")]
    #[schemars(with = "String")]
    pub interval: Duration,
}

impl Default for Scim {
    fn default() -> Self {
        Self {
            url: String::new(),
            client_id: String::new(),
            secret_file: PathBuf::new(),
            health_subject: String::new(),
            interval: Duration::from_hours(6),
        }
    }
}

impl Scim {
    fn validate(&self) -> Result<(), String> {
        validate_http_url("scim.url", &self.url)?;
        if self.client_id.is_empty() {
            return Err("scim.client_id is required".into());
        }
        validate_absolute("scim.secret_file", &self.secret_file)?;
        validate_lifetime("scim.interval", self.interval)
    }
}

// --- Authoritative DNS, quotas, and logging ---

/// Optional authoritative DNS server for interface `dns_zone` domains. Publishes `A` and `AAAA`
/// records at `<dns_name>.<dns_zone>` for each device that has a `dns_name`.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[schemars(extend("required" = ["name_server"]))]
pub struct Dns {
    /// UDP and TCP socket address for the authoritative DNS listener.
    pub listen: SocketAddr,
    /// Authoritative nameserver hostname placed in zone `NS` and `SOA` records. Must lie outside
    /// every configured `dns_zone` and resolve independently, because the server does not publish
    /// glue records.
    #[serde(deserialize_with = "deserialize_domain_name")]
    #[schemars(example = &"vpn.example.com")]
    pub name_server: String,
    /// Time to live in seconds for DNS records and negative caching responses.
    #[schemars(range(max = 2147483647))]
    pub ttl: u32,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            listen: "[::1]:53".parse().expect("static address"),
            name_server: String::new(),
            ttl: 60,
        }
    }
}

impl Dns {
    /// Validates the DNS server settings against the set of distinct interface `zones`, ensuring
    /// that `name_server` lies outside all zones and that no zone is a subdomain of another.
    fn validate(&self, zones: &std::collections::BTreeSet<&str>) -> Result<(), String> {
        let ns = &self.name_server;
        if !is_dns_domain(ns) {
            return Err("dns.name_server must be a domain".into());
        }
        let is_inside_zone =
            |name: &str, zone: &str| name == zone || name.ends_with(&format!(".{zone}"));
        for zone in zones {
            if is_inside_zone(ns, zone) {
                return Err(format!("dns.name_server must be outside the zone {zone}"));
            }
            if let Some(outer) = zones.iter().find(|o| *o != zone && is_inside_zone(zone, o)) {
                return Err(format!("the zone {zone} lies inside the zone {outer}"));
            }
        }
        // RFC 2181 limits TTL values to 2^31 - 1.
        if self.ttl > i32::MAX as u32 {
            return Err("dns.ttl must be at most 2147483647".into());
        }
        Ok(())
    }
}

/// Default per-account address limits. Each limit is a decimal address count (such as `"16"`), a
/// CIDR prefix length (such as `"/64"`), or `""` for unlimited. Administrators can override these
/// defaults on individual accounts.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct DefaultQuota {
    /// Default IPv4 address limit per account.
    pub ipv4: String,
    /// Default IPv6 address limit per account.
    pub ipv6: String,
}

impl Default for DefaultQuota {
    fn default() -> Self {
        Self {
            ipv4: "16".into(),
            ipv6: "/64".into(),
        }
    }
}

impl DefaultQuota {
    fn validate(&self) -> Result<(), String> {
        let quota = Quota {
            ipv4: self.ipv4.clone(),
            ipv6: self.ipv6.clone(),
        };
        crate::addressing::parse_limits(&quota)
            .map(drop)
            .map_err(|e| format!("quota: {}", e.detail.unwrap_or_default()))
    }
}

/// Logging configuration.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    /// Log filter directives in `tracing_subscriber::EnvFilter` syntax, such as `info` or
    /// `info,ito::reconcile=debug`.
    pub level: String,
    /// Whether to log every HTTP response at `info` level. Leave `false` when the reverse proxy
    /// already records access logs.
    pub requests: bool,
    /// Output format: `auto` (systemd journal when stderr is connected to journald, otherwise
    /// plain text on stderr), `text` (plain text on stderr), or `json` (newline-delimited JSON on
    /// stderr).
    pub format: LogFormat,
}

/// Log output format.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Native systemd journal when stderr is connected to journald, otherwise plain text.
    #[default]
    Auto,
    /// Plain text on stderr.
    Text,
    /// Newline-delimited JSON (JSONL) on stderr.
    Json,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: "info,hickory_server=warn".into(),
            requests: false,
            format: LogFormat::Auto,
        }
    }
}

impl Log {
    fn validate(&self) -> Result<(), String> {
        tracing_subscriber::EnvFilter::try_new(&self.level)
            .map(drop)
            .map_err(|e| format!("log.level: {e}"))
    }
}

// --- Validation and deserialization helpers ---

pub fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let config: Config = toml::from_str(&text).map_err(|e| format_parse_error(path, &text, &e))?;
    config.validate()?;
    Ok(config)
}

/// Formats a TOML parse error as `PATH:LINE:COLUMN: message` without quoting the source line.
fn format_parse_error(path: &Path, text: &str, e: &toml::de::Error) -> String {
    let at = e.span().map_or(String::new(), |span| {
        let before = &text[..span.start];
        let line = before.matches('\n').count() + 1;
        let column = before.chars().rev().take_while(|c| *c != '\n').count() + 1;
        format!(":{line}:{column}")
    });
    format!("{}{at}: {}", path.display(), e.message())
}

fn validate_absolute(name: &str, path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!("{name} must be an absolute path"));
    }
    Ok(())
}

fn validate_http_url(name: &str, url: &str) -> Result<(), String> {
    let url = Url::parse(url).map_err(|e| format!("{name}: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("{name} must be an http or https URL"));
    }
    Ok(())
}

/// Verifies that a duration is positive and can be added to the current UTC timestamp without
/// overflowing.
fn validate_lifetime(name: &str, d: Duration) -> Result<(), String> {
    let representable = chrono::Duration::from_std(d)
        .ok()
        .and_then(|d| chrono::Utc::now().checked_add_signed(d))
        .is_some();
    if d.is_zero() || !representable {
        return Err(format!(
            "{name} must be positive and representable as a date"
        ));
    }
    Ok(())
}

/// Deserializes a single canonical CIDR prefix.
fn deserialize_prefix<'de, D: serde::Deserializer<'de>>(d: D) -> Result<IpNet, D::Error> {
    let s = String::deserialize(d)?;
    prefix::parse_prefix(&s).map_err(|e| serde::de::Error::custom(e.detail.unwrap_or_default()))
}

/// Deserializes a list of canonical CIDR prefixes.
fn deserialize_prefixes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<IpNet>, D::Error> {
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|s| prefix::parse_prefix(s))
        .collect::<Result<_, _>>()
        .map_err(|e| serde::de::Error::custom(e.detail.unwrap_or_default()))
}

/// Deserializes a domain name in lowercase with any trailing dot removed.
fn deserialize_domain_name<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let name = String::deserialize(d)?;
    Ok(name.trim_end_matches('.').to_ascii_lowercase())
}

/// Reads and trims a secret file. Called on each use so secret rotation takes effect without
/// restarting the controller.
pub fn read_secret(path: &Path) -> Result<String, String> {
    let format_error = |reason: &str| format!("{}: {reason}", path.display());
    let text = std::fs::read_to_string(path).map_err(|e| format_error(&e.to_string()))?;
    let secret = text.trim();
    if secret.is_empty() {
        return Err(format_error("is empty"));
    }
    Ok(secret.into())
}

/// Serde adapter for durations written in `humantime` format (`90m`, `12h`, `30days`).
mod duration {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        humantime::parse_duration(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }

    /// Serializes a duration using the largest exact unit (`days`, `h`, or `m`).
    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        let secs = d.as_secs();
        let text = match () {
            _ if secs.is_multiple_of(86_400) && secs > 86_400 => format!("{}days", secs / 86_400),
            _ if secs.is_multiple_of(3_600) => format!("{}h", secs / 3_600),
            _ if secs.is_multiple_of(60) => format!("{}m", secs / 60),
            _ => humantime::format_duration(*d).to_string(),
        };
        s.serialize_str(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_sample_config() -> Config {
        toml::from_str(include_str!("../../../config.sample.toml")).unwrap()
    }

    fn change_wg0(c: &mut Config) -> &mut Interface {
        c.interfaces.get_mut("wg0").unwrap()
    }

    /// Adds `wg1`, a copy of `wg0` on its own port, address and pool.
    fn add_wg1(c: &mut Config) -> &mut Interface {
        let mut wg1 = c.interfaces["wg0"].clone();
        wg1.listen_port = 51821;
        wg1.addresses = vec!["10.1.0.1/24".into()];
        wg1.pools = vec![Pool {
            prefix: "10.1.0.0/24".parse().unwrap(),
            ..Pool::default()
        }];
        c.interfaces
            .entry("wg1".into())
            .insert_entry(wg1)
            .into_mut()
    }

    fn add_scim(c: &mut Config) -> &mut Scim {
        c.scim.insert(Scim {
            url: "https://id.example.com/scim/v2".into(),
            client_id: "status".into(),
            secret_file: "/etc/ito/status.secret".into(),
            ..Scim::default()
        })
    }

    /// Serves `wg0` in the zone `vpn.example.test` from the name server `ns.example.com`.
    fn add_zone(c: &mut Config) -> &mut Dns {
        change_wg0(c).dns_zone = "vpn.example.test".into();
        c.dns.insert(Dns {
            name_server: "ns.example.com".into(),
            ..Dns::default()
        })
    }

    fn add_profile(c: &mut Config, id: &str, name: &str, allowed_ips: &[&str]) {
        let wg0 = change_wg0(c);
        wg0.route_profiles.push(RouteProfile {
            id: id.into(),
            name: name.into(),
            allowed_ips: allowed_ips.iter().map(|p| p.to_string()).collect(),
        });
        wg0.default_profile_id = "all".into();
    }

    #[test]
    fn sample_configuration_is_valid() {
        parse_sample_config().validate().unwrap();
    }

    /// A change to the sample configuration.
    type Change = fn(&mut Config);

    #[test]
    fn invalid_configurations_are_refused() {
        let cases: &[(&str, &str, Change)] = &[
            ("uppercase host", "public_url", |c| {
                c.public_url = "https://VPN.example.com".into();
            }),
            ("default port", "public_url", |c| {
                c.public_url = "https://vpn.example.com:443".into();
            }),
            ("trailing slash", "public_url", |c| {
                c.public_url = "https://vpn.example.com/".into();
            }),
            (
                "relative database",
                "database must be an absolute path",
                |c| {
                    c.database = "ito.db".into();
                },
            ),
            (
                "no session lifetime",
                "session_lifetime must be positive",
                |c| {
                    c.session_lifetime = Duration::ZERO;
                },
            ),
            ("no idle time", "session_idle must be positive", |c| {
                c.session_idle = Duration::ZERO;
            }),
            (
                "endless key lifetime",
                "key_lifetime must be positive",
                |c| {
                    c.key_lifetime = Duration::MAX;
                },
            ),
            (
                "short key lifetime",
                "key_lifetime must be at least 4 days",
                |c| {
                    c.key_lifetime = Duration::from_hours(4 * 24 - 1);
                },
            ),
            (
                "idle beyond lifetime",
                "session_idle must not exceed",
                |c| {
                    c.session_idle = c.session_lifetime + Duration::from_secs(1);
                },
            ),
            ("issuer not a URL", "oidc.issuer:", |c| {
                c.oidc.issuer = "id.example.com".into();
            }),
            ("issuer not HTTP", "oidc.issuer must be an http", |c| {
                c.oidc.issuer = "ftp://id.example.com".into();
            }),
            ("no client ID", "oidc.client_id", |c| {
                c.oidc.client_id.clear()
            }),
            ("relative OIDC secret", "oidc.secret_file", |c| {
                c.oidc.secret_file = "oidc.secret".into();
            }),
            ("empty admin group", "oidc.admin_groups", |c| {
                c.oidc.admin_groups.push(String::new());
            }),
            ("SCIM not HTTP", "scim.url", |c| {
                add_scim(c).url = "ldap://id.example.com".into();
            }),
            ("no SCIM client", "scim.client_id", |c| {
                add_scim(c).client_id.clear();
            }),
            ("relative SCIM secret", "scim.secret_file", |c| {
                add_scim(c).secret_file = "status.secret".into();
            }),
            ("no SCIM interval", "scim.interval", |c| {
                add_scim(c).interval = Duration::ZERO;
            }),
            (
                "slash in an interface name",
                "interfaces.a/b must be named",
                |c| {
                    let wg0 = c.interfaces.remove("wg0").unwrap();
                    c.interfaces.insert("a/b".into(), wg0);
                },
            ),
            (
                "long interface name",
                "must be named as a Linux interface",
                |c| {
                    let wg0 = c.interfaces.remove("wg0").unwrap();
                    c.interfaces.insert("sixteen-letters0".into(), wg0);
                },
            ),
            (
                "relative private key",
                "interfaces.wg0.private_key_file",
                |c| {
                    change_wg0(c).private_key_file = "wg0.key".into();
                },
            ),
            ("listen port 0", "interfaces.wg0.listen_port", |c| {
                change_wg0(c).listen_port = 0;
            }),
            ("listen port 65536", "interfaces.wg0.listen_port", |c| {
                change_wg0(c).listen_port = 65536;
            }),
            ("endpoint without port", "interfaces.wg0.endpoint", |c| {
                change_wg0(c).endpoint = "vpn.example.com".into();
            }),
            ("address without subnet", "interfaces.wg0.addresses", |c| {
                change_wg0(c).addresses = vec!["10.0.0.1".into()];
            }),
            ("no MTU", "interfaces.wg0.mtu", |c| change_wg0(c).mtu = 0),
            ("negative client MTU", "interfaces.wg0.client_mtu", |c| {
                change_wg0(c).client_mtu = -1;
            }),
            ("negative keepalive", "interfaces.wg0.keepalive", |c| {
                change_wg0(c).keepalive = -1;
            }),
            ("keepalive 65536", "interfaces.wg0.keepalive", |c| {
                change_wg0(c).keepalive = 65536;
            }),
            ("DNS server not an address", "interfaces.wg0.dns", |c| {
                change_wg0(c).dns = vec!["dns.example.com".into()];
            }),
            (
                "search domain not a domain",
                "interfaces.wg0.dns_search",
                |c| {
                    change_wg0(c).dns_search = vec!["Example.com".into()];
                },
            ),
            ("zone not a domain", "interfaces.wg0.dns_zone", |c| {
                change_wg0(c).dns_zone = "-vpn.example.com".into();
            }),
            (
                "profile ID not a label",
                "interfaces.wg0.route_profiles",
                |c| {
                    add_profile(c, "All", "All", &[]);
                },
            ),
            (
                "repeated profile ID",
                "interfaces.wg0.route_profiles",
                |c| {
                    add_profile(c, "all", "All", &[]);
                    add_profile(c, "all", "Again", &[]);
                },
            ),
            ("unnamed profile", "interfaces.wg0.route_profiles", |c| {
                add_profile(c, "all", "", &[]);
            }),
            (
                "line break in a profile name",
                "interfaces.wg0.route_profiles",
                |c| {
                    add_profile(c, "all", "All\ntraffic", &[]);
                },
            ),
            (
                "non-canonical profile prefix",
                "interfaces.wg0.route_profiles",
                |c| {
                    add_profile(c, "all", "All", &["10.0.0.1/24"]);
                },
            ),
            (
                "default without profiles",
                "interfaces.wg0.default_profile_id",
                |c| {
                    change_wg0(c).default_profile_id = "all".into();
                },
            ),
            (
                "profiles without a default",
                "interfaces.wg0.default_profile_id",
                |c| {
                    add_profile(c, "all", "All", &[]);
                    change_wg0(c).default_profile_id.clear();
                },
            ),
            (
                "pool minimum outside the prefix",
                "min_prefix_length lies outside",
                |c| {
                    change_wg0(c).pools[0].min_prefix_length = Some(23);
                },
            ),
            (
                "no grants from a pool",
                "max_prefixes must be at least 1",
                |c| {
                    change_wg0(c).pools[0].max_prefixes = 0;
                },
            ),
            (
                "exclusion outside the pool",
                "exclusion 10.1.0.0/24 lies outside",
                |c| {
                    change_wg0(c).pools[0].exclusions = vec!["10.1.0.0/24".parse().unwrap()];
                },
            ),
            ("shared listen port", "share listen_port", |c| {
                add_wg1(c).listen_port = 51820;
            }),
            ("shared address", "share address 10.0.0.1/32", |c| {
                add_wg1(c).addresses = vec!["10.0.0.1/16".into()];
            }),
            ("overlapping pools", "overlaps pool", |c| {
                add_wg1(c).pools[0].prefix = "10.0.0.128/25".parse().unwrap();
            }),
            ("zone without DNS", "needs the [dns] section", |c| {
                change_wg0(c).dns_zone = "vpn.example.test".into();
            }),
            (
                "name server not a domain",
                "dns.name_server must be a domain",
                |c| {
                    add_zone(c).name_server = "NS".into();
                },
            ),
            (
                "name server inside the zone",
                "dns.name_server must be outside",
                |c| {
                    add_zone(c).name_server = "ns.vpn.example.test".into();
                },
            ),
            (
                "nested zones",
                "lies inside the zone vpn.example.test",
                |c| {
                    add_zone(c);
                    add_wg1(c).dns_zone = "sub.vpn.example.test".into();
                },
            ),
            ("TTL beyond 2^31 - 1", "dns.ttl", |c| {
                add_zone(c).ttl = u32::MAX
            }),
            ("IPv4 quota not a count", "quota: bad quota many", |c| {
                c.quota.ipv4 = "many".into();
            }),
            ("IPv6 quota beyond /128", "quota: bad quota /129", |c| {
                c.quota.ipv6 = "/129".into();
            }),
            ("bad log filter", "log.level", |c| {
                c.log.level = "info,=bogus=".into();
            }),
        ];
        for (case, expected, change) in cases {
            let mut c = parse_sample_config();
            change(&mut c);
            let error = c.validate().expect_err(case);
            assert!(error.contains(expected), "{case}: {error}");
        }
    }

    #[test]
    fn unparsable_configurations_are_refused() {
        let pool = "[oidc]\n[interfaces.wg0]\n[[interfaces.wg0.pools]]\n";
        for (case, text) in [
            ("unknown key", "surprise = true".to_string()),
            ("unknown duration", "session_idle = \"soon\"".into()),
            ("pool without prefix", pool.into()),
            (
                "host bits in a pool",
                format!("{pool}prefix = '10.0.0.1/24'"),
            ),
            ("uppercase pool", format!("{pool}prefix = 'FD00::/64'")),
            (
                "IPv4-mapped pool",
                format!("{pool}prefix = '::ffff:192.0.2.0/120'"),
            ),
            (
                "pool not a prefix",
                format!("{pool}prefix = 'not a prefix'"),
            ),
            (
                "host bits in an exclusion",
                format!("{pool}prefix = '10.0.0.0/24'\nexclusions = ['10.0.0.1/28']"),
            ),
        ] {
            assert!(toml::from_str::<Config>(&text).is_err(), "{case}");
        }
    }

    #[test]
    fn parse_errors_name_the_line_and_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "public_url = \"https://vpn.example.com\"\nsurprise = 1\n",
        )
        .unwrap();
        let error = load(&path).unwrap_err();
        assert!(
            error.starts_with(&format!("{}:2:1: ", path.display())),
            "{error}"
        );
    }

    #[test]
    fn loading_normalizes_names_and_fills_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let sample = include_str!("../../../config.sample.toml").replace(
            "[interfaces.wg0]\n",
            "[interfaces.wg0]\ndns_zone = \"VPN.Example.test.\"\n",
        );
        let text =
            format!("{sample}\n[dns]\nname_server = \"NS1.example.com\"\n[quota]\nipv4 = \"8\"\n");
        std::fs::write(&path, text).unwrap();
        let c = load(&path).unwrap();
        let zone = &c.interfaces["wg0"].dns_zone;
        let ns = &c.dns.as_ref().unwrap().name_server;
        assert_eq!(
            (zone.as_str(), ns.as_str()),
            ("vpn.example.test", "ns1.example.com")
        );
        assert_eq!((c.quota.ipv4.as_str(), c.quota.ipv6.as_str()), ("8", "/64"));
        assert_eq!(c.interfaces["wg0"].pools[0].max_prefixes, 1);
    }

    #[test]
    fn pools_without_a_minimum_grant_single_hosts() {
        for (prefix, bits) in [("10.0.0.0/24", 32), ("fd00::/64", 128)] {
            let pool: Pool = toml::from_str(&format!("prefix = {prefix:?}")).unwrap();
            assert_eq!(pool.min_length(), bits, "{prefix}");
        }
    }

    #[test]
    fn secret_files_are_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, " value\n").unwrap();
        assert_eq!(read_secret(&path).unwrap(), "value");
    }

    #[test]
    fn empty_secret_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "\n").unwrap();
        assert!(read_secret(&path).unwrap_err().ends_with("is empty"));
    }
}
