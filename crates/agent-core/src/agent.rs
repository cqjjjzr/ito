//! Platform-agnostic operations for managing saved VPN connections and synchronizing tunnels.

use crate::{
    client::{Client, ClientError, DeviceInfo},
    login::{Login, LoginTicket},
    naming::derive_tunnel_name,
    spec::TunnelSpec,
    state::{CachedConfig, ConnectionState, SavedConnection, StateDir},
    tunnel::{TunnelDriver, TunnelError},
};
use chrono::Utc;
use ito_shared::{
    api::{DeviceStatus, DisabledReason, RouteProfile},
    dump::Link,
    keys::generate_key_pair,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, io, time::Duration};
use tokio::sync::Mutex;

/// Window before key expiry during which the agent automatically renews the device key.
const RENEW_BEFORE: chrono::TimeDelta = chrono::TimeDelta::days(3);
/// Timeout when revoking the agent credential during logout.
const REVOKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Polling interval while waiting for user approval during login.
pub const CLAIM_INTERVAL: Duration = Duration::from_secs(5);
/// Maximum duration to wait for login approval, matching the portal's request TTL.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);

// --- Errors and connection summaries ---

#[derive(Debug)]
pub enum AgentError {
    /// No connection exists with the given name.
    Unknown(String),
    /// The request itself is malformed, such as an unknown route profile or a bad prefix.
    Invalid(String),
    /// The request is well formed, but the agent will not carry it out as things are, such as a
    /// connection whose routes another connected tunnel already uses, or an expired login.
    Refused(String),
    Client(ClientError),
    Tunnel(TunnelError),
    State(io::Error),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(name) => write!(f, "no connection named {name}"),
            Self::Invalid(message) | Self::Refused(message) => f.write_str(message),
            Self::Client(e) => e.fmt(f),
            Self::Tunnel(e) => write!(f, "WireGuard: {e}"),
            Self::State(e) => write!(f, "saved connections: {e}"),
        }
    }
}

impl From<ClientError> for AgentError {
    fn from(e: ClientError) -> Self {
        Self::Client(e)
    }
}

impl From<TunnelError> for AgentError {
    fn from(e: TunnelError) -> Self {
        Self::Tunnel(e)
    }
}

impl From<io::Error> for AgentError {
    fn from(e: io::Error) -> Self {
        Self::State(e)
    }
}

pub type Result<T, E = AgentError> = std::result::Result<T, E>;

/// Summary of a saved connection returned to CLI and tray clients.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionSummary {
    pub name: String,
    pub portal: String,
    pub device: DeviceInfo,
    pub state: ConnectionState,
    pub no_dns: bool,
    pub revoked: bool,
    /// Active server route profile ID, or `None` when using `custom_allowed_ips`.
    pub profile_id: Option<String>,
    pub profiles: Vec<RouteProfile>,
    /// Saved local `AllowedIPs` override; active when `profile_id` is `None`.
    #[serde(default)]
    pub custom_allowed_ips: Option<Vec<String>>,
    /// Reason the controller currently blocks this device from connecting.
    pub disabled_reason: Option<DisabledReason>,
    pub last_error: Option<String>,
}

/// Combined local and server tunnel status for a connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub summary: ConnectionSummary,
    /// Local WireGuard link state, or `None` when the tunnel is down.
    pub local: Option<Link>,
    /// Peer state reported by the controller.
    pub server: Option<DeviceStatus>,
    /// Error encountered when querying the controller's status endpoint.
    pub server_error: Option<String>,
}

impl ConnectionSummary {
    /// Formats a human-readable state description for CLI and tray displays.
    pub fn describe_state(&self) -> String {
        if self.revoked {
            "Revoked: log in again through the portal".into()
        } else if self.state == ConnectionState::Disconnected {
            "Disconnected".into()
        } else if self.state == ConnectionState::Disconnecting {
            "Error: retrying disconnection".into()
        } else if self.state == ConnectionState::Errored {
            "Error: retrying connection".into()
        } else if let Some(reason) = self.disabled_reason {
            format!("Connected, but disabled by controller: {reason}")
        } else {
            "Connected".into()
        }
    }
}

fn build_connection_summary(c: &SavedConnection) -> ConnectionSummary {
    let config = c.config.as_ref().map(|x| &x.config);
    let profiles = config.map(|x| x.route_profiles.clone()).unwrap_or_default();
    let chosen = c.profile_id.clone();
    let profile_id = chosen
        .filter(|id| config.is_none() || profiles.iter().any(|p| &p.id == id))
        .or_else(|| {
            config
                .filter(|_| c.profile_id.is_some() || c.custom_allowed_ips.is_none())
                .map(|x| x.default_profile_id.clone())
        });
    ConnectionSummary {
        name: c.name.clone(),
        portal: c.portal.clone(),
        device: c.device.clone(),
        state: c.state,
        no_dns: c.no_dns,
        revoked: c.revoked,
        profile_id,
        profiles,
        custom_allowed_ips: c.custom_allowed_ips.clone(),
        disabled_reason: config.and_then(|x| x.disabled_reason),
        last_error: c.last_error.clone(),
    }
}

/// Approved login claim containing the pending login state, bearer token, and device metadata.
pub struct ClaimedLogin {
    login: Login,
    token: String,
    device: DeviceInfo,
}

/// Result of completing a login and installing the connection on this host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginOutcome {
    pub summary: ConnectionSummary,
    /// `true` if the device was already saved on this host and its credentials were updated in
    /// place.
    pub reauthenticated: bool,
    /// Other connections on this host that belong to the same portal.
    pub others: Vec<ConnectionSummary>,
    /// Name of an already-connected tunnel with an identical route prefix that prevented
    /// auto-connect.
    pub overlap: Option<String>,
}

/// Builds the desired [`TunnelSpec`] for `c` once its cached configuration is available.
fn build_spec(c: &SavedConnection) -> Option<TunnelSpec> {
    let config = &c.config.as_ref()?.config;
    let mut spec = TunnelSpec::build(config, &c.private_key, c.profile_id.as_deref());
    if c.profile_id.is_none()
        && let Some(routes) = &c.custom_allowed_ips
    {
        spec.peer.allowed_ips = routes.clone();
    }
    if c.no_dns {
        spec.dns.clear();
        spec.dns_search.clear();
    }
    Some(spec)
}

// --- Agent state and login flow ---

/// Coordinates saved connections and the platform [`TunnelDriver`].
///
/// Mutating operations acquire an internal mutex so tunnel and state updates run sequentially.
pub struct Agent<T> {
    state: StateDir,
    tunnel: T,
    lock: Mutex<()>,
    /// Pending logins indexed by request ID.
    logins: std::sync::Mutex<HashMap<String, Login>>,
}

impl<T: TunnelDriver> Agent<T> {
    pub fn new(state: StateDir, tunnel: T) -> Self {
        Self {
            state,
            tunnel,
            lock: Mutex::new(()),
            logins: std::sync::Mutex::default(),
        }
    }

    fn load(&self, name: &str) -> Result<SavedConnection> {
        self.state
            .load(name)?
            .ok_or_else(|| AgentError::Unknown(name.into()))
    }

    pub async fn list(&self) -> Result<Vec<ConnectionSummary>> {
        Ok(self
            .state
            .load_all()?
            .connections
            .iter()
            .map(build_connection_summary)
            .collect())
    }

    /// Starts a login flow for `portal` and returns the [`LoginTicket`] containing the approval
    /// URL.
    pub fn begin_login(
        &self,
        portal: &str,
        device: Option<&str>,
        host_name: &str,
        no_dns: bool,
    ) -> LoginTicket {
        let mut login = Login::start(portal, device, host_name);
        login.no_dns = no_dns;
        let ticket = login.ticket.clone();
        let mut logins = self.logins.lock().expect("logins lock");
        logins.insert(ticket.request.clone(), login);
        ticket
    }

    /// Polls the controller every `interval` until the login `request` is approved and claimed.
    ///
    /// Does not hold the agent mutex while polling so background synchronization can continue.
    pub async fn await_claim(&self, request: &str, interval: Duration) -> Result<ClaimedLogin> {
        let login = self.logins.lock().expect("logins lock").remove(request);
        let login = login.ok_or_else(|| AgentError::Refused(format!("no login {request}")))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(login.ticket.requested_at) >= LOGIN_TIMEOUT.as_secs() {
            return Err(AgentError::Refused("login expired: start again".into()));
        }
        let client = Client::new(&login.portal, "")?;
        let deadline = tokio::time::Instant::now()
            + LOGIN_TIMEOUT.saturating_sub(Duration::from_secs(
                now.saturating_sub(login.ticket.requested_at),
            ));
        loop {
            let device = login.device.as_deref();
            match client
                .claim(&login.secret, &login.keys.public, device)
                .await
            {
                Ok(Some((token, device))) => {
                    return Ok(ClaimedLogin {
                        login,
                        token,
                        device,
                    });
                }
                Ok(None) => {}
                // Ignore transient network errors or 502/503 responses while polling.
                Err(
                    ClientError::Network(_)
                    | ClientError::Problem {
                        status: 502 | 503, ..
                    },
                ) => {}
                Err(e) => return Err(e.into()),
            }
            if tokio::time::Instant::now() + interval > deadline {
                let message = "nobody approved the login in time: start again".into();
                return Err(AgentError::Refused(message));
            }
            tokio::time::sleep(interval).await;
        }
    }

    /// Saves a claimed login as a local connection and optionally brings the tunnel up.
    ///
    /// If the claimed device is already saved locally, updates its credentials and keys in place.
    pub async fn install_claim(
        &self,
        claimed: ClaimedLogin,
        connect: bool,
    ) -> Result<LoginOutcome> {
        let _guard = self.lock.lock().await;
        let ClaimedLogin {
            login,
            token,
            device,
        } = claimed;
        let all = self.state.load_all()?.connections;
        let existing = all.iter().find(|c| c.device.id == device.id).cloned();
        let reauthenticated = existing.is_some();
        let c = match existing {
            Some(mut c) => {
                c.portal = login.portal.clone();
                c.token = token;
                c.device = device;
                c.private_key = login.keys.private;
                c.revoked = false;
                c.no_dns |= login.no_dns;
                // Keep the cached config as an offline fallback; its ETag will mismatch on the next
                // fetch.
                c
            }
            None => {
                let taken: Vec<String> = all.iter().map(|c| c.name.clone()).collect();
                SavedConnection {
                    name: derive_tunnel_name(&device.id, &taken),
                    portal: login.portal.clone(),
                    token,
                    device,
                    private_key: login.keys.private,
                    profile_id: None,
                    custom_allowed_ips: None,
                    state: ConnectionState::Disconnected,
                    no_dns: login.no_dns,
                    config: None,
                    applied: None,
                    revoked: false,
                    last_error: None,
                }
            }
        };
        // Persist immediately because the controller already holds the new public key.
        self.state.save(&c)?;
        let mut summary = self.sync_and_save(c).await?;
        let mut overlap = None;
        if connect && !reauthenticated {
            let mut c = self.load(&summary.name)?;
            overlap = self.find_overlap(&c).await?;
            if overlap.is_none() {
                c.state = ConnectionState::Connected;
                summary = self.sync_and_save(c).await?;
            }
        }
        let others = all
            .iter()
            .filter(|o| o.portal == login.portal && o.name != summary.name)
            .map(build_connection_summary)
            .collect();
        Ok(LoginOutcome {
            summary,
            reauthenticated,
            others,
            overlap,
        })
    }

    /// Waits for `request` to be approved and installs the resulting claim.
    pub async fn finish_login(&self, request: &str, connect: bool) -> Result<LoginOutcome> {
        let claimed = self.await_claim(request, CLAIM_INTERVAL).await?;
        self.install_claim(claimed, connect).await
    }

    /// Periodically purges pending login tickets older than `LOGIN_TIMEOUT`.
    pub async fn expire_logins(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.logins.lock().expect("logins lock").retain(|_, login| {
                now.saturating_sub(login.ticket.requested_at) < LOGIN_TIMEOUT.as_secs()
            });
        }
    }

    // --- Tunnel lifecycle and synchronization ---

    /// Brings the connection's tunnel up unless another connected tunnel uses an identical route
    /// prefix.
    pub async fn connect(&self, name: &str) -> Result<ConnectionSummary> {
        let _guard = self.lock.lock().await;
        let mut c = self.load(name)?;
        if let Some(other) = self.find_overlap(&c).await? {
            let message =
                format!("an identical route prefix is used by {other}, which is connected");
            return Err(AgentError::Refused(message));
        }
        c.state = ConnectionState::Connected;
        self.sync_and_save(c).await
    }

    /// Checks whether another active connection has an identical route prefix.
    async fn find_overlap(&self, c: &SavedConnection) -> Result<Option<String>> {
        let Some(spec) = build_spec(c) else {
            return Ok(None);
        };
        let loaded = self.state.load_all()?;
        for (name, error) in &loaded.errors {
            if name != &c.name && self.tunnel.is_up(name).await? {
                return Err(AgentError::Refused(format!(
                    "cannot check routes of running {name}: {error}"
                )));
            }
        }
        for other in loaded
            .connections
            .into_iter()
            .filter(|o| o.name != c.name && o.state.wants_connection() && !o.revoked)
        {
            let routes = other.applied.clone().or_else(|| build_spec(&other));
            if routes.is_some_and(|routes| routes.overlaps(&spec))
                && (other.state != ConnectionState::Errored
                    || self.tunnel.is_up(&other.name).await?)
            {
                return Ok(Some(other.name));
            }
        }
        Ok(None)
    }

    pub async fn disconnect(&self, name: &str) -> Result<ConnectionSummary> {
        let _guard = self.lock.lock().await;
        let mut c = self.load(name)?;
        c.state = ConnectionState::Disconnecting;
        self.sync_and_save(c).await
    }

    /// Tears down the tunnel, attempts to revoke the device (its agent credential and key) on the
    /// controller, and deletes the saved connection.
    pub async fn logout(&self, name: &str) -> Result<bool> {
        let _guard = self.lock.lock().await;
        let c = self.load(name)?;
        self.tunnel.remove(&c.name).await?;
        let revoked = match Client::new(&c.portal, &c.token) {
            Ok(client) => matches!(
                tokio::time::timeout(REVOKE_TIMEOUT, client.revoke()).await,
                Ok(Ok(()) | Err(ClientError::Revoked))
            ),
            Err(_) => false,
        };
        self.state.remove(&c.name)?;
        Ok(revoked)
    }

    // --- Route profiles, DNS, and key rotation ---

    /// Generates a new WireGuard key pair locally and uploads the public key to the controller.
    pub async fn rotate_key(&self, name: &str) -> Result<ConnectionSummary> {
        let _guard = self.lock.lock().await;
        let mut c = self.load(name)?;
        let client = Client::new(&c.portal, &c.token)?;
        let revision = client.fetch_device().await?.revision;
        let keys = generate_key_pair();
        c.device = client.set_key(revision, Some(&keys.public)).await?;
        c.private_key = keys.private;
        // Persist immediately because the controller already holds the new public key.
        self.state.save(&c)?;
        self.sync_and_save(c).await
    }

    /// Requests that the controller generate a new preshared key for the device.
    pub async fn rotate_psk(&self, name: &str) -> Result<ConnectionSummary> {
        let _guard = self.lock.lock().await;
        let mut c = self.load(name)?;
        let client = Client::new(&c.portal, &c.token)?;
        let revision = client.fetch_device().await?.revision;
        c.device = client.generate_psk(revision).await?;
        self.sync_and_save(c).await
    }

    /// Selects a server route profile or sets a custom local `AllowedIPs` override.
    ///
    /// Selecting a server profile preserves any saved `custom_allowed_ips` so UIs can re-select it
    /// later.
    pub async fn set_profile(
        &self,
        name: &str,
        profile: Option<&str>,
        allowed_ips: Option<Vec<String>>,
    ) -> Result<ConnectionSummary> {
        let _guard = self.lock.lock().await;
        let mut c = self.load(name)?;
        match (profile, allowed_ips) {
            (Some(profile), None) => {
                let profiles = c.config.as_ref().map(|x| &x.config.route_profiles);
                if !profiles.is_some_and(|all| all.iter().any(|p| p.id == profile)) {
                    return Err(AgentError::Invalid(format!(
                        "no route profile named {profile}"
                    )));
                }
                c.profile_id = Some(profile.into());
            }
            (None, Some(routes)) => {
                let mut parsed = Vec::new();
                for route in routes {
                    let prefix: ipnet::IpNet = route.parse().map_err(|_| {
                        AgentError::Invalid(format!("invalid AllowedIPs prefix: {route:?}"))
                    })?;
                    parsed.push(prefix.trunc().to_string());
                }
                parsed.sort();
                parsed.dedup();
                c.custom_allowed_ips = Some(parsed);
                c.profile_id = None;
            }
            _ => {
                return Err(AgentError::Invalid(
                    "send exactly one of profile or allowed_ips".into(),
                ));
            }
        }
        if c.state.wants_connection()
            && let Some(other) = self.find_overlap(&c).await?
        {
            return Err(AgentError::Refused(format!(
                "an identical route prefix is used by {other}, which is connected"
            )));
        }
        self.sync_and_save(c).await
    }

    pub async fn set_dns(&self, name: &str, enabled: bool) -> Result<ConnectionSummary> {
        let _guard = self.lock.lock().await;
        let mut c = self.load(name)?;
        c.no_dns = !enabled;
        self.sync_and_save(c).await
    }

    /// Returns the combined local and server status for connection `name`.
    pub async fn status(&self, name: &str) -> Result<ConnectionStatus> {
        let c = self.load(name)?;
        let local = self.tunnel.read(&c.name).await?;
        let server = match Client::new(&c.portal, &c.token) {
            Ok(client) => client.fetch_status().await,
            Err(e) => Err(e),
        };
        Ok(ConnectionStatus {
            summary: build_connection_summary(&c),
            local,
            server_error: server.as_ref().err().map(ToString::to_string),
            server: server.ok(),
        })
    }

    /// Synchronizes all saved connections with the controller and local WireGuard driver.
    pub async fn sync_all(&self) -> Result<()> {
        let _guard = self.lock.lock().await;
        let follow_external = self.tunnel.follows_external_state();
        let loaded = self.state.load_all()?;
        for c in loaded.connections {
            let (c, _) = self.sync(c, follow_external).await;
            self.state.save(&c)?;
        }
        if !loaded.errors.is_empty() {
            let unreadable: Vec<String> = loaded.errors.into_iter().map(|(_, e)| e).collect();
            return Err(AgentError::State(io::Error::new(
                io::ErrorKind::InvalidData,
                unreadable.join("; "),
            )));
        }
        Ok(())
    }

    /// Synchronizes `c` and saves its updated state.
    ///
    /// Tunnel errors fail the operation, whereas controller network errors fall back to cached
    /// config.
    async fn sync_and_save(&self, c: SavedConnection) -> Result<ConnectionSummary> {
        let (c, failure) = self.sync(c, false).await;
        self.state.save(&c)?;
        match failure {
            Some(e) => Err(e),
            None => Ok(build_connection_summary(&c)),
        }
    }

    /// Refreshes device config from the controller, renews expiring keys, and reconciles the local
    /// tunnel.
    ///
    /// When `follow_external` is `true`, updates `c.state` to match external tunnel activation or
    /// deactivation.
    async fn sync(
        &self,
        mut c: SavedConnection,
        follow_external: bool,
    ) -> (SavedConnection, Option<AgentError>) {
        let refreshed = self.refresh(&mut c).await;
        match &refreshed {
            Ok(()) => c.revoked = false,
            Err(AgentError::Client(ClientError::Revoked)) => c.revoked = true,
            // Fall back to cached config when the controller is unreachable.
            Err(_) => {}
        }
        let applied = self.apply(&mut c, follow_external).await.err();
        if applied.is_some() && c.state.wants_connection() {
            c.state = ConnectionState::Errored;
        }
        let refresh_error = refreshed.err().filter(|_| !c.revoked);
        c.last_error = applied
            .as_ref()
            .map(ToString::to_string)
            .or(refresh_error.map(|e| e.to_string()));
        (c, applied)
    }

    async fn refresh(&self, c: &mut SavedConnection) -> Result<()> {
        let client = Client::new(&c.portal, &c.token)?;
        let etag = c.config.as_ref().map(|x| x.etag.as_str());
        if let Some((config, etag)) = client.fetch_config(etag).await? {
            c.device = client.fetch_device().await?;
            c.config = Some(CachedConfig { etag, config });
        }
        let expiry = c.config.as_ref().and_then(|x| x.config.key_expires_at);
        if expiry.is_some_and(|t| t - Utc::now() < RENEW_BEFORE) {
            c.device = client.set_key(c.device.revision, None).await?;
        }
        Ok(())
    }

    async fn apply(&self, c: &mut SavedConnection, follow_external: bool) -> Result<()> {
        let up = self.tunnel.is_up(&c.name).await?;
        if follow_external
            && !matches!(
                c.state,
                ConnectionState::Errored | ConnectionState::Disconnecting
            )
        {
            c.state = if up {
                ConnectionState::Connected
            } else {
                ConnectionState::Disconnected
            };
        }
        let wanted = c.state.wants_connection() && !c.revoked;
        match build_spec(c) {
            Some(spec) if wanted => {
                if let Some(other) = self.find_overlap(c).await? {
                    if up {
                        self.tunnel.down(&c.name).await?;
                    }
                    c.state = ConnectionState::Errored;
                    c.applied = None;
                    return Err(AgentError::Refused(format!(
                        "an identical route prefix is used by {other}, which is connected"
                    )));
                }
                if up && c.applied.as_ref() == Some(&spec) {
                    self.tunnel.reconcile(&c.name, &spec).await?;
                    c.state = ConnectionState::Connected;
                    return Ok(());
                }
                if up {
                    self.tunnel.down(&c.name).await?;
                }
                self.tunnel.up(&c.name, &spec).await?;
                c.applied = Some(spec.clone());
                self.tunnel.reconcile(&c.name, &spec).await?;
                c.state = ConnectionState::Connected;
            }
            _ if !wanted => {
                if up {
                    self.tunnel.down(&c.name).await?;
                }
                c.applied = None;
                c.state = ConnectionState::Disconnected;
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
