pub mod accounts;
pub mod addressing;
pub mod approvals;
pub mod config;
pub mod db;
pub mod devices;
pub mod dns;
pub mod error;
pub mod http;
pub mod identity;
pub mod kernel;
pub mod logging;
pub mod reconcile;
pub mod wireguard_keys;

use db::Db;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

pub struct App {
    pub config: config::Config,
    pub db: Db,
    pub kernel: Arc<dyn kernel::KernelDriver>,
    pub http_client: reqwest::Client,
    pub identity_cache: identity::IdentityCache,
    pub server_keys: wireguard_keys::ServerKeyByInterface,
    /// Latest reconciliation status for each configured interface, keyed by interface name.
    pub interface_status: Mutex<BTreeMap<String, InterfaceStatus>>,
    /// Wakes the SCIM user status sweep immediately when notified.
    pub sweep_notify: tokio::sync::Notify,
    /// In-memory store of approved agent login requests.
    pub approvals: approvals::AgentApprovals,
}

/// Reconciliation outcome for a single WireGuard interface.
#[derive(Clone, Debug, Default)]
pub struct InterfaceStatus {
    /// Whether the configured interface state has been applied to and verified in the kernel.
    pub applied: bool,
    /// Error from the latest reconciliation pass, or empty when applied.
    pub apply_error: String,
}

impl App {
    /// Initializes shared application state and loads server private keys for all interfaces.
    pub fn new(
        config: config::Config,
        db: Db,
        kernel: Arc<dyn kernel::KernelDriver>,
    ) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            server_keys: wireguard_keys::ServerKeyByInterface::read(&config)?,
            config,
            db,
            kernel,
            http_client: identity::oidc::build_http_client(),
            identity_cache: identity::IdentityCache::default(),
            interface_status: Mutex::default(),
            sweep_notify: tokio::sync::Notify::default(),
            approvals: approvals::AgentApprovals::default(),
        }))
    }

    /// Returns the latest reconciliation status for interface `name`.
    pub fn interface_status(&self, name: &str) -> InterfaceStatus {
        let all = self.interface_status.lock().expect("status lock");
        all.get(name).cloned().unwrap_or_default()
    }
}
