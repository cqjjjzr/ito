//! Platform-specific WireGuard tunnel lifecycle trait.

use crate::spec::TunnelSpec;
use ito_shared::dump::Link;
use std::fmt;

/// Error returned by a platform [`TunnelDriver`].
#[derive(Debug)]
pub struct TunnelError(pub String);

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Interface to the host's WireGuard implementation.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait TunnelDriver: Send + Sync {
    /// Brings up tunnel `name` with `spec`.
    async fn up(&self, name: &str, spec: &TunnelSpec) -> Result<(), TunnelError>;

    /// Takes tunnel `name` down if it is currently up.
    async fn down(&self, name: &str) -> Result<(), TunnelError>;

    /// Reconciles host-dependent settings (such as policy routing) for a running tunnel.
    async fn reconcile(&self, _name: &str, _spec: &TunnelSpec) -> Result<(), TunnelError> {
        Ok(())
    }

    /// Tears down tunnel `name` and deletes any platform configuration files for it.
    async fn remove(&self, name: &str) -> Result<(), TunnelError> {
        self.down(name).await
    }

    async fn is_up(&self, name: &str) -> Result<bool, TunnelError>;

    /// Reads the live WireGuard link state for `name`, returning `None` when the tunnel is down.
    async fn read(&self, name: &str) -> Result<Option<Link>, TunnelError>;

    /// Returns `true` if users can also start or stop tunnels through external tools (such as
    /// WireGuard for Windows), in which case periodic sync follows the tunnel's current state.
    fn follows_external_state(&self) -> bool {
        false
    }
}
