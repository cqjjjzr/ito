//! Trait abstracting WireGuard for Windows operations and a file-backed fake implementation.

use ito_agent_core::tunnel::TunnelError;
use std::{collections::BTreeSet, path::PathBuf, sync::Mutex};

/// Operations on the WireGuard for Windows configuration store and tunnel services.
#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait WireGuardDriver: Send + Sync {
    /// Writes the `wg-quick` configuration `text` for tunnel `name` into WireGuard's store.
    async fn write_config(&self, name: &str, text: &str) -> Result<(), TunnelError>;

    async fn delete_config(&self, name: &str) -> Result<(), TunnelError>;

    /// Installs and starts `WireGuardTunnel$<name>` from the stored configuration.
    async fn install(&self, name: &str) -> Result<(), TunnelError>;

    /// Stops and removes `WireGuardTunnel$<name>`.
    async fn uninstall(&self, name: &str) -> Result<(), TunnelError>;

    async fn is_running(&self, name: &str) -> Result<bool, TunnelError>;

    /// Returns the `wg show <name> dump` output for a running tunnel.
    async fn dump(&self, name: &str) -> Result<String, TunnelError>;
}

/// File-backed [`WireGuardDriver`] used by `console --fake` and the front-end socket test.
///
/// It stores configurations as files in `store` and keeps the set of running tunnels in memory, so
/// it simulates WireGuard for Windows on any host.
pub struct FakeWireGuard {
    store: PathBuf,
    running: Mutex<BTreeSet<String>>,
}

impl FakeWireGuard {
    pub fn new(store: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&store)?;
        Ok(Self {
            store,
            running: Mutex::default(),
        })
    }

    fn resolve_config_path(&self, name: &str) -> PathBuf {
        self.store.join(format!("{name}.conf"))
    }
}

fn build_tunnel_error(e: std::io::Error) -> TunnelError {
    TunnelError(e.to_string())
}

#[async_trait::async_trait]
impl WireGuardDriver for FakeWireGuard {
    async fn write_config(&self, name: &str, text: &str) -> Result<(), TunnelError> {
        std::fs::write(self.resolve_config_path(name), text).map_err(build_tunnel_error)
    }

    async fn delete_config(&self, name: &str) -> Result<(), TunnelError> {
        match std::fs::remove_file(self.resolve_config_path(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(build_tunnel_error(e)),
            _ => Ok(()),
        }
    }

    async fn install(&self, name: &str) -> Result<(), TunnelError> {
        if !self.resolve_config_path(name).exists() {
            return Err(TunnelError(format!("no stored configuration {name}")));
        }
        let mut running = self.running.lock().unwrap();
        if !running.insert(name.into()) {
            return Err(TunnelError("Tunnel already installed and running".into()));
        }
        Ok(())
    }

    async fn uninstall(&self, name: &str) -> Result<(), TunnelError> {
        self.running.lock().unwrap().remove(name);
        Ok(())
    }

    async fn is_running(&self, name: &str) -> Result<bool, TunnelError> {
        Ok(self.running.lock().unwrap().contains(name))
    }

    async fn dump(&self, name: &str) -> Result<String, TunnelError> {
        let text =
            std::fs::read_to_string(self.resolve_config_path(name)).map_err(build_tunnel_error)?;
        let read_field = |key: &str| {
            let prefix = format!("{key} = ");
            let line = text.lines().find_map(|l| l.strip_prefix(&prefix));
            line.unwrap_or("(none)").replace(", ", ",")
        };
        Ok(format!(
            "(hidden)\t(hidden)\t0\toff\n{}\t(hidden)\t{}\t{}\t0\t0\t0\toff\n",
            read_field("PublicKey"),
            read_field("Endpoint"),
            read_field("AllowedIPs"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG_TEXT: &str = "[Peer]\nPublicKey = SERVER=\nEndpoint = vpn.test:51820\n\
                               AllowedIPs = 10.0.0.0/24, fd00::/64\n";

    /// Creates a fake on a new directory with the config of `ito-a` stored.
    async fn create_fake_with_ito_a() -> (tempfile::TempDir, FakeWireGuard) {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeWireGuard::new(dir.path().into()).unwrap();
        fake.write_config("ito-a", CONFIG_TEXT).await.unwrap();
        (dir, fake)
    }

    #[tokio::test]
    async fn the_fake_installs_only_stored_configs() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeWireGuard::new(dir.path().into()).unwrap();
        assert!(fake.install("ito-a").await.is_err());
        fake.write_config("ito-a", CONFIG_TEXT).await.unwrap();
        fake.install("ito-a").await.unwrap();
        assert!(fake.is_running("ito-a").await.unwrap());
    }

    #[tokio::test]
    async fn the_fake_refuses_to_install_a_running_tunnel_again() {
        let (_dir, fake) = create_fake_with_ito_a().await;
        fake.install("ito-a").await.unwrap();
        assert!(fake.install("ito-a").await.is_err());
    }

    #[tokio::test]
    async fn the_fake_dumps_the_stored_peer() {
        let (_dir, fake) = create_fake_with_ito_a().await;
        let link = ito_shared::dump::parse_dump(&fake.dump("ito-a").await.unwrap()).unwrap();
        assert_eq!(link.peers[0].public_key, "SERVER=");
        assert_eq!(link.peers[0].endpoint, "vpn.test:51820");
        assert_eq!(link.peers[0].allowed_ips, ["10.0.0.0/24", "fd00::/64"]);
    }

    #[tokio::test]
    async fn uninstalled_fake_tunnels_stop_running() {
        let (_dir, fake) = create_fake_with_ito_a().await;
        fake.install("ito-a").await.unwrap();
        fake.uninstall("ito-a").await.unwrap();
        assert!(!fake.is_running("ito-a").await.unwrap());
    }

    #[tokio::test]
    async fn the_fake_deletes_stored_configs() {
        let (_dir, fake) = create_fake_with_ito_a().await;
        fake.delete_config("ito-a").await.unwrap();
        assert!(fake.install("ito-a").await.is_err());
    }
}
