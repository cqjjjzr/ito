//! [`TunnelDriver`] implementation backed by a Windows [`WireGuardDriver`].

use crate::wireguard::WireGuardDriver;
use ito_agent_core::{
    spec::TunnelSpec,
    tunnel::{TunnelDriver, TunnelError},
    wg_quick,
};
use ito_shared::dump::{Link, parse_dump};

/// Manages tunnels through WireGuard for Windows (`WireGuardTunnel$<name>` services).
///
/// Follows external state changes so starting or stopping a tunnel inside the WireGuard GUI is
/// preserved by periodic synchronization.
pub struct WindowsTunnel<W> {
    wireguard: W,
}

impl<W: WireGuardDriver> WindowsTunnel<W> {
    pub fn new(wireguard: W) -> Self {
        Self { wireguard }
    }
}

#[async_trait::async_trait]
impl<W: WireGuardDriver> TunnelDriver for WindowsTunnel<W> {
    async fn up(&self, name: &str, spec: &TunnelSpec) -> Result<(), TunnelError> {
        self.wireguard
            .write_config(name, &wg_quick::render_config(spec))
            .await?;
        self.wireguard.install(name).await
    }

    async fn down(&self, name: &str) -> Result<(), TunnelError> {
        if self.wireguard.is_running(name).await? {
            self.wireguard.uninstall(name).await?;
        }
        Ok(())
    }

    async fn remove(&self, name: &str) -> Result<(), TunnelError> {
        self.down(name).await?;
        self.wireguard.delete_config(name).await
    }

    async fn is_up(&self, name: &str) -> Result<bool, TunnelError> {
        self.wireguard.is_running(name).await
    }

    async fn read(&self, name: &str) -> Result<Option<Link>, TunnelError> {
        if !self.wireguard.is_running(name).await? {
            return Ok(None);
        }
        let dump = self.wireguard.dump(name).await?;
        let link = parse_dump(&dump).map_err(|_| TunnelError("unexpected wg.exe output".into()))?;
        Ok(Some(Link { up: true, ..link }))
    }

    fn follows_external_state(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::MockWireGuardDriver;
    use ito_agent_core::spec::PeerSpec;
    use mockall::Sequence;

    fn build_sample_spec() -> TunnelSpec {
        TunnelSpec {
            private_key: "KEY=".into(),
            addresses: vec!["10.0.0.2/32".into()],
            dns: vec![],
            dns_search: vec![],
            mtu: 0,
            peer: PeerSpec {
                public_key: "SERVER=".into(),
                preshared_key: String::new(),
                endpoint: "vpn.test:51820".into(),
                allowed_ips: vec!["10.0.0.0/24".into()],
                keepalive: 0,
            },
        }
    }

    #[tokio::test]
    async fn tunnels_are_stored_then_installed() {
        let mut wireguard = MockWireGuardDriver::new();
        let mut order = Sequence::new();
        wireguard
            .expect_write_config()
            .withf(|name, text| name == "ito-a" && text.contains("AllowedIPs = 10.0.0.0/24\n"))
            .times(1)
            .in_sequence(&mut order)
            .returning(|_, _| Ok(()));
        wireguard
            .expect_install()
            .times(1)
            .in_sequence(&mut order)
            .returning(|_| Ok(()));
        let tunnel = WindowsTunnel::new(wireguard);
        tunnel.up("ito-a", &build_sample_spec()).await.unwrap();
    }

    #[tokio::test]
    async fn only_running_tunnels_are_uninstalled() {
        for running in [false, true] {
            let mut wireguard = MockWireGuardDriver::new();
            wireguard
                .expect_is_running()
                .returning(move |_| Ok(running));
            wireguard
                .expect_uninstall()
                .times(usize::from(running))
                .returning(|_| Ok(()));
            let tunnel = WindowsTunnel::new(wireguard);
            tunnel.down("ito-a").await.unwrap();
        }
    }

    #[tokio::test]
    async fn removing_a_tunnel_uninstalls_it_then_deletes_its_config() {
        let mut wireguard = MockWireGuardDriver::new();
        let mut order = Sequence::new();
        wireguard.expect_is_running().returning(move |_| Ok(true));
        wireguard
            .expect_uninstall()
            .times(1)
            .in_sequence(&mut order)
            .returning(|_| Ok(()));
        wireguard
            .expect_delete_config()
            .times(1)
            .in_sequence(&mut order)
            .returning(|_| Ok(()));
        WindowsTunnel::new(wireguard).remove("ito-a").await.unwrap();
    }

    #[tokio::test]
    async fn running_tunnels_read_from_their_dump() {
        let mut wireguard = MockWireGuardDriver::new();
        wireguard.expect_is_running().returning(move |_| Ok(true));
        wireguard.expect_dump().returning(|_| {
            Ok("(hidden)\tpub\t0\toff\nSERVER=\t(hidden)\t1.2.3.4:51820\t10.0.0.0/24\t1700000000\t5\t6\toff\n".into())
        });
        let link = WindowsTunnel::new(wireguard)
            .read("ito-a")
            .await
            .unwrap()
            .unwrap();
        assert!(link.up);
        assert_eq!(link.peers[0].endpoint, "1.2.3.4:51820");
        assert_eq!(link.peers[0].transmit_bytes, 6);
    }

    #[tokio::test]
    async fn stopped_tunnels_read_as_absent() {
        let mut wireguard = MockWireGuardDriver::new();
        wireguard.expect_is_running().returning(move |_| Ok(false));
        let link = WindowsTunnel::new(wireguard).read("ito-a").await.unwrap();
        assert_eq!(link, None);
    }

    #[test]
    fn tunnels_follow_changes_made_in_wireguard_for_windows() {
        let tunnel = WindowsTunnel::new(MockWireGuardDriver::new());
        assert!(tunnel.follows_external_state());
    }
}
