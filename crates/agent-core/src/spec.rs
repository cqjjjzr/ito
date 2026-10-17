//! Desired WireGuard tunnel configuration derived from the controller's [`DeviceConfig`].

use ipnet::IpNet;
use ito_shared::api::DeviceConfig;
use serde::{Deserialize, Serialize};

/// Complete local WireGuard tunnel configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelSpec {
    pub private_key: String,
    /// Interface IP addresses formatted as single-host prefixes (e.g. `10.0.0.2/32`).
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
    /// Interface MTU, or `0` for automatic selection.
    pub mtu: i32,
    pub peer: PeerSpec,
}

/// Controller WireGuard peer configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerSpec {
    pub public_key: String,
    /// Base64 preshared key, or empty when none is configured.
    pub preshared_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    /// Persistent keepalive interval in seconds, or `0` when disabled.
    pub keepalive: i32,
}

impl TunnelSpec {
    /// Builds a [`TunnelSpec`] from `c`, `private_key`, and the selected or default route profile.
    pub fn build(c: &DeviceConfig, private_key: &str, profile_id: Option<&str>) -> Self {
        let find_profile = |id: &str| c.route_profiles.iter().find(|p| p.id == id);
        let profile = profile_id
            .and_then(find_profile)
            .or_else(|| find_profile(&c.default_profile_id));
        Self {
            private_key: private_key.into(),
            addresses: c.addresses.iter().map(|a| format_host_prefix(a)).collect(),
            dns: c.dns.clone(),
            dns_search: c.dns_search.clone(),
            mtu: c.mtu,
            peer: PeerSpec {
                public_key: c.server_public_key.clone(),
                preshared_key: c.preshared_key.clone(),
                endpoint: c.endpoint.clone(),
                allowed_ips: profile.map(|p| p.allowed_ips.clone()).unwrap_or_default(),
                keepalive: c.keepalive,
            },
        }
    }

    fn routes(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.peer
            .allowed_ips
            .iter()
            .filter_map(|r| r.parse::<IpNet>().ok())
            .map(|r| r.trunc())
    }

    /// Returns any default routes (`0.0.0.0/0` or `::/0`) in `peer.allowed_ips`.
    pub fn default_routes(&self) -> Vec<IpNet> {
        self.routes().filter(|r| r.prefix_len() == 0).collect()
    }

    /// Returns `true` if `self` and `other` share an identical canonical route prefix.
    ///
    /// Subnets of different prefix lengths do not conflict because the OS routing table selects
    /// the more specific prefix.
    pub fn overlaps(&self, other: &Self) -> bool {
        self.routes().any(|a| other.routes().any(|b| a == b))
    }
}

/// Formats an IP address with its single-host CIDR prefix length (`/32` or `/128`).
pub fn format_host_prefix(address: &str) -> String {
    let bits = if address.contains(':') { 128 } else { 32 };
    format!("{address}/{bits}")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ito_shared::api::RouteProfile;

    /// Sample server public key used in test configs.
    pub(crate) const SERVER_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    /// Sample preshared key used in test configs.
    pub(crate) const PSK: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";

    pub(crate) fn build_sample_config() -> DeviceConfig {
        let build_profile = |id: &str, ips: &[&str]| RouteProfile {
            id: id.into(),
            name: id.into(),
            allowed_ips: ips.iter().map(|s| s.to_string()).collect(),
        };
        DeviceConfig {
            device_id: "d".into(),
            revision: 1,
            enabled: true,
            disabled_reason: None,
            ready: true,
            addresses: vec!["10.0.0.2".into(), "fd00::2".into()],
            grants: vec![],
            public_key: None,
            preshared_key: PSK.into(),
            server_public_key: SERVER_KEY.into(),
            endpoint: "vpn.test:51820".into(),
            route_profiles: vec![
                build_profile("vpn", &["10.0.0.0/24", "fd00::/64"]),
                build_profile("all", &["0.0.0.0/0", "::/0"]),
            ],
            default_profile_id: "vpn".into(),
            dns: vec!["10.0.0.1".into()],
            dns_search: vec!["vpn.test".into()],
            mtu: 0,
            keepalive: 25,
            key_expires_at: None,
            agent_credential_issued_at: None,
        }
    }

    #[test]
    fn specs_use_the_chosen_profile_or_fall_back_to_the_default() {
        for (chosen, expected) in [
            (Some("all"), ["0.0.0.0/0", "::/0"]),
            (None, ["10.0.0.0/24", "fd00::/64"]),
            (Some("gone"), ["10.0.0.0/24", "fd00::/64"]),
        ] {
            let spec = TunnelSpec::build(&build_sample_config(), "KEY=", chosen);
            assert_eq!(spec.peer.allowed_ips, expected, "{chosen:?}");
        }
    }

    #[test]
    fn addresses_become_host_prefixes() {
        let spec = TunnelSpec::build(&build_sample_config(), "KEY=", None);
        assert_eq!(spec.addresses, ["10.0.0.2/32", "fd00::2/128"]);
    }

    #[test]
    fn default_routes_are_found_among_the_allowed_ips() {
        for (profile, expected) in [("all", vec!["0.0.0.0/0", "::/0"]), ("vpn", vec![])] {
            let spec = TunnelSpec::build(&build_sample_config(), "KEY=", Some(profile));
            let defaults: Vec<String> = spec
                .default_routes()
                .iter()
                .map(|r| r.to_string())
                .collect();
            assert_eq!(defaults, expected, "{profile}");
        }
    }

    #[test]
    fn only_identical_canonical_prefixes_conflict() {
        for (a, b, expected) in [
            ("10.0.0.0/24", "10.0.0.0/24", true),
            ("10.0.0.1/24", "10.0.0.200/24", true),
            ("fd00::1/64", "fd00:0:0:0::/64", true),
            ("10.0.0.0/24", "10.0.0.0/8", false),
            ("10.0.0.0/24", "10.1.0.0/24", false),
            ("10.0.0.0/24", "0.0.0.0/0", false),
        ] {
            let mut first = TunnelSpec::build(&build_sample_config(), "KEY=", None);
            let mut second = first.clone();
            first.peer.allowed_ips = vec![a.into()];
            second.peer.allowed_ips = vec![b.into()];
            assert_eq!(first.overlaps(&second), expected, "{a} and {b}");
        }
    }
}
