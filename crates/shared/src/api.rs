//! Controller HTTP API types shared with device agents.

use crate::{
    keys::is_valid_key,
    names::{is_dns_domain, is_endpoint},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Named set of `AllowedIPs` that a client can select for its local tunnel routes. Selecting a
/// profile changes only the client's `AllowedIPs`, leaving the server's peer routes unchanged.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RouteProfile {
    /// Profile identifier: a DNS label that is unique within the interface.
    pub id: String,
    /// Display name shown to users in the portal and agent UI.
    pub name: String,
    /// Client-side `AllowedIPs` prefixes routed through the tunnel when this profile is active.
    pub allowed_ips: Vec<String>,
}

/// Reason a device's peer is excluded from the kernel WireGuard interface, ordered by precedence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DisabledReason {
    /// The device's interface is no longer present in the server configuration.
    InterfaceNotConfigured,
    /// The device's interface is marked `disabled` in the server configuration.
    InterfaceDisabled,
    /// The device is marked for deletion and awaiting kernel removal.
    Deleting,
    /// An administrator blocked the device.
    Blocked,
    /// The owning account is blocked or inactive at the identity provider.
    AccountInactive,
    /// The device is paused by its owner or an administrator.
    Paused,
    /// The device's grants no longer fit within its interface's configured pools.
    OutsidePools,
    /// A grant overlaps an address assigned to a server interface.
    AddressConflict,
    /// The device does not have a WireGuard public key yet.
    NoKey,
    /// The device's WireGuard key has expired or been revoked.
    KeyExpired,
    #[serde(other)]
    Unknown,
}

impl std::fmt::Display for DisabledReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InterfaceNotConfigured => "interface removed",
            Self::InterfaceDisabled => "interface disabled",
            Self::Deleting => "being deleted",
            Self::Blocked => "blocked",
            Self::AccountInactive => "account inactive",
            Self::Paused => "paused",
            Self::OutsidePools => "outside the pools",
            Self::AddressConflict => "address conflict",
            Self::NoKey => "no key",
            Self::KeyExpired => "key expired",
            Self::Unknown => "unavailable",
        })
    }
}

/// Parameters required by a client or agent to assemble its local WireGuard configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeviceConfig {
    pub device_id: String,
    pub revision: i64,
    /// Whether the device is currently permitted to connect.
    pub enabled: bool,
    /// Reason the device cannot connect right now, or `null` when enabled.
    pub disabled_reason: Option<DisabledReason>,
    /// Whether the kernel reconciler has applied the device's current revision and interface
    /// settings without error.
    pub ready: bool,
    /// Single IP addresses assigned to the client's WireGuard interface.
    pub addresses: Vec<String>,
    /// Prefixes routed to this device on the server.
    pub grants: Vec<String>,
    pub public_key: Option<String>,
    /// Preshared key in base64, or empty when none is configured.
    pub preshared_key: String,
    pub server_public_key: String,
    pub endpoint: String,
    /// Route profiles available on the interface. When the interface defines no profiles, the
    /// server synthesizes a single `pools` profile covering the interface's address pools.
    pub route_profiles: Vec<RouteProfile>,
    pub default_profile_id: String,
    pub dns: Vec<String>,
    /// DNS search domains, consisting of the interface's `dns_search` list followed by its
    /// `dns_zone`.
    pub dns_search: Vec<String>,
    /// Suggested client MTU, or `0` for automatic selection.
    pub mtu: i32,
    pub keepalive: i32,
    /// Timestamp when the current WireGuard key expires unless renewed or rotated.
    pub key_expires_at: Option<DateTime<Utc>>,
    /// Timestamp when the device's current agent credential was issued, or `null` if none exists.
    pub agent_credential_issued_at: Option<DateTime<Utc>>,
}

impl DeviceConfig {
    /// Validates all addresses, keys, and domain names used to build a tunnel so no field can
    /// inject extra arguments or configuration lines.
    pub fn validate(&self) -> Result<(), String> {
        let validate_field = |field: &str, ok: bool, value: &str| {
            ok.then_some(())
                .ok_or_else(|| format!("{field} has the malformed value {value:?}"))
        };
        for a in &self.addresses {
            validate_field("addresses", a.parse::<IpAddr>().is_ok(), a)?;
        }
        for d in &self.dns {
            validate_field("dns", d.parse::<IpAddr>().is_ok(), d)?;
        }
        for d in &self.dns_search {
            validate_field("dns_search", is_dns_domain(d), d)?;
        }
        for r in self.route_profiles.iter().flat_map(|p| &p.allowed_ips) {
            validate_field("route_profiles", r.parse::<ipnet::IpNet>().is_ok(), r)?;
        }
        let server_key = &self.server_public_key;
        validate_field("server_public_key", is_valid_key(server_key), server_key)?;
        let psk = &self.preshared_key;
        validate_field(
            "preshared_key",
            psk.is_empty() || is_valid_key(psk),
            "(hidden)",
        )?;
        validate_field("endpoint", is_endpoint(&self.endpoint), &self.endpoint)
    }
}

/// Live kernel state of a device's WireGuard peer at request time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeviceStatus {
    pub device_id: String,
    pub interface_id: String,
    pub observed_at: DateTime<Utc>,
    pub interface_present: bool,
    pub interface_up: bool,
    pub peer_present: bool,
    pub addresses: Vec<String>,
    pub allowed_ips: Option<Vec<String>>,
    pub endpoint: Option<String>,
    pub handshake: Option<DateTime<Utc>>,
    pub receive_bytes: u64,
    pub transmit_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a config whose every field is well formed.
    fn build_valid_config() -> DeviceConfig {
        DeviceConfig {
            device_id: "d".into(),
            revision: 1,
            enabled: true,
            disabled_reason: None,
            ready: true,
            addresses: vec!["10.0.0.2".into(), "fd00::2".into()],
            grants: vec![],
            public_key: None,
            preshared_key: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=".into(),
            server_public_key: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=".into(),
            endpoint: "vpn.test:51820".into(),
            route_profiles: vec![RouteProfile {
                id: "vpn".into(),
                name: "VPN".into(),
                allowed_ips: vec!["10.0.0.0/24".into()],
            }],
            default_profile_id: "vpn".into(),
            dns: vec!["10.0.0.1".into()],
            dns_search: vec!["vpn.test".into()],
            mtu: 0,
            keepalive: 25,
            key_expires_at: None,
            agent_credential_issued_at: None,
        }
    }

    /// A change that makes one field of a config malformed.
    type BreakField = fn(&mut DeviceConfig);

    #[test]
    fn configs_with_a_malformed_field_are_refused() {
        assert_eq!(build_valid_config().validate(), Ok(()));
        let cases: [(&str, BreakField); 7] = [
            ("addresses", |c| c.addresses.push("10.0.0.300".into())),
            ("dns", |c| c.dns.push("dns.vpn.test".into())),
            ("dns_search", |c| {
                c.dns_search.push("vpn.test\r\n[Peer]".into())
            }),
            ("route_profiles", |c| {
                c.route_profiles[0].allowed_ips.push("10.0.0.0/33".into());
            }),
            ("server_public_key", |c| c.server_public_key = "AAAA".into()),
            ("preshared_key", |c| c.preshared_key = "secret".into()),
            ("endpoint", |c| c.endpoint.push_str("\nPostUp = calc")),
        ];
        for (field, break_field) in cases {
            let mut config = build_valid_config();
            break_field(&mut config);
            let refused = config.validate().unwrap_err();
            assert!(refused.starts_with(&format!("{field} ")), "{refused}");
        }
    }

    #[test]
    fn malformed_preshared_keys_are_not_repeated() {
        let mut config = build_valid_config();
        config.preshared_key = "secret".into();
        let refused = config.validate().unwrap_err();
        assert!(!refused.contains("secret"), "{refused}");
    }

    #[test]
    fn unknown_fields_and_disabled_reasons_are_accepted() {
        let mut value = serde_json::to_value(build_valid_config()).unwrap();
        value["future_setting"] = serde_json::json!(123);
        value["route_profiles"][0]["future_profile_setting"] = serde_json::json!(true);
        value["disabled_reason"] = serde_json::json!("future_reason");
        let config: DeviceConfig = serde_json::from_value(value).unwrap();
        assert_eq!(config.disabled_reason, Some(DisabledReason::Unknown));
    }
}
