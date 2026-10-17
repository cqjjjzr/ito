//! Device lifecycle rules, peer eligibility, key binding, and route validation.

use crate::{
    addressing::{self, prefix},
    config::{Config, Interface},
    db::*,
    error::{Code, Result, conflict, invalid, not_found},
    wireguard_keys::{ServerKeyByInterface, validate_key},
};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use ito_shared::{
    api::DisabledReason,
    names::{is_dns_domain, is_dns_label},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::Deserialize;
use std::net::IpAddr;
use utoipa::ToSchema;

// --- Peer eligibility and change detection ---

/// Collects the device's server-side AllowedIPs: its grants and extra routes, sorted and
/// deduplicated.
pub fn collect_allowed_ips(d: &device::Model) -> Vec<String> {
    let mut routes: Vec<String> = d
        .grants
        .iter()
        .chain(d.extra_allowed_ips.iter())
        .cloned()
        .collect();
    routes.sort();
    routes.dedup();
    routes
}

/// Validates that the device's current grants still fit within its interface's configured pools.
fn validate_fit(d: &device::Model, i: &Interface) -> Result<()> {
    addressing::validate_grants(&i.pools, &prefix::remove_covered_prefixes(&d.grants)?)
}

/// Determines why the device's peer is excluded from the kernel, or returns `None` when it is
/// eligible.
pub fn determine_disabled_reason(
    d: &device::Model,
    config: &Config,
    a: &account::Model,
    now: DateTime<Utc>,
) -> Option<DisabledReason> {
    use DisabledReason::*;
    let Some(i) = config.interfaces.get(&d.interface_id) else {
        return Some(InterfaceNotConfigured);
    };
    let reason = if i.disabled {
        InterfaceDisabled
    } else if d.deleting {
        Deleting
    } else if d.blocked {
        Blocked
    } else if !a.active() {
        AccountInactive
    } else if d.paused {
        Paused
    } else if validate_fit(d, i).is_err() {
        OutsidePools
    } else if covers_interface_address(d, config) {
        AddressConflict
    } else if d.public_key.is_none() {
        NoKey
    } else if !d.key_expires_at.is_some_and(|t| now < t) {
        KeyExpired
    } else {
        return None;
    };
    Some(reason)
}

/// Checks whether any grant of the device overlaps a configured server interface address.
fn covers_interface_address(d: &device::Model, config: &Config) -> bool {
    let grants = prefix::remove_covered_prefixes(&d.grants).unwrap_or_default();
    let mut hosts = config
        .interfaces
        .values()
        .flat_map(|i| &i.addresses)
        .filter_map(|a| prefix::parse_interface_address(a).ok());
    hosts.any(|h| grants.iter().any(|g| prefix::overlaps(*g, h)))
}

/// Collects the client IP addresses published for `d` in authoritative DNS.
pub fn collect_dns_addresses(d: &device::Model) -> Vec<IpAddr> {
    d.client_addresses
        .iter()
        .filter_map(|a| a.parse().ok())
        .collect()
}

/// Extracts the device attributes that determine its WireGuard peer state in the kernel.
pub fn extract_peer_view(d: &device::Model) -> impl PartialEq + use<> {
    (
        d.interface_id.clone(),
        d.public_key.clone(),
        collect_allowed_ips(d),
        d.preshared_key.clone(),
        d.paused,
        d.blocked,
        d.deleting,
        d.key_expires_at,
    )
}

/// Marks the transaction as changing kernel or DNS state when those views of the device differ.
pub fn notify(tx: &mut Tx, old: Option<&device::Model>, new: Option<&device::Model>) {
    if old.map(extract_peer_view) != new.map(extract_peer_view) {
        tx.mark_kernel_changed();
    }
    let extract_dns_view = |d: &device::Model| {
        d.dns_name
            .clone()
            .map(|name| (name, collect_dns_addresses(d)))
    };
    if old.and_then(extract_dns_view) != new.and_then(extract_dns_view) {
        tx.mark_dns_changed();
    }
}

// --- Persistence and revocation ---

/// Stores a device update with the next revision.
pub async fn save(
    tx: &mut Tx,
    old: &device::Model,
    mut new: device::Model,
) -> Result<device::Model> {
    new.revision = old.revision + 1;
    // If the old revision was applied and the peer view is unchanged, the kernel already matches
    // the new revision too.
    if old.applied_revision == old.revision && extract_peer_view(old) == extract_peer_view(&new) {
        new.applied_revision = new.revision;
    }
    tx.update::<device::ActiveModel>(new.clone()).await?;
    notify(tx, Some(old), Some(&new));
    Ok(new)
}

/// Deletes the agent credential of the device `device_id`, if it has one.
pub async fn delete_agent_credentials(tx: &Tx, device_id: &str) -> Result<()> {
    agent_credential::Entity::delete_many()
        .filter(agent_credential::Column::DeviceId.eq(device_id))
        .exec(&**tx)
        .await?;
    Ok(())
}

/// Deletes the device's agent credential, forgets pending approvals, and clears its WireGuard
/// public key while preserving its address grants.
pub async fn revoke(
    tx: &mut Tx,
    approvals: &crate::approvals::AgentApprovals,
    mut d: device::Model,
) -> Result<device::Model> {
    delete_agent_credentials(tx, &d.id).await?;
    approvals.forget_device(&d.id);
    d.public_key = None;
    d.key_expires_at = None;
    Ok(d)
}

/// Deletes the device's agent credential, forgets pending approvals, and ends its key now, for an
/// account that stopped being active. Unlike [`revoke`], the device keeps its key: an account that
/// becomes active again, such as after a mistaken block, can renew it instead of setting up every
/// device anew.
pub async fn suspend(
    tx: &mut Tx,
    approvals: &crate::approvals::AgentApprovals,
    mut d: device::Model,
) -> Result<device::Model> {
    delete_agent_credentials(tx, &d.id).await?;
    approvals.forget_device(&d.id);
    let now = Utc::now();
    if d.key_expires_at.is_some_and(|t| t > now) {
        d.key_expires_at = Some(now);
    }
    Ok(d)
}

// --- Device mutations ---

/// Binds a public key to the device for `lifetime`, refusing keys held by any other device.
pub async fn bind_key(
    tx: &mut Tx,
    servers: &ServerKeyByInterface,
    d: &mut device::Model,
    key: &str,
    lifetime: std::time::Duration,
) -> Result<()> {
    validate_key(key)?;
    let key = key.to_string();
    if d.blocked && d.public_key.as_deref() != Some(&key) {
        return Err(conflict(Code::KeyConflict).detail("can't change the key of a blocked device"));
    }
    (!servers.contains_public(&key)).ok_or_else(|| conflict(Code::KeyConflict))?;
    let holder = device::Entity::find()
        .filter(device::Column::PublicKey.eq(&key))
        .one(&**tx)
        .await?;
    if holder.is_some_and(|source| source.id != d.id) {
        return Err(conflict(Code::KeyConflict));
    }
    d.public_key = Some(key);
    let lifetime = chrono::TimeDelta::from_std(lifetime).expect("validated lifetime");
    d.key_expires_at = Some(Utc::now() + lifetime);
    Ok(())
}

/// Mutable device settings; omitted fields remain unchanged.
#[derive(Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct Settings {
    pub name: Option<String>,
    pub note: Option<String>,
    /// DNS label for the device in its interface's zone, or empty to opt out of DNS publication.
    pub dns_name: Option<String>,
    pub paused: Option<bool>,
}

/// Applies `s` to the device after validating each modified field.
pub async fn apply_settings(
    tx: &Tx,
    config: &Config,
    mut d: device::Model,
    s: Settings,
) -> Result<device::Model> {
    (!d.deleting).ok_or_else(not_found)?;
    if let Some(name) = s.name {
        let valid = name.chars().count() <= 255 && !name.contains(['\r', '\n', '\0']);
        valid.ok_or_else(|| invalid("name is too long or contains control characters"))?;
        d.name = name;
    }
    if let Some(note) = s.note {
        (!note.contains('\0')).ok_or_else(|| invalid("note must not contain NUL"))?;
        d.note = note;
    }
    if let Some(name) = s.dns_name {
        let name = name.to_ascii_lowercase();
        if name.is_empty() {
            d.dns_name = None;
        } else {
            is_dns_label(&name).ok_or_else(|| invalid("dns_name must be one DNS label"))?;
            let zone = config.interfaces.get(&d.interface_id).map(|i| &i.dns_zone);
            if let Some(zone) = zone.filter(|z| !z.is_empty()) {
                is_dns_domain(&format!("{name}.{zone}"))
                    .ok_or_else(|| invalid("dns_name is too long for the zone"))?;
            }
            let taken = device::Entity::find()
                .filter(device::Column::DnsName.eq(&name))
                .filter(device::Column::Id.ne(&d.id))
                .one(&**tx)
                .await?;
            taken
                .is_none()
                .ok_or_else(|| conflict(Code::DnsNameTaken))?;
            d.dns_name = Some(name);
        }
    }
    if let Some(paused) = s.paused {
        d.paused = paused;
    }
    Ok(d)
}

/// Preshared key update request; specify either `generate: true` or `preshared_key`.
#[derive(Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct Psk {
    /// Base64 preshared key, or empty to clear it.
    pub preshared_key: Option<String>,
    /// Whether the server should generate a random preshared key.
    pub generate: bool,
}

/// Sets the device's preshared key from `input`.
pub fn apply_psk(mut d: device::Model, input: Psk) -> Result<device::Model> {
    (!d.deleting).ok_or_else(not_found)?;
    d.preshared_key = match (input.generate, input.preshared_key) {
        (true, None) => {
            let mut bytes = [0u8; 32];
            getrandom::fill(&mut bytes).expect("operating system random source");
            base64::engine::general_purpose::STANDARD.encode(bytes)
        }
        (false, Some(key)) if key.is_empty() => key,
        (false, Some(key)) => {
            validate_key(&key)?;
            key
        }
        _ => return Err(invalid("send exactly one of generate or preshared_key")),
    };
    Ok(d)
}

/// WireGuard public key update request.
#[derive(Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct DeviceKey {
    /// New public key, or omitted to renew the existing key.
    pub public_key: Option<String>,
}

/// Sets the device's key from `input`, or renews the current one, for `lifetime`.
pub async fn apply_key(
    tx: &mut Tx,
    servers: &ServerKeyByInterface,
    lifetime: std::time::Duration,
    old: &device::Model,
    input: DeviceKey,
) -> Result<device::Model> {
    let key = input
        .public_key
        .or_else(|| old.public_key.clone())
        .ok_or_else(|| invalid("public_key is required"))?;
    let mut new = old.clone();
    bind_key(tx, servers, &mut new, &key, lifetime).await?;
    Ok(new)
}

/// Replaces the device's extra server-side `AllowedIPs` prefixes.
///
/// Exact prefix duplicates on the same interface are rejected because WireGuard assigns each
/// `AllowedIPs` prefix to a single peer. Routes contained within a pool also cannot overlap another
/// device's grants. Broader routes outside or encompassing a pool (such as `0.0.0.0/0` on a gateway
/// peer) are permitted; WireGuard's longest-prefix matching sends pool traffic to the more specific
/// peer grants. Extra routes of different devices may nest in one another, inside pools too, and
/// the longer prefix wins.
pub async fn apply_extra_routes(
    tx: &Tx,
    config: &Config,
    d: device::Model,
    mut routes: Vec<String>,
) -> Result<device::Model> {
    (!d.deleting).ok_or_else(not_found)?;
    routes.sort();
    routes.dedup();
    let parsed = routes
        .iter()
        .map(|r| Ok((r, prefix::parse_prefix(r)?)))
        .collect::<Result<Vec<_>>>()?;
    let pools = addressing::list_pool_prefixes(config);
    let others = device::Entity::find()
        .filter(device::Column::Id.ne(&d.id))
        .all(&**tx)
        .await?;
    for (r, route) in parsed {
        let in_pool = pools.iter().any(|p| p.contains(&route));
        let taken = others.iter().any(|o| {
            let neighbor = o.interface_id == d.interface_id && !o.deleting;
            let same = o.grants.contains(r) || o.extra_allowed_ips.contains(r);
            let overlapping = o
                .grants
                .iter()
                .any(|g| prefix::parse_prefix(g).is_ok_and(|g| prefix::overlaps(g, route)));
            (neighbor && same) || (in_pool && overlapping)
        });
        (!taken).ok_or_else(|| conflict(Code::AddressConflict).detail(r))?;
    }
    Ok(device::Model {
        extra_allowed_ips: Strings(routes),
        ..d
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Pool;
    use DisabledReason::*;

    /// A device on `wg0` with every reason to be disabled at once.
    fn build_troubled_device() -> (device::Model, account::Model, Config) {
        let mut config = Config::default();
        let interface = Interface {
            disabled: true,
            addresses: vec!["10.0.0.1/24".into()],
            pools: vec![Pool {
                prefix: "10.0.0.0/24".parse().unwrap(),
                ..Pool::default()
            }],
            ..Interface::default()
        };
        config.interfaces.insert("wg0".into(), interface);
        let now = Utc::now();
        let a = account::Model {
            id: "a".into(),
            subject: "a".into(),
            display_name: "a".into(),
            blocked: true,
            idp_status: account::IdpStatus::Active,
            idp_checked_at: None,
            idp_check_error: false,
            quota_ipv4: String::new(),
            quota_ipv6: String::new(),
            revision: 1,
            created_at: now,
        };
        let d = device::Model {
            id: "d".into(),
            account_id: "a".into(),
            interface_id: "gone".into(),
            name: String::new(),
            note: String::new(),
            dns_name: None,
            preshared_key: String::new(),
            public_key: None,
            key_expires_at: Some(now - chrono::TimeDelta::seconds(1)),
            // Outside the pool, and over the server's address.
            grants: Strings(vec!["10.1.0.2/32".into(), "10.0.0.1/32".into()]),
            client_addresses: Strings::default(),
            extra_allowed_ips: Strings::default(),
            paused: true,
            blocked: true,
            deleting: true,
            revision: 1,
            applied_revision: 0,
            applied_enabled: false,
            apply_error: String::new(),
            created_at: now,
        };
        (d, a, config)
    }

    /// A change that removes one reason for a device to be disabled.
    type Removal = fn(&mut device::Model, &mut account::Model, &mut Config);

    #[test]
    fn disabled_reasons_follow_their_precedence() {
        let (mut d, mut a, mut config) = build_troubled_device();
        // Each step reports one reason, then removes it to uncover the next.
        let steps: &[(DisabledReason, Removal)] = &[
            (InterfaceNotConfigured, |d, _, _| {
                d.interface_id = "wg0".into()
            }),
            (InterfaceDisabled, |_, _, c| {
                c.interfaces.get_mut("wg0").unwrap().disabled = false;
            }),
            (Deleting, |d, _, _| d.deleting = false),
            (Blocked, |d, _, _| d.blocked = false),
            (AccountInactive, |_, a, _| a.blocked = false),
            (Paused, |d, _, _| d.paused = false),
            (OutsidePools, |d, _, _| {
                d.grants.0.retain(|g| g != "10.1.0.2/32")
            }),
            (AddressConflict, |d, _, _| {
                d.grants = Strings(vec!["10.0.0.2/32".into()])
            }),
            (NoKey, |d, _, _| d.public_key = Some("key".into())),
            (KeyExpired, |d, _, _| {
                d.key_expires_at = Some(Utc::now() + chrono::TimeDelta::hours(1));
            }),
        ];
        for (reason, remove) in steps {
            let found = determine_disabled_reason(&d, &config, &a, Utc::now());
            assert_eq!(found, Some(*reason));
            remove(&mut d, &mut a, &mut config);
        }
        assert_eq!(determine_disabled_reason(&d, &config, &a, Utc::now()), None);
    }
}
