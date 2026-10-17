//! Device address pools, per-account quotas, and grant assignment.

pub mod prefix;

use crate::{
    accounts::resolve_quota,
    config::{Config, Pool},
    db::*,
    error::{Code, Error, Result, conflict, invalid, not_found},
};
use ipnet::IpNet;
use prefix::{count_address_bits, overlaps, remove_covered_prefixes};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

// --- Quotas ---

/// Address limits per IP family, expressed as a decimal address count or a prefix length such as
/// `/64`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, utoipa::ToSchema)]
#[serde(default)]
pub struct Quota {
    /// IPv4 address limit.
    pub ipv4: String,
    /// IPv6 address limit.
    pub ipv6: String,
}

/// Parses a quota into address-count limits per family (`[ipv4, ipv6]`). `None` means unlimited,
/// and counts saturate at `u128::MAX`.
pub fn parse_limits(q: &Quota) -> Result<[Option<u128>; 2]> {
    let parse_limit = |s: &str, family_bits: u32| -> Result<Option<u128>> {
        if s.is_empty() {
            return Ok(None);
        }
        let n = match s.strip_prefix('/') {
            Some(len) => {
                let len: u32 = len.parse().map_err(|_| invalid(format!("bad quota {s}")))?;
                if len > family_bits {
                    return Err(invalid(format!("bad quota {s}")));
                }
                1u128.checked_shl(family_bits - len).unwrap_or(u128::MAX)
            }
            None => s.parse().map_err(|_| invalid(format!("bad quota {s}")))?,
        };
        Ok(Some(n))
    };
    Ok([parse_limit(&q.ipv4, 32)?, parse_limit(&q.ipv6, 128)?])
}

pub fn count_usage(grants: &[String]) -> Result<[u128; 2]> {
    let mut out = [0u128; 2];
    for p in remove_covered_prefixes(grants)? {
        let size = 1u128
            .checked_shl(u32::from(count_address_bits(p) - p.prefix_len()))
            .unwrap_or(u128::MAX);
        let family = usize::from(!p.addr().is_ipv4());
        out[family] = out[family].saturating_add(size);
    }
    Ok(out)
}

/// Validates a change in grants against the account quota. Growing past the limit is rejected,
/// while keeping or shrinking an existing over-quota allocation is allowed.
pub fn validate_quota(before: &[String], after: &[String], q: &Quota) -> Result<()> {
    let limits = parse_limits(q)?;
    let (old, new) = (count_usage(before)?, count_usage(after)?);
    for i in 0..2 {
        if limits[i].is_some_and(|limit| new[i] > limit && new[i] > old[i]) {
            return Err(conflict(Code::AddressQuotaExceeded));
        }
    }
    Ok(())
}

// --- Pool validation and grant assignment ---

/// Validates merged grants against an interface's pools. Every grant must fit within a pool,
/// avoid its exclusions, have a prefix length of at least `min_prefix_length`, and stay within
/// `max_prefixes`.
pub fn validate_grants(pools: &[crate::config::Pool], grants: &[IpNet]) -> Result<()> {
    let mut per_pool = vec![0u32; pools.len()];
    for g in grants {
        let (n, pool) = pools
            .iter()
            .enumerate()
            .find(|(_, p)| p.prefix.contains(g))
            .ok_or_else(|| Error::new(Code::OutsidePool).detail(g))?;
        (g.prefix_len() >= pool.min_length())
            .ok_or_else(|| invalid(format!("{g} is larger than the pool allows")))?;
        per_pool[n] += 1;
        (per_pool[n] <= pool.max_prefixes)
            .ok_or_else(|| invalid(format!("too many prefixes from pool {}", pool.prefix)))?;
        for e in &pool.exclusions {
            (!overlaps(*e, *g)).ok_or_else(|| conflict(Code::AddressConflict).detail(g))?;
        }
    }
    Ok(())
}

/// Request to allocate one free block of `prefix_length` from a pool.
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema)]
pub struct Allocation {
    /// Pool prefix, such as `10.0.0.0/24`.
    pub pool: String,
    pub prefix_length: u8,
}

/// A device's interface addresses and routed prefix grants.
///
/// Every grant and interface address must belong to a pool on the device's interface, satisfy the
/// pool's `min_prefix_length`, `max_prefixes`, and `exclusions`, and avoid overlapping any server
/// interface address or another device's grants. The account's total usage across all devices must
/// stay within its quota, though shrinking an existing allocation is always allowed.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct Addresses {
    /// Single IP addresses assigned to the client's WireGuard interface, such as `10.0.0.2`. Each
    /// address also becomes a `/32` or `/128` grant unless it is already covered by `grants`. When
    /// both `addresses` and `allocate_addresses` are empty, the server allocates one free address
    /// per address family that has available pool space and quota.
    pub addresses: Vec<String>,
    /// Pool prefixes from which to allocate one additional free client address each.
    pub allocate_addresses: Vec<String>,
    /// Additional prefixes routed to the device, such as `10.0.0.8/29`.
    pub grants: Vec<String>,
    /// Prefix blocks to allocate from pools as additional grants.
    pub allocate_grants: Vec<Allocation>,
}

/// Lists the prefixes of all pools across all configured interfaces.
pub fn list_pool_prefixes(config: &Config) -> Vec<IpNet> {
    config
        .interfaces
        .values()
        .flat_map(|i| &i.pools)
        .map(|p| p.prefix)
        .collect()
}

/// Collects all prefixes occupied by server interfaces and by devices other than `except`.
async fn collect_occupied_prefixes(
    c: &impl ConnectionTrait,
    config: &Config,
    except: &str,
) -> Result<Vec<String>> {
    let pools = list_pool_prefixes(config);
    let mut used: Vec<String> = Vec::new();
    for d in device::Entity::find()
        .filter(device::Column::Id.ne(except))
        .all(c)
        .await?
    {
        used.extend(d.grants.0);
        // Extra server-side routes that fall inside a pool reserve that address space so it is not
        // allocated to another device.
        for r in d.extra_allowed_ips.iter() {
            let r = prefix::parse_prefix(r)?;
            if pools.iter().any(|p| p.contains(&r)) {
                used.push(r.to_string());
            }
        }
    }
    for i in config.interfaces.values() {
        for a in &i.addresses {
            used.push(prefix::parse_interface_address(a)?.to_string());
        }
    }
    Ok(used)
}

/// Validates and assigns a device's client addresses and additional grants, allocating from pools
/// as requested.
pub async fn assign(
    tx: &Tx,
    config: &Config,
    d: &mut device::Model,
    a: &account::Model,
    input: Addresses,
) -> Result<()> {
    let interface = config
        .interfaces
        .get(&d.interface_id)
        .ok_or_else(not_found)?;
    let used = collect_occupied_prefixes(&**tx, config, &d.id).await?;
    let find_pool = |prefix: &str| -> Result<&Pool> {
        let pool = interface
            .pools
            .iter()
            .find(|p| p.prefix.to_string() == prefix);
        pool.ok_or_else(not_found)
    };
    let mut grants = input.grants;
    for request in input.allocate_grants {
        let pool = find_pool(&request.pool)?;
        (request.prefix_length >= pool.min_length())
            .ok_or_else(|| invalid("prefix_length is below the pool minimum"))?;
        let taken: Vec<String> = (pool.exclusions.iter().map(ToString::to_string))
            .chain(grants.iter().cloned())
            .chain(used.iter().cloned())
            .collect();
        grants.push(prefix::allocate(
            pool.prefix,
            request.prefix_length,
            &taken,
        )?);
    }
    // Client addresses are tracked as host prefixes during validation and stored as plain IP
    // addresses on the device model.
    let mut own = input
        .addresses
        .iter()
        .map(|a| prefix::parse_address(a).map(|h| h.to_string()))
        .collect::<Result<Vec<_>>>()?;
    for request in input.allocate_addresses {
        let pool = find_pool(&request)?;
        let taken: Vec<String> = (pool.exclusions.iter().map(ToString::to_string))
            .chain(grants.iter().cloned())
            .chain(own.iter().cloned())
            .chain(used.iter().cloned())
            .collect();
        let net = pool.prefix;
        own.push(prefix::allocate(
            net,
            prefix::count_address_bits(net),
            &taken,
        )?);
    }
    let others: Vec<String> = device::Entity::find()
        .filter(device::Column::AccountId.eq(&a.id))
        .filter(device::Column::Id.ne(&d.id))
        .filter(device::Column::Deleting.eq(false))
        .all(&**tx)
        .await?
        .into_iter()
        .flat_map(|o| o.grants.0)
        .collect();
    if own.is_empty() {
        // Count the account's other devices and this request's explicit grants against the quota
        // before deciding which address families can receive an automatic host address.
        let limits = parse_limits(&resolve_quota(config, a))?;
        let taken: Vec<String> = others.iter().chain(&grants).cloned().collect();
        let usage = count_usage(&taken)?;
        let room = [0, 1].map(|f| limits[f].is_none_or(|limit| usage[f] < limit));
        own = pick_hosts(&interface.pools, room, &grants, &used)?;
    }
    (!own.is_empty()).ok_or_else(|| invalid("a device needs at least one address"))?;
    let own = remove_covered_prefixes(&own)?;
    let all: Vec<String> = own.iter().map(ToString::to_string).chain(grants).collect();
    let granted = remove_covered_prefixes(&all)?;
    validate_grants(&interface.pools, &granted)?;
    let used = remove_covered_prefixes(&used)?;
    for g in &granted {
        let taken = used.iter().any(|u| prefix::overlaps(*u, *g));
        (!taken).ok_or_else(|| conflict(Code::AddressConflict).detail(g))?;
    }
    let new: Vec<String> = granted.iter().map(ToString::to_string).collect();
    let before: Vec<String> = others.iter().chain(d.grants.iter()).cloned().collect();
    let after: Vec<String> = others.iter().chain(&new).cloned().collect();
    validate_quota(&before, &after, &resolve_quota(config, a))?;
    d.client_addresses = Strings(own.iter().map(|h| h.addr().to_string()).collect());
    d.grants = Strings(new);
    Ok(())
}

/// Allocates one free host address for each IP family that has both an available pool and quota
/// headroom (`room`), avoiding `grants` and `used`.
fn pick_hosts(
    pools: &[Pool],
    room: [bool; 2],
    grants: &[String],
    used: &[String],
) -> Result<Vec<String>> {
    let mut done = [false; 2];
    let mut exhausted = false;
    let mut over_quota = false;
    let mut hosts = Vec::new();
    for p in pools {
        let net = p.prefix;
        let family = usize::from(!net.addr().is_ipv4());
        over_quota |= !room[family];
        if done[family] || !room[family] {
            continue;
        }
        let taken: Vec<String> = (used.iter().cloned())
            .chain(grants.iter().cloned())
            .chain(p.exclusions.iter().map(ToString::to_string))
            .collect();
        match prefix::allocate(net, prefix::count_address_bits(net), &taken) {
            Ok(h) => {
                hosts.push(h);
                done[family] = true;
            }
            Err(e) if e.code == Code::PoolExhausted => exhausted = true,
            Err(e) => return Err(e),
        }
    }
    if hosts.is_empty() && exhausted {
        return Err(conflict(Code::PoolExhausted));
    }
    if hosts.is_empty() && over_quota {
        return Err(conflict(Code::AddressQuotaExceeded));
    }
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn usage_counts_overlapping_grants_once() {
        let grants = to_strings(&["fd00::/64", "fd00::/128", "10.0.0.0/28", "10.0.0.1/32"]);
        assert_eq!(count_usage(&grants).unwrap(), [16, 1 << 64]);
    }

    #[test]
    fn quotas_are_counts_or_prefix_lengths() {
        for (ipv4, ipv6, limits) in [
            ("4", "/0", [Some(4), Some(u128::MAX)]),
            ("/24", "/64", [Some(256), Some(1 << 64)]),
            ("", "", [None, None]),
        ] {
            let q = Quota {
                ipv4: ipv4.into(),
                ipv6: ipv6.into(),
            };
            assert_eq!(parse_limits(&q).unwrap(), limits, "{ipv4:?} {ipv6:?}");
        }
    }

    #[test]
    fn quotas_refuse_growth_past_the_limit() {
        let q = Quota {
            ipv4: "4".into(),
            ipv6: String::new(),
        };
        let error = validate_quota(&[], &to_strings(&["10.0.0.0/29"]), &q).unwrap_err();
        assert_eq!(error.code, Code::AddressQuotaExceeded);
    }

    #[test]
    fn quotas_allow_shrinking_allocations_over_the_limit() {
        let q = Quota {
            ipv4: "4".into(),
            ipv6: String::new(),
        };
        let (before, after) = (to_strings(&["10.0.0.0/28"]), to_strings(&["10.0.0.0/29"]));
        validate_quota(&before, &after, &q).unwrap();
    }

    #[test]
    fn automatic_addresses_skip_families_without_room() {
        let pool = |prefix: &str| Pool {
            prefix: prefix.parse().unwrap(),
            ..Pool::default()
        };
        let pools = [pool("10.0.0.0/30"), pool("fd00::/126")];
        let pick = |room, used: &[&str]| pick_hosts(&pools, room, &[], &to_strings(used));
        let both = pick([true, true], &[]).unwrap();
        assert_eq!(both, to_strings(&["10.0.0.1/32", "fd00::1/128"]));
        let v6 = pick([false, true], &[]).unwrap();
        assert_eq!(v6, to_strings(&["fd00::1/128"]), "no IPv4 quota left");
        let v6 = pick([true, true], &["10.0.0.0/30"]).unwrap();
        assert_eq!(v6, to_strings(&["fd00::1/128"]), "the IPv4 pool is full");
        let full = pick([true, false], &["10.0.0.0/30"]).unwrap_err();
        assert_eq!(full.code, Code::PoolExhausted);
        let none = pick([false, false], &[]).unwrap_err();
        assert_eq!(none.code, Code::AddressQuotaExceeded);
    }
}
