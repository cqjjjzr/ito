//! IP prefix parsing, validation, and block allocation within address pools.

use crate::error::{Code, Result, conflict, invalid};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parses a canonical CIDR prefix (no host bits set, no IPv4-mapped IPv6 addresses, and formatted
/// identically to `Display`).
pub fn parse_prefix(s: &str) -> Result<IpNet> {
    let p: IpNet = s
        .parse()
        .map_err(|_| invalid(format!("{s} is not a prefix")))?;
    if p != p.trunc()
        || p.to_string() != s
        || matches!(p.addr(), IpAddr::V6(a) if a.to_ipv4_mapped().is_some())
    {
        return Err(invalid(format!("{s} is not a canonical prefix")));
    }
    Ok(p)
}

pub fn count_address_bits(p: IpNet) -> u8 {
    if p.addr().is_ipv4() { 32 } else { 128 }
}

/// Parses a single canonical IP address (such as `10.0.0.2`) into a host prefix (`/32` or `/128`).
pub fn parse_address(s: &str) -> Result<IpNet> {
    let a: IpAddr = s
        .parse()
        .map_err(|_| invalid(format!("{s} is not an address")))?;
    if a.to_string() != s || matches!(a, IpAddr::V6(v) if v.to_ipv4_mapped().is_some()) {
        return Err(invalid(format!("{s} is not a canonical address")));
    }
    Ok(IpNet::from(a))
}

pub fn overlaps(a: IpNet, b: IpNet) -> bool {
    a.contains(&b) || b.contains(&a)
}

/// Parses a list of prefixes, sorts them, and removes any prefix covered by a broader prefix.
pub fn remove_covered_prefixes(ss: &[String]) -> Result<Vec<IpNet>> {
    let mut ps = ss
        .iter()
        .map(|s| parse_prefix(s))
        .collect::<Result<Vec<_>>>()?;
    ps.sort_by_key(|p| (count_address_bits(*p), p.addr(), p.prefix_len()));
    let mut out: Vec<IpNet> = Vec::new();
    for p in ps {
        if !out.last().is_some_and(|last| last.contains(&p)) {
            out.push(p);
        }
    }
    Ok(out)
}

fn convert_ip_to_u128(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(a) => u32::from(a).into(),
        IpAddr::V6(a) => a.into(),
    }
}

fn compute_last_address_u128(p: IpNet) -> u128 {
    convert_ip_to_u128(p.broadcast())
}

/// Finds the lowest free aligned block of prefix length `len` inside `pool`.
pub fn allocate(pool: IpNet, len: u8, occupied: &[String]) -> Result<String> {
    if len < pool.prefix_len() || len > count_address_bits(pool) {
        return Err(invalid("prefix length outside the pool"));
    }
    let build_exhausted_error = || conflict(Code::PoolExhausted);
    let build_prefix_at = |n: u128| -> Result<IpNet> {
        let addr = if pool.addr().is_ipv4() {
            IpAddr::V4(Ipv4Addr::from(
                u32::try_from(n).map_err(|_| build_exhausted_error())?,
            ))
        } else {
            IpAddr::V6(Ipv6Addr::from(n))
        };
        Ok(IpNet::new(addr, len).expect("valid length").trunc())
    };
    let mut taken = occupied.to_vec();
    if len == count_address_bits(pool) {
        // Single-host allocations skip the IPv4 network and broadcast addresses (for pools larger
        // than /31) and the IPv6 subnet-router anycast address (for pools larger than /127).
        if pool.addr().is_ipv4() && pool.prefix_len() < 31 {
            taken.extend([pool.network(), pool.broadcast()].map(|a| format!("{a}/32")));
        } else if pool.addr().is_ipv6() && pool.prefix_len() < 127 {
            taken.push(format!("{}/128", pool.network()));
        }
    }
    let mut candidate = build_prefix_at(convert_ip_to_u128(pool.network()))?;
    for used in remove_covered_prefixes(&taken)? {
        if !overlaps(candidate, used) {
            continue;
        }
        let next = compute_last_address_u128(used)
            .checked_add(1)
            .ok_or_else(build_exhausted_error)?;
        candidate = build_prefix_at(next)?;
        if convert_ip_to_u128(candidate.network()) < next {
            candidate = build_prefix_at(
                compute_last_address_u128(candidate)
                    .checked_add(1)
                    .ok_or_else(build_exhausted_error)?,
            )?;
        }
        if !pool.contains(&candidate) {
            return Err(build_exhausted_error());
        }
    }
    Ok(candidate.to_string())
}

/// Parses a canonical interface address with its subnet, such as `10.0.0.1/24`, into the host
/// prefix it occupies (`10.0.0.1/32`). Rejects IPv4-mapped IPv6 addresses and non-canonical
/// formatting.
pub fn parse_interface_address(address: &str) -> Result<IpNet> {
    let p: IpNet = address
        .parse()
        .map_err(|_| invalid(format!("{address} is not an address")))?;
    if p.to_string() != address || matches!(p.addr(), IpAddr::V6(a) if a.to_ipv4_mapped().is_some())
    {
        return Err(invalid(format!("{address} is not a canonical address")));
    }
    Ok(IpNet::new(p.addr(), count_address_bits(p)).expect("full length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn allocation_skips_and_aligns_blocks() {
        for (pool, len, used, want) in [
            ("10.0.0.0/24", 32, vec!["10.0.0.0/31"], "10.0.0.2/32"),
            ("10.0.0.0/24", 28, vec!["10.0.0.1/32"], "10.0.0.16/28"),
            // Hosts skip the network address, but larger blocks may start at it.
            ("10.0.0.0/24", 32, vec![], "10.0.0.1/32"),
            ("10.0.0.0/24", 29, vec![], "10.0.0.0/29"),
            ("10.0.0.0/24", 24, vec![], "10.0.0.0/24"),
            ("::/0", 64, vec!["::/1"], "8000::/64"),
            // Hosts also skip the IPv6 subnet-router anycast address, except in a /127.
            ("fd00::/64", 128, vec![], "fd00::1/128"),
            ("fd00::/127", 128, vec![], "fd00::/128"),
            (
                "fd00::/64",
                124,
                vec!["fd00::/124", "fd00::10/128"],
                "fd00::20/124",
            ),
        ] {
            assert_eq!(
                allocate(parse_prefix(pool).unwrap(), len, &to_strings(&used)).unwrap(),
                want
            );
        }
        let full = allocate(
            parse_prefix("10.0.0.0/31").unwrap(),
            32,
            &to_strings(&["10.0.0.0/31"]),
        );
        assert_eq!(full.unwrap_err().code, Code::PoolExhausted);
    }

    #[test]
    fn non_canonical_prefixes_are_refused() {
        for s in [
            "10.0.0.1/24",
            "::ffff:10.0.0.1/128",
            "FD00::/64",
            "10.0.0.1",
        ] {
            assert!(parse_prefix(s).is_err(), "{s}");
        }
    }

    #[test]
    fn non_canonical_addresses_are_refused() {
        for s in ["10.0.0.1/32", "::ffff:10.0.0.1", "FD00::1"] {
            assert!(parse_address(s).is_err(), "{s}");
        }
    }

    #[test]
    fn addresses_parse_as_host_prefixes() {
        assert_eq!(parse_address("fd00::1").unwrap().to_string(), "fd00::1/128");
    }
}
