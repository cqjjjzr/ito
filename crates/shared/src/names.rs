//! Validators for DNS names and WireGuard endpoints, shared by the controller and its agents.

use std::net::Ipv6Addr;

/// Returns true if `s` is a valid lowercase DNS label (1..=63 ASCII lowercase letters, digits, or
/// interior hyphens).
pub fn is_dns_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

/// Returns true if `s` is a valid lowercase DNS domain name (dot-separated DNS labels up to 253
/// bytes total, with no trailing dot).
pub fn is_dns_domain(s: &str) -> bool {
    s.len() <= 253 && s.split('.').all(is_dns_label)
}

/// Returns true if `s` is a WireGuard endpoint `host:port`: a host name or IPv4 address, or a
/// bracketed IPv6 address, with a port from 1 to 65535.
pub fn is_endpoint(s: &str) -> bool {
    let Some((host, port)) = s.rsplit_once(':') else {
        return false;
    };
    let host_ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<Ipv6Addr>().is_ok(),
        None => {
            !host.is_empty()
                && host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.')
        }
    };
    host_ok && port.parse::<u16>().is_ok_and(|p| p != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_a_plain_host_and_a_port() {
        for ok in [
            "vpn.example.com:51820",
            "192.0.2.1:1",
            "[2001:db8::1]:65535",
        ] {
            assert!(is_endpoint(ok), "{ok}");
        }
        for bad in [
            "vpn.example.com",
            "vpn.example.com:0",
            ":51820",
            "2001:db8::1:51820",
            "[vpn]:51820",
            "vpn.example.com:51820\nPostUp = calc",
            "vpn example.com:51820",
        ] {
            assert!(!is_endpoint(bad), "{bad}");
        }
    }

    #[test]
    fn dns_labels_are_short_lowercase_words_with_inner_hyphens() {
        let longest = "a".repeat(63);
        for ok in ["a", "laptop-2", longest.as_str()] {
            assert!(is_dns_label(ok), "{ok}");
        }
        let too_long = "a".repeat(64);
        for bad in [
            "", "Laptop", "-laptop", "laptop-", "lap_top", "lap.top", &too_long,
        ] {
            assert!(!is_dns_label(bad), "{bad}");
        }
    }

    #[test]
    fn dns_domains_are_dotted_labels_within_253_bytes() {
        let longest = ["a".repeat(63).as_str(); 4].join(".")[..253].to_string();
        for ok in ["vpn", "vpn.example.com", longest.as_str()] {
            assert!(is_dns_domain(ok), "{ok}");
        }
        let too_long = format!("{longest}a");
        for bad in [
            "",
            "vpn.example.com.",
            ".vpn",
            "vpn..example",
            "Vpn.example",
            &too_long,
        ] {
            assert!(!is_dns_domain(bad), "{bad}");
        }
    }
}
