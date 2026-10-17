//! Parser and data types for `wg show <interface> dump` output.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Observed state of a kernel WireGuard interface.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Link {
    #[serde(skip)]
    pub alias: String,
    pub up: bool,
    pub mtu: i32,
    pub listen_port: i32,
    pub public_key: String,
    pub addresses: Vec<String>,
    pub peers: Vec<Peer>,
}

/// Observed state of a WireGuard peer in the kernel.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Peer {
    pub public_key: String,
    #[serde(skip)]
    pub preshared_key: String,
    pub endpoint: String,
    /// Peer AllowedIPs sorted lexicographically.
    pub allowed_ips: Vec<String>,
    /// Timestamp of the latest completed WireGuard handshake, if any.
    pub handshake: Option<DateTime<Utc>>,
    pub receive_bytes: u64,
    pub transmit_bytes: u64,
}

/// Error returned when `wg show <interface> dump` output is malformed.
#[derive(Debug)]
pub struct DumpError;

/// Parses `wg show <interface> dump` output into a [`Link`] with its public key, listen port, and
/// peers. Link flags, MTU, and IP addresses come from `ip` and remain at their default values here.
pub fn parse_dump(text: &str) -> Result<Link, DumpError> {
    let strip_none_marker = |s: &str| {
        if s == "(none)" {
            String::new()
        } else {
            s.to_string()
        }
    };
    let mut lines = text.lines();
    let header: Vec<_> = lines.next().ok_or(DumpError)?.split('\t').collect();
    // Header format: private-key \t public-key \t listen-port \t fwmark
    let [_, public_key, port, _] = header[..] else {
        return Err(DumpError);
    };
    let mut link = Link {
        public_key: strip_none_marker(public_key),
        listen_port: port.parse().map_err(|_| DumpError)?,
        ..Link::default()
    };
    for line in lines {
        let p: Vec<_> = line.split('\t').collect();
        let [key, psk, endpoint, ips, handshake, rx, tx, _] = p[..] else {
            return Err(DumpError);
        };
        let mut allowed_ips: Vec<String> = ips
            .split(',')
            .filter(|s| *s != "(none)")
            .map(String::from)
            .collect();
        allowed_ips.sort();
        let handshake: i64 = handshake.parse().map_err(|_| DumpError)?;
        link.peers.push(Peer {
            public_key: key.into(),
            preshared_key: strip_none_marker(psk),
            endpoint: strip_none_marker(endpoint),
            allowed_ips,
            handshake: (handshake > 0)
                .then(|| DateTime::from_timestamp(handshake, 0))
                .flatten(),
            receive_bytes: rx.parse().map_err(|_| DumpError)?,
            transmit_bytes: tx.parse().map_err(|_| DumpError)?,
        });
    }
    Ok(link)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dumps_give_the_link_and_its_peers() {
        let link = parse_dump(
            "private\tpublic\t51820\toff\n\
             peer\tpsk\t192.0.2.1:51820\tfd00::2/128,10.0.0.2/32\t1700000000\t123\t456\t0\n",
        )
        .unwrap();
        assert_eq!(link.public_key, "public");
        assert_eq!(link.listen_port, 51820);
        let peer = &link.peers[0];
        assert_eq!(peer.endpoint, "192.0.2.1:51820");
        assert_eq!(peer.allowed_ips, ["10.0.0.2/32", "fd00::2/128"]);
        assert_eq!(peer.handshake, DateTime::from_timestamp(1_700_000_000, 0));
        assert_eq!((peer.receive_bytes, peer.transmit_bytes), (123, 456));
    }

    #[test]
    fn none_markers_and_zero_handshakes_mean_unset() {
        let link =
            parse_dump("(none)\t(none)\t0\toff\npeer\t(none)\t(none)\t(none)\t0\t0\t0\toff\n")
                .unwrap();
        assert_eq!(link.public_key, "");
        let peer = &link.peers[0];
        assert_eq!(peer.preshared_key, "");
        assert_eq!(peer.endpoint, "");
        assert!(peer.allowed_ips.is_empty());
        assert_eq!(peer.handshake, None);
    }

    #[test]
    fn serialized_links_leave_out_preshared_keys() {
        let link = parse_dump("private\tpublic\t0\toff\npeer\tpsk\t(none)\t(none)\t0\t0\t0\toff\n");
        let json = serde_json::to_string(&link.unwrap()).unwrap();
        assert!(!json.contains("psk"), "{json}");
    }

    #[test]
    fn malformed_dumps_are_refused() {
        for dump in [
            "",
            "private\tpublic\t51820\n",
            "private\tpublic\tport\toff\n",
            "private\tpublic\t0\toff\npeer\tpsk\n",
            "private\tpublic\t0\toff\npeer\tpsk\t(none)\t(none)\tsoon\t0\t0\toff\n",
        ] {
            assert!(parse_dump(dump).is_err(), "{dump:?}");
        }
    }
}
