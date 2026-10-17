//! Names of connections, which are also the names of their WireGuard interfaces and tunnels.

/// Generates a tunnel name for `device_id`: `ito-` followed by the last 8 to 11 hex digits of the
/// ID, avoiding any names already present in `taken`. Names fit within Linux's 15-byte interface
/// limit.
pub fn derive_tunnel_name(device_id: &str, taken: &[String]) -> String {
    let hex: Vec<char> = device_id.chars().filter(char::is_ascii_hexdigit).collect();
    let name = |n: usize| {
        let tail: String = hex[hex.len().saturating_sub(n)..].iter().collect();
        format!("ito-{tail}")
    };
    (8..=11)
        .map(name)
        .find(|n| !taken.contains(n))
        .unwrap_or_else(|| name(11))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_take_the_tail_of_the_id_and_grow_on_collision() {
        let id = "01a14162-f7c1-764c-b059-c93b05c7ff30";
        let taken = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        let shorter = ["ito-05c7ff30", "ito-b05c7ff30", "ito-3b05c7ff30"];
        for (taken, expected) in [
            (taken(&[]), "ito-05c7ff30"),
            (taken(&shorter[..1]), "ito-b05c7ff30"),
            // The longest name fills Linux's 15-byte limit for interface names.
            (taken(&shorter), "ito-93b05c7ff30"),
        ] {
            assert_eq!(derive_tunnel_name(id, &taken), expected, "{taken:?}");
        }
    }
}
