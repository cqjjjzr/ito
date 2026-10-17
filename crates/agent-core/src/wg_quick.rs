//! Tunnels written as wg-quick configuration files.

use crate::spec::TunnelSpec;

/// Renders `spec` as a wg-quick configuration file.
pub fn render_config(spec: &TunnelSpec) -> String {
    let p = &spec.peer;
    let dns: Vec<&str> = spec
        .dns
        .iter()
        .chain(&spec.dns_search)
        .map(String::as_str)
        .collect();
    let mut lines = vec![
        "[Interface]".to_string(),
        format!("PrivateKey = {}", spec.private_key),
        format!("Address = {}", spec.addresses.join(", ")),
    ];
    if !dns.is_empty() {
        lines.push(format!("DNS = {}", dns.join(", ")));
    }
    if spec.mtu != 0 {
        lines.push(format!("MTU = {}", spec.mtu));
    }
    lines.extend([
        "".into(),
        "[Peer]".into(),
        format!("PublicKey = {}", p.public_key),
    ]);
    if !p.preshared_key.is_empty() {
        lines.push(format!("PresharedKey = {}", p.preshared_key));
    }
    lines.push(format!("Endpoint = {}", p.endpoint));
    lines.push(format!("AllowedIPs = {}", p.allowed_ips.join(", ")));
    if p.keepalive != 0 {
        lines.push(format!("PersistentKeepalive = {}", p.keepalive));
    }
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::tests::{PSK, SERVER_KEY, build_sample_config};

    #[test]
    fn specs_render_as_wg_quick_files() {
        let mut spec = TunnelSpec::build(&build_sample_config(), "KEY=", None);
        spec.mtu = 1380;
        assert_eq!(
            render_config(&spec),
            format!(
                "[Interface]\nPrivateKey = KEY=\nAddress = 10.0.0.2/32, fd00::2/128\n\
                 DNS = 10.0.0.1, vpn.test\nMTU = 1380\n\n[Peer]\nPublicKey = {SERVER_KEY}\n\
                 PresharedKey = {PSK}\nEndpoint = vpn.test:51820\n\
                 AllowedIPs = 10.0.0.0/24, fd00::/64\nPersistentKeepalive = 25\n"
            )
        );
    }

    #[test]
    fn unset_settings_are_left_out() {
        let mut spec = TunnelSpec::build(&build_sample_config(), "KEY=", None);
        spec.dns.clear();
        spec.dns_search.clear();
        spec.peer.preshared_key.clear();
        spec.peer.keepalive = 0;
        assert_eq!(
            render_config(&spec),
            format!(
                "[Interface]\nPrivateKey = KEY=\nAddress = 10.0.0.2/32, fd00::2/128\n\n\
                 [Peer]\nPublicKey = {SERVER_KEY}\nEndpoint = vpn.test:51820\n\
                 AllowedIPs = 10.0.0.0/24, fd00::/64\n"
            )
        );
    }
}
