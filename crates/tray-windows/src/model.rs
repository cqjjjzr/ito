//! Platform-independent tray menu model, icon renderer, and link parsers.

use chrono::Local;
use ito_agent_core::{
    agent::{ConnectionStatus, ConnectionSummary},
    state::ConnectionState,
};
use std::collections::BTreeMap;
use url::Url;

// --- Menu model and icon appearance ---

/// A connection in the tray menu, identified by its agent connection name and human-readable device
/// name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionInMenu {
    pub name: String,
    pub device: String,
}

impl ConnectionInMenu {
    pub fn from_summary(s: &ConnectionSummary) -> Self {
        Self {
            name: s.name.clone(),
            device: s.device.name.clone(),
        }
    }

    /// Formats the connection name for dialogs and menus, for example `Laptop (ito-05c7ff30)`.
    pub fn label(&self) -> String {
        format!("{} ({})", self.device, self.name)
    }
}

/// What choosing a menu item does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Connect(ConnectionInMenu),
    Disconnect(ConnectionInMenu),
    SetProfile {
        connection: ConnectionInMenu,
        profile: Option<String>,
        allowed_ips: Option<Vec<String>>,
    },
    SetDns {
        connection: ConnectionInMenu,
        enabled: bool,
    },
    RotateKey(ConnectionInMenu),
    RotatePsk(ConnectionInMenu),
    /// Prompts for confirmation before removing the connection and revoking its credential.
    Logout(ConnectionInMenu),
    OpenPortal(String),
    /// Logs in through the portal, choosing or creating the device on its approval page.
    Login(String),
    /// Adds a connection from clipboard content; see [`parse_clipboard`].
    AddFromClipboard,
    Exit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// Non-interactive informational line.
    Text(String),
    Item {
        label: String,
        action: Action,
        /// `Some` for a check item, such as the active route profile.
        checked: Option<bool>,
    },
    Submenu {
        label: String,
        checked: Option<bool>,
        entries: Vec<Entry>,
    },
    Separator,
}

/// Tray icon state: `Up` when any connection is connected, `Problem` when any connection failed or
/// was revoked, and `Down` otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Look {
    Up,
    Down,
    Problem,
}

/// Draws an anti-aliased RGBA dot of `size` by `size` pixels for `look`.
pub fn draw_dot(look: Look, size: u32) -> Vec<u8> {
    let [r, g, b] = match look {
        Look::Up => [0xff, 0xc9, 0xd7],
        Look::Down => [0x9e, 0x9e, 0x9e],
        Look::Problem => [0xe0, 0x55, 0x55],
    };
    let (center, radius) = (size as f32 / 2.0, size as f32 * 13.0 / 32.0);
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let distance = (x as f32 + 0.5 - center).hypot(y as f32 + 0.5 - center);
            let coverage = (radius - distance + 0.5).clamp(0.0, 1.0);
            rgba.extend([r, g, b, (coverage * 255.0).round() as u8]);
        }
    }
    rgba
}

/// Determines the tray icon appearance from the current connection summaries.
pub fn determine_look(connections: &[ConnectionSummary]) -> Look {
    if connections
        .iter()
        .any(|s| s.revoked || s.last_error.is_some())
    {
        Look::Problem
    } else if connections
        .iter()
        .any(|s| s.state == ConnectionState::Connected)
    {
        Look::Up
    } else {
        Look::Down
    }
}

// --- Menu builder ---

fn format_bytes(n: u64) -> String {
    match n {
        0..1_000 => format!("{n} B"),
        1_000..1_000_000 => format!("{:.1} kB", n as f64 / 1e3),
        1_000_000..1_000_000_000 => format!("{:.1} MB", n as f64 / 1e6),
        _ => format!("{:.1} GB", n as f64 / 1e9),
    }
}

/// Builds status text lines for a connection: device name, local tunnel state, and server state.
fn build_status_lines(s: &ConnectionSummary, status: Option<&ConnectionStatus>) -> Vec<Entry> {
    let mut lines = vec![
        Entry::Text(ConnectionInMenu::from_summary(s).label()),
        Entry::Text(s.describe_state()),
    ];
    if let Some(e) = &s.last_error {
        lines.push(Entry::Text(format!("Problem: {e}")));
    }
    let Some(status) = status else { return lines };
    let format_time =
        |t: chrono::DateTime<chrono::Utc>| t.with_timezone(&Local).format("%H:%M:%S").to_string();
    if let Some(peer) = status.local.as_ref().and_then(|l| l.peers.first()) {
        let handshake = peer.handshake.map_or("no handshake yet".into(), |t| {
            format!("handshake {}", format_time(t))
        });
        let traffic = format!(
            "{} in, {} out",
            format_bytes(peer.receive_bytes),
            format_bytes(peer.transmit_bytes)
        );
        lines.push(Entry::Text(format!(
            "This computer: {handshake}, {traffic}"
        )));
    }
    match (&status.server, &status.server_error) {
        (Some(server), _) if server.peer_present => {
            let handshake = server.handshake.map_or("no handshake yet".into(), |t| {
                format!("handshake {}", format_time(t))
            });
            lines.push(Entry::Text(format!("Server: {handshake}")));
        }
        (Some(_), _) => lines.push(Entry::Text("Server: no peer for this device".into())),
        (None, Some(e)) => lines.push(Entry::Text(format!("Server: {e}"))),
        (None, None) => {}
    }
    lines
}

/// Builds the tray menu: a submenu per connection, then global items.
pub fn build_menu(
    connections: &[ConnectionSummary],
    statuses: &BTreeMap<String, ConnectionStatus>,
) -> Vec<Entry> {
    let mut menu = Vec::new();
    for s in connections {
        let connection = ConnectionInMenu::from_summary(s);
        let mut entries = build_status_lines(s, statuses.get(&s.name));
        entries.push(Entry::Separator);
        if !s.revoked {
            entries.push(if s.state.wants_connection() {
                Entry::Item {
                    label: "Disconnect".into(),
                    action: Action::Disconnect(connection.clone()),
                    checked: None,
                }
            } else {
                Entry::Item {
                    label: "Connect".into(),
                    action: Action::Connect(connection.clone()),
                    checked: None,
                }
            });
            if s.profiles.len() > 1 || s.custom_allowed_ips.is_some() {
                let mut profiles: Vec<Entry> = s
                    .profiles
                    .iter()
                    .map(|p| Entry::Item {
                        label: p.name.clone(),
                        action: Action::SetProfile {
                            connection: connection.clone(),
                            profile: Some(p.id.clone()),
                            allowed_ips: None,
                        },
                        checked: Some(s.profile_id.as_deref() == Some(&p.id)),
                    })
                    .collect();
                if let Some(routes) = &s.custom_allowed_ips {
                    profiles.push(Entry::Item {
                        label: "Custom routes".into(),
                        action: Action::SetProfile {
                            connection: connection.clone(),
                            profile: None,
                            allowed_ips: Some(routes.clone()),
                        },
                        checked: Some(s.profile_id.is_none()),
                    });
                }
                push_submenu(&mut entries, "Routes", profiles);
            }
            entries.push(Entry::Item {
                label: "Use controller DNS".into(),
                action: Action::SetDns {
                    connection: connection.clone(),
                    enabled: s.no_dns,
                },
                checked: Some(!s.no_dns),
            });
            entries.push(Entry::Item {
                label: "Rotate key".into(),
                action: Action::RotateKey(connection.clone()),
                checked: None,
            });
            entries.push(Entry::Item {
                label: "Rotate preshared key".into(),
                action: Action::RotatePsk(connection.clone()),
                checked: None,
            });
        }
        entries.push(Entry::Item {
            label: "Open portal".into(),
            action: Action::OpenPortal(s.portal.clone()),
            checked: None,
        });
        entries.push(Entry::Item {
            label: "Log out…".into(),
            action: Action::Logout(connection),
            checked: None,
        });
        menu.push(Entry::Submenu {
            label: s.device.name.clone(),
            checked: Some(s.state == ConnectionState::Connected),
            entries,
        });
    }
    if connections.is_empty() {
        menu.push(Entry::Text("No connections".into()));
    }
    menu.push(Entry::Separator);
    let mut portals: Vec<&str> = connections.iter().map(|s| s.portal.as_str()).collect();
    portals.sort_unstable();
    portals.dedup();
    let mut add: Vec<Entry> = portals
        .into_iter()
        .map(|portal| Entry::Item {
            label: format!("Log in to {portal}"),
            action: Action::Login(portal.into()),
            checked: None,
        })
        .collect();
    add.push(Entry::Item {
        label: "From clipboard".into(),
        action: Action::AddFromClipboard,
        checked: None,
    });
    push_submenu(&mut menu, "Add connection", add);
    menu.push(Entry::Item {
        label: "Exit".into(),
        action: Action::Exit,
        checked: None,
    });
    menu
}

fn push_submenu(entries: &mut Vec<Entry>, label: &str, children: Vec<Entry>) {
    entries.push(Entry::Submenu {
        label: label.into(),
        checked: None,
        entries: children,
    });
}

// --- Clipboard and link parsing ---

/// Returns true if `text` is a valid HTTP or HTTPS portal URL without user credentials.
fn is_valid_portal(text: &str) -> bool {
    Url::parse(text).is_ok_and(|u| {
        matches!(u.scheme(), "http" | "https")
            && u.has_host()
            && u.username().is_empty()
            && u.password().is_none()
    })
}

/// Returns true if `text` contains any control characters.
fn contains_control_chars(text: &str) -> bool {
    text.chars().any(char::is_control)
}

/// Extracts the host and optional non-default port from a portal URL.
pub fn extract_portal_host(portal: &str) -> Option<String> {
    let url = Url::parse(portal).ok()?;
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.into(),
    })
}

/// Parses a portal URL or `ito-agent login` command from clipboard text.
pub fn parse_clipboard(text: &str) -> Option<(String, Option<String>)> {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.iter().any(|w| contains_control_chars(w)) {
        return None;
    }
    match words[..] {
        ["ito-agent", "login", portal, "--device", device, ..] if is_valid_portal(portal) => {
            Some((portal.into(), Some(device.into())))
        }
        ["ito-agent", "login", portal, ..] | [portal] if is_valid_portal(portal) => {
            Some((portal.into(), None))
        }
        _ => None,
    }
}

/// Parses an `ito-wg://connect?portal=…&device=…` URL into the portal URL and optional device ID.
pub fn parse_link(link: &str) -> Option<(String, Option<String>)> {
    if contains_control_chars(link) {
        return None;
    }
    let link = Url::parse(link).ok()?;
    // `Url::parse` lowercases the scheme but preserves host casing for custom schemes.
    let connect = link.scheme() == "ito-wg"
        && link.host_str()?.eq_ignore_ascii_case("connect")
        && matches!(link.path(), "" | "/");
    if !connect {
        return None;
    }
    let mut portal = None;
    let mut device = None;
    for (key, value) in link.query_pairs() {
        match &*key {
            "portal" => portal = Some(value.into_owned()),
            "device" => device = Some(value.into_owned()),
            _ => {}
        }
    }
    // Percent-decoding can reintroduce control characters.
    let portal = portal.filter(|p| is_valid_portal(p) && !contains_control_chars(p))?;
    if device.as_deref().is_some_and(contains_control_chars) {
        return None;
    }
    Some((portal, device))
}

/// Decodes UTF-16 clipboard text up to the first NUL terminator.
pub fn decode_clipboard_text(units: &[u16]) -> Option<String> {
    let end = units.iter().position(|&c| c == 0)?;
    String::from_utf16(&units[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use ito_agent_core::client::DeviceInfo;
    use ito_shared::{
        api::{DeviceStatus, RouteProfile},
        dump::{Link, Peer},
    };

    fn build_summary(name: &str, connected: bool) -> ConnectionSummary {
        let build_profile = |id: &str| RouteProfile {
            id: id.into(),
            name: id.to_uppercase(),
            allowed_ips: vec![],
        };
        ConnectionSummary {
            name: name.into(),
            portal: "https://vpn.test".into(),
            device: DeviceInfo {
                id: "d".into(),
                name: "Laptop".into(),
                note: String::new(),
                dns_name: None,
                interface_id: "wg0".into(),
                revision: 1,
                key_expires_at: None,
                disabled_reason: None,
            },
            state: if connected {
                ConnectionState::Connected
            } else {
                ConnectionState::Disconnected
            },
            no_dns: false,
            revoked: false,
            profile_id: Some("vpn".into()),
            custom_allowed_ips: None,
            profiles: vec![build_profile("vpn"), build_profile("all")],
            disabled_reason: None,
            last_error: None,
        }
    }

    fn collect_items(entries: &[Entry]) -> Vec<(String, Option<bool>)> {
        entries
            .iter()
            .flat_map(|e| match e {
                Entry::Item { label, checked, .. } => vec![(label.clone(), *checked)],
                Entry::Submenu { entries, .. } => collect_items(entries),
                _ => vec![],
            })
            .collect()
    }

    /// Collects the labels of the items, including those in submenus, in `entries`.
    fn collect_labels(entries: &[Entry]) -> Vec<String> {
        collect_items(entries).into_iter().map(|(l, _)| l).collect()
    }

    /// Finds the entries of the submenu labeled `label` in `menu`.
    fn find_submenu<'a>(menu: &'a [Entry], label: &str) -> &'a [Entry] {
        menu.iter()
            .find_map(|e| match e {
                Entry::Submenu {
                    label: l, entries, ..
                } if l == label => Some(entries.as_slice()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no submenu {label} in {menu:?}"))
    }

    /// Builds the status of `s` with a local peer and the controller's view.
    fn build_status(
        s: &ConnectionSummary,
        local_peer: Peer,
        server: Option<DeviceStatus>,
        server_error: Option<&str>,
    ) -> ConnectionStatus {
        ConnectionStatus {
            summary: s.clone(),
            local: Some(Link {
                peers: vec![local_peer],
                ..Link::default()
            }),
            server,
            server_error: server_error.map(Into::into),
        }
    }

    fn build_server_status(peer_present: bool, handshake: Option<DateTime<Utc>>) -> DeviceStatus {
        DeviceStatus {
            device_id: "d".into(),
            interface_id: "wg0".into(),
            observed_at: DateTime::UNIX_EPOCH,
            interface_present: true,
            interface_up: true,
            peer_present,
            addresses: vec![],
            allowed_ips: None,
            endpoint: None,
            handshake,
            receive_bytes: 0,
            transmit_bytes: 0,
        }
    }

    #[test]
    fn connected_menus_offer_disconnecting_profiles_dns_and_key_rotation() {
        let menu = build_menu(&[build_summary("ito-a", true)], &BTreeMap::new());
        assert_eq!(
            collect_items(find_submenu(&menu, "Laptop")),
            [
                ("Disconnect".into(), None),
                ("VPN".into(), Some(true)),
                ("ALL".into(), Some(false)),
                ("Use controller DNS".into(), Some(true)),
                ("Rotate key".into(), None),
                ("Rotate preshared key".into(), None),
                ("Open portal".into(), None),
                ("Log out…".into(), None),
            ]
        );
    }

    #[test]
    fn revoked_menus_offer_only_the_portal_and_logging_out() {
        let mut revoked = build_summary("ito-a", false);
        revoked.revoked = true;
        let menu = build_menu(&[revoked], &BTreeMap::new());
        let labels = collect_labels(find_submenu(&menu, "Laptop"));
        assert_eq!(labels, ["Open portal", "Log out…"]);
    }

    #[test]
    fn adding_connections_offers_each_portal_once_and_the_clipboard() {
        let mut other = build_summary("ito-c", false);
        other.portal = "https://another.test".into();
        let connections = [
            build_summary("ito-a", true),
            other,
            build_summary("ito-b", false),
        ];
        let menu = build_menu(&connections, &BTreeMap::new());
        assert_eq!(
            collect_labels(find_submenu(&menu, "Add connection")),
            [
                "Log in to https://another.test",
                "Log in to https://vpn.test",
                "From clipboard"
            ]
        );
    }

    #[test]
    fn the_icon_shows_problems_before_connections() {
        let connected = build_summary("ito-a", true);
        let disconnected = build_summary("ito-b", false);
        let mut revoked = build_summary("ito-c", false);
        revoked.revoked = true;
        let mut failing = build_summary("ito-d", false);
        failing.last_error = Some("offline".into());
        for (case, connections, expected) in [
            ("nothing", vec![], Look::Down),
            ("disconnected", vec![disconnected.clone()], Look::Down),
            ("connected", vec![disconnected, connected.clone()], Look::Up),
            ("revoked", vec![connected.clone(), revoked], Look::Problem),
            ("failing", vec![connected, failing], Look::Problem),
        ] {
            assert_eq!(determine_look(&connections), expected, "{case}");
        }
    }

    #[test]
    fn saved_custom_routes_can_be_selected_alongside_server_profiles() {
        let mut s = build_summary("ito-a", true);
        s.profiles.truncate(1);
        s.custom_allowed_ips = Some(vec!["10.2.0.0/24".into()]);
        for custom in [false, true] {
            s.profile_id = (!custom).then(|| "vpn".into());
            let menu = build_menu(&[s.clone()], &BTreeMap::new());
            let routes = find_submenu(find_submenu(&menu, "Laptop"), "Routes");
            let checks = collect_items(routes);
            assert_eq!(
                checks,
                [
                    ("VPN".into(), Some(!custom)),
                    ("Custom routes".into(), Some(custom))
                ]
            );
            assert!(matches!(&routes[1], Entry::Item {
                action: Action::SetProfile { profile: None, allowed_ips: Some(ips), .. }, ..
            } if ips == s.custom_allowed_ips.as_ref().unwrap()));
        }
    }

    #[test]
    fn byte_counts_use_decimal_units() {
        for (bytes, expected) in [
            (0, "0 B"),
            (999, "999 B"),
            (1_000, "1.0 kB"),
            (1_500_000, "1.5 MB"),
            (2_000_000_000, "2.0 GB"),
        ] {
            assert_eq!(format_bytes(bytes), expected);
        }
    }

    #[test]
    fn status_lines_show_the_local_handshake_and_traffic() {
        let s = build_summary("ito-a", true);
        let handshake = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let time = handshake.with_timezone(&Local).format("%H:%M:%S");
        for (handshake, expected) in [
            (
                Some(handshake),
                format!("This computer: handshake {time}, 1.5 kB in, 999 B out"),
            ),
            (
                None,
                "This computer: no handshake yet, 1.5 kB in, 999 B out".into(),
            ),
        ] {
            let peer = Peer {
                handshake,
                receive_bytes: 1_500,
                transmit_bytes: 999,
                ..Peer::default()
            };
            let lines = build_status_lines(&s, Some(&build_status(&s, peer, None, None)));
            assert!(lines.contains(&Entry::Text(expected.clone())), "{expected}");
        }
    }

    #[test]
    fn status_lines_show_what_the_server_sees() {
        let s = build_summary("ito-a", true);
        for (server, server_error, expected) in [
            (
                Some(build_server_status(true, None)),
                None,
                "Server: no handshake yet",
            ),
            (
                Some(build_server_status(false, None)),
                None,
                "Server: no peer for this device",
            ),
            (None, Some("offline"), "Server: offline"),
        ] {
            let status = build_status(&s, Peer::default(), server, server_error);
            let lines = build_status_lines(&s, Some(&status));
            assert_eq!(lines.last(), Some(&Entry::Text(expected.into())));
        }
    }

    #[test]
    fn clipboard_text_gives_a_portal_and_an_optional_device() {
        for (text, expected) in [
            (
                "ito-agent login https://vpn.test --device d1\r\n",
                Some(("https://vpn.test", Some("d1"))),
            ),
            (" https://vpn.test/ ", Some(("https://vpn.test/", None))),
            (
                "ito-agent login https://vpn.test",
                Some(("https://vpn.test", None)),
            ),
            ("ito-agent enroll https://vpn.test itoa_abc", None),
            ("hello world", None),
            ("https://me@evil.test", None),
            ("https://vpn.test\u{1b}[2J", None),
        ] {
            let expected = expected.map(|(p, d)| (p.to_string(), d.map(String::from)));
            assert_eq!(parse_clipboard(text), expected, "{text:?}");
        }
    }

    #[test]
    fn links_give_a_portal_and_an_optional_device() {
        for (link, expected) in [
            (
                "ito-wg://connect?portal=https%3A%2F%2Fvpn.test&device=d1",
                Some(("https://vpn.test", Some("d1"))),
            ),
            (
                "ITO-WG://Connect/?x&portal=https://vpn.test&device=d%201#top",
                Some(("https://vpn.test", Some("d 1"))),
            ),
            (
                "ito-wg://connect?portal=https://vpn.test",
                Some(("https://vpn.test", None)),
            ),
            ("https://elsewhere", None),
            ("ito-wg://connect/other?portal=https://vpn.test", None),
            ("ito-wg://connect?portal=https://", None),
        ] {
            let expected = expected.map(|(p, d)| (p.to_string(), d.map(String::from)));
            assert_eq!(parse_link(link), expected, "{link}");
        }
    }

    #[test]
    fn hostile_links_are_refused() {
        for hostile in [
            "ito-wg://connect?portal=javascript%3Aalert(1)",
            "ito-wg://connect?portal=https://vpn.test%40evil.test",
            "ito-wg://connect?portal=https://me:pw@evil.test",
            "ito-wg://connect?portal=https://vpn.test%0A.evil.test",
            "ito-wg://connect?portal=https://vpn.test\n.evil.test",
            "ito-wg://connect?portal=https://vpn.test&device=d%0D1",
        ] {
            assert_eq!(parse_link(hostile), None, "{hostile}");
        }
    }

    #[test]
    fn portal_hosts_keep_only_non_default_ports() {
        for (portal, expected) in [
            ("https://vpn.test/very/long/path?x=1", "vpn.test"),
            ("http://vpn.test:8000", "vpn.test:8000"),
            ("https://vpn.test:443/", "vpn.test"),
        ] {
            assert_eq!(extract_portal_host(portal).as_deref(), Some(expected));
        }
    }

    #[test]
    fn clipboard_text_requires_a_terminator_within_the_allocation() {
        assert_eq!(decode_clipboard_text(&[65, 0, 66]), Some("A".into()));
        assert_eq!(decode_clipboard_text(&[65, 66]), None);
        assert_eq!(decode_clipboard_text(&[]), None);
        assert_eq!(decode_clipboard_text(&[0xd800, 0]), None);
    }

    #[test]
    fn dot_fills_its_middle_and_clears_its_corners() {
        for size in [16, 20, 24, 32, 256] {
            let rgba = draw_dot(Look::Up, size);
            assert_eq!(rgba.len(), (size * size * 4) as usize);
            let read_alpha = |x: u32, y: u32| rgba[((y * size + x) * 4 + 3) as usize];
            assert_eq!(read_alpha(size / 2, size / 2), 0xff);
            assert_eq!(read_alpha(0, 0), 0);
            // Somewhere on the edge, a pixel is only partly covered.
            assert!(rgba.chunks(4).any(|p| (1..0xff).contains(&p[3])));
        }
    }
}
