//! Portal login ticket generation and verification codes.
//!
//! The agent generates a random secret, hashes it with SHA-256 to form a request ID, and directs
//! the user to the portal's `/connect` page. Once the user approves the request, the agent claims
//! the device using the secret and a newly generated WireGuard public key.

use base64::Engine as _;
use ito_shared::keys::{KeyPair, generate_key_pair};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

/// Pending login state containing the secret and WireGuard key pair held by the agent.
pub struct Login {
    pub portal: String,
    /// Preselected device ID from the portal, or `None` if selected during approval.
    pub device: Option<String>,
    pub(crate) secret: String,
    pub(crate) keys: KeyPair,
    pub ticket: LoginTicket,
    pub(crate) no_dns: bool,
}

/// Login details displayed to the user for approval in the portal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginTicket {
    /// Request ID (lowercase hex SHA-256 of the login secret).
    pub request: String,
    /// Portal `/connect` URL where the user approves this request.
    pub url: String,
    /// Short verification code displayed on both the agent and the approval page (e.g.
    /// `3F9A-1C2E`).
    pub code: String,
    /// Unix timestamp in seconds when the login request was created.
    pub requested_at: u64,
}

impl Login {
    /// Creates a new pending login for `portal`.
    pub fn start(portal: &str, device: Option<&str>, host_name: &str) -> Self {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).expect("operating system random source");
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let request: String = sha2::Sha256::digest(secret.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let portal = portal.trim_end_matches('/').to_string();
        let requested_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let target = match device {
            Some(id) => ("device", id),
            None => ("name", host_name),
        };
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("id", &request)
            .append_pair("t", &requested_at.to_string())
            .append_pair(target.0, target.1)
            .finish();
        let ticket = LoginTicket {
            url: format!("{portal}/connect?{query}"),
            code: format_check_code(&request),
            request,
            requested_at,
        };
        Self {
            portal,
            device: device.map(Into::into),
            secret,
            keys: generate_key_pair(),
            ticket,
            no_dns: false,
        }
    }
}

/// Formats the first 8 hex characters of `request` as `3F9A-1C2E` for the user verification prompt.
pub fn format_check_code(request: &str) -> String {
    let head = request[..8].to_uppercase();
    format!("{}-{}", &head[..4], &head[4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tickets_link_the_connect_page_with_the_request_and_its_time() {
        let t = Login::start("https://vpn.test/", None, "box").ticket;
        let expected = format!(
            "https://vpn.test/connect?id={}&t={}&name=box",
            t.request, t.requested_at
        );
        assert_eq!(t.url, expected);
    }

    #[test]
    fn tickets_preselect_the_device_or_suggest_the_host_name() {
        for (device, host_name, expected_end) in [
            (Some("d-1"), "box", "&device=d-1"),
            (None, "Alice's box", "&name=Alice%27s+box"),
        ] {
            let url = Login::start("https://vpn.test", device, host_name)
                .ticket
                .url;
            assert!(url.ends_with(expected_end), "{url}");
        }
    }

    #[test]
    fn each_login_has_a_new_request_with_its_check_code() {
        let (a, b) = (
            Login::start("https://vpn.test", None, "box"),
            Login::start("https://vpn.test", None, "box"),
        );
        assert_eq!(a.ticket.request.len(), 64);
        assert_eq!(a.ticket.code, format_check_code(&a.ticket.request));
        assert_ne!(a.ticket.request, b.ticket.request);
    }

    #[test]
    fn check_codes_show_the_first_eight_hex_digits() {
        assert_eq!(format_check_code("3f9a1c2e5b"), "3F9A-1C2E");
    }
}
