//! HTTP client for `/api/v1/agent` endpoints authenticated with a device bearer credential.

use chrono::{DateTime, Utc};
use ito_shared::api::{DeviceConfig, DeviceStatus, DisabledReason};
use reqwest::{Method, StatusCode, header};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{fmt, time::Duration};

/// Device metadata returned by the controller's agent API.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub note: String,
    pub dns_name: Option<String>,
    pub interface_id: String,
    pub revision: i64,
    pub key_expires_at: Option<DateTime<Utc>>,
    pub disabled_reason: Option<DisabledReason>,
}

#[derive(Debug)]
pub enum ClientError {
    /// The agent credential was rejected (`401 Unauthorized`) because the device was revoked,
    /// blocked, or deleted, its account became inactive, or a newer credential replaced it.
    Revoked,
    /// The controller returned an RFC 9457 Problem Details error response.
    Problem {
        status: u16,
        title: String,
        detail: Option<String>,
    },
    /// The controller could not be reached: no connection, a TLS failure or a timeout.
    Network(String),
    /// The portal answered with something other than the controller's API, such as a web page from
    /// a proxy or a config the agent cannot use.
    Response(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Revoked => f.write_str("the agent credential no longer works"),
            Self::Problem { title, detail, .. } => match detail {
                Some(detail) => write!(f, "{title} {detail}"),
                None => f.write_str(title),
            },
            Self::Network(e) => write!(f, "controller unreachable: {e}"),
            Self::Response(e) => write!(f, "unexpected answer from the controller: {e}"),
        }
    }
}

/// HTTP client for a single device connection to an Ito portal.
pub struct Client {
    http: reqwest::Client,
    /// Base URL `<portal>/api/v1`.
    base: String,
    token: String,
}

impl Client {
    /// Creates a client for `portal` (such as `https://vpn.example.com`) authenticating with bearer
    /// `token` (`itoa_<secret>`).
    pub fn new(portal: &str, token: &str) -> Result<Self, ClientError> {
        let url = reqwest::Url::parse(portal)
            .map_err(|e| ClientError::Network(format!("{portal}: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ClientError::Network(format!(
                "{portal}: not an http or https URL"
            )));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| ClientError::Network(e.to_string()))?;
        Ok(Self {
            http,
            base: format!("{}/api/v1", portal.trim_end_matches('/')),
            token: token.into(),
        })
    }

    /// Sends an HTTP request with optional `If-Match` (`revision`) and `If-None-Match` (`etag`)
    /// headers.
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        revision: Option<i64>,
        etag: Option<&str>,
    ) -> Result<reqwest::Response, ClientError> {
        let url = format!("{}{path}", self.base);
        let mut request = self.http.request(method, url);
        if !self.token.is_empty() {
            request = request.bearer_auth(&self.token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        if let Some(revision) = revision {
            request = request.header(header::IF_MATCH, format!("\"{revision}\""));
        }
        if let Some(etag) = etag {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        let response = request
            .send()
            .await
            .map_err(|e| ClientError::Network(format_error_chain(&e)))?;
        let status = response.status();
        if status.is_success() || status == StatusCode::NOT_MODIFIED {
            return Ok(response);
        }
        if status == StatusCode::UNAUTHORIZED {
            return Err(ClientError::Revoked);
        }
        let problem: Value = response.json().await.unwrap_or_default();
        let reason = status.canonical_reason().unwrap_or_default();
        Err(ClientError::Problem {
            status: status.as_u16(),
            title: problem["title"].as_str().unwrap_or(reason).into(),
            detail: problem["detail"].as_str().map(Into::into),
        })
    }

    /// Decodes the JSON response body.
    ///
    /// Decode errors report only the HTTP status, media type, and parser line/column, never the
    /// body: the agent runs as root and the portal may be any address a user gives, so repeating
    /// the body would let that user read what only root can reach.
    async fn decode_json<T: DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, ClientError> {
        let path = response.url().path().to_string();
        let status = response.status();
        let media_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .unwrap_or("no media type")
            .to_string();
        let body = response
            .bytes()
            .await
            .map_err(|e| ClientError::Network(format_error_chain(&e)))?;
        serde_json::from_slice(&body).map_err(|e| {
            ClientError::Response(format!(
                "{path} answered {status} with {media_type}, not the expected JSON ({:?} error at \
                 line {}, column {})",
                e.classify(),
                e.line(),
                e.column()
            ))
        })
    }

    pub async fn fetch_device(&self) -> Result<DeviceInfo, ClientError> {
        let response = self.send(Method::GET, "/agent/device", None, None, None);
        Self::decode_json(response.await?).await
    }

    /// Fetches the device configuration and its `ETag`, returning `None` if the server responds
    /// with `304 Not Modified`.
    pub async fn fetch_config(
        &self,
        etag: Option<&str>,
    ) -> Result<Option<(DeviceConfig, String)>, ClientError> {
        let response = self
            .send(Method::GET, "/agent/config", None, None, etag)
            .await?;
        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(None);
        }
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let config: DeviceConfig = Self::decode_json(response).await?;
        config
            .validate()
            .map_err(|e| ClientError::Response(format!("unusable config: {e}")))?;
        Ok(Some((config, etag)))
    }

    /// Fetches the live peer status observed on the controller's WireGuard interface.
    pub async fn fetch_status(&self) -> Result<DeviceStatus, ClientError> {
        let response = self.send(Method::GET, "/agent/status", None, None, None);
        Self::decode_json(response.await?).await
    }

    /// Sets a new public key for the device, or renews the existing key when `public_key` is
    /// `None`.
    pub async fn set_key(
        &self,
        revision: i64,
        public_key: Option<&str>,
    ) -> Result<DeviceInfo, ClientError> {
        let body = json!({ "public_key": public_key });
        let response = self.send(Method::POST, "/agent/key", Some(body), Some(revision), None);
        Self::decode_json(response.await?).await
    }

    /// Requests that the controller generate a new preshared key for the device.
    pub async fn generate_psk(&self, revision: i64) -> Result<DeviceInfo, ClientError> {
        let body = json!({ "generate": true });
        let response = self.send(Method::PUT, "/agent/psk", Some(body), Some(revision), None);
        Self::decode_json(response.await?).await
    }

    /// Polls `/api/v1/agent/claim` with `secret` and `public_key`. Returns `Ok(None)` while waiting
    /// for user approval (`202 Accepted`), or the new bearer token and [`DeviceInfo`] once
    /// approved. With `device_id`, the controller refuses an approval for any other device.
    pub async fn claim(
        &self,
        secret: &str,
        public_key: &str,
        device_id: Option<&str>,
    ) -> Result<Option<(String, DeviceInfo)>, ClientError> {
        let body = json!({ "secret": secret, "public_key": public_key, "device_id": device_id });
        let response = self
            .send(Method::POST, "/agent/claim", Some(body), None, None)
            .await?;
        if response.status() == StatusCode::ACCEPTED {
            return Ok(None);
        }
        #[derive(Deserialize)]
        struct ClaimedResponse {
            token: String,
            device: DeviceInfo,
        }
        let claimed: ClaimedResponse = Self::decode_json(response).await?;
        Ok(Some((claimed.token, claimed.device)))
    }

    /// Revokes the device's public key and agent credential while keeping the device record.
    pub async fn revoke(&self) -> Result<(), ClientError> {
        self.send(Method::POST, "/agent/revoke", None, None, None)
            .await
            .map(drop)
    }
}

/// Formats `e` and its full `source()` chain into a single colon-separated string.
fn format_error_chain(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(e) = source {
        text = format!("{text}: {e}");
        source = e.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::tests::build_sample_config;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{any, header, method, path},
    };

    /// Builds the controller's JSON for device `d` at revision 1.
    fn build_device_json() -> Value {
        json!({
            "id": "d", "name": "laptop", "note": "", "dns_name": null, "interface_id": "wg0",
            "revision": 1, "key_expires_at": null, "disabled_reason": null,
        })
    }

    /// Starts a controller that answers every request with `response`, and a client for it.
    async fn start_controller(response: ResponseTemplate) -> (MockServer, Client) {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(response)
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), "itoa_x").unwrap();
        (server, client)
    }

    #[tokio::test]
    async fn unauthorized_answers_mean_the_credential_was_revoked() {
        let (_server, client) = start_controller(ResponseTemplate::new(401)).await;
        assert!(matches!(
            client.fetch_device().await,
            Err(ClientError::Revoked)
        ));
    }

    #[tokio::test]
    async fn problems_report_their_status_and_title_with_detail_or_reason_phrase() {
        let conflict = json!({ "title": "Conflict", "detail": "The revision changed." });
        for (response, expected_status, expected_text) in [
            (
                ResponseTemplate::new(409).set_body_json(conflict),
                409,
                "Conflict The revision changed.",
            ),
            (
                ResponseTemplate::new(400).set_body_json(json!({ "title": "Bad key" })),
                400,
                "Bad key",
            ),
            (ResponseTemplate::new(500), 500, "Internal Server Error"),
        ] {
            let (_server, client) = start_controller(response).await;
            let Err(e @ ClientError::Problem { status, .. }) = client.fetch_device().await else {
                panic!("{expected_text}: no problem reported");
            };
            assert_eq!(status, expected_status, "{expected_text}");
            assert_eq!(e.to_string(), expected_text);
        }
    }

    #[tokio::test]
    async fn requests_carry_the_bearer_credential() {
        let server = MockServer::start().await;
        Mock::given(header("authorization", "Bearer itoa_x"))
            .respond_with(ResponseTemplate::new(200).set_body_json(build_device_json()))
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), "itoa_x").unwrap();
        client.fetch_device().await.unwrap();
    }

    #[tokio::test]
    async fn writes_send_the_revision_as_if_match() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api/v1/agent/psk"))
            .and(header("if-match", "\"7\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(build_device_json()))
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), "itoa_x").unwrap();
        client.generate_psk(7).await.unwrap();
    }

    #[tokio::test]
    async fn config_fetches_send_the_etag_and_accept_not_modified() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/agent/config"))
            .and(header("if-none-match", "\"e1\""))
            .respond_with(ResponseTemplate::new(304))
            .mount(&server)
            .await;
        let client = Client::new(&server.uri(), "itoa_x").unwrap();
        assert!(matches!(
            client.fetch_config(Some("\"e1\"")).await,
            Ok(None)
        ));
    }

    #[tokio::test]
    async fn fetched_configs_come_with_their_etag() {
        let response = ResponseTemplate::new(200)
            .set_body_json(build_sample_config())
            .insert_header("etag", "\"e2\"");
        let (_server, client) = start_controller(response).await;
        let Ok(Some((config, etag))) = client.fetch_config(None).await else {
            panic!("no config fetched");
        };
        assert_eq!(config, build_sample_config());
        assert_eq!(etag, "\"e2\"");
    }

    #[tokio::test]
    async fn unusable_configs_are_refused() {
        let mut config = build_sample_config();
        config.endpoint.push_str("\nPostUp = calc");
        let response = ResponseTemplate::new(200).set_body_json(config);
        let (_server, client) = start_controller(response).await;
        let Err(ClientError::Response(e)) = client.fetch_config(None).await else {
            panic!("an unusable config was taken");
        };
        assert!(e.starts_with("unusable config: endpoint"), "{e}");
    }

    #[tokio::test]
    async fn answers_that_are_not_json_are_reported_without_their_body() {
        let page = ResponseTemplate::new(200).set_body_raw("<html>secret</html>", "text/html");
        let (_server, client) = start_controller(page).await;
        let Err(ClientError::Response(e)) = client.fetch_device().await else {
            panic!("a web page was taken for a device");
        };
        assert!(e.starts_with("/api/v1/agent/device answered 200 OK with text/html"));
        assert!(!e.contains("secret"), "{e}");
    }

    #[tokio::test]
    async fn pending_claims_wait_for_approval() {
        let (_server, client) = start_controller(ResponseTemplate::new(202)).await;
        assert!(matches!(client.claim("s", "k", None).await, Ok(None)));
    }

    #[test]
    fn portals_other_than_http_urls_are_refused() {
        for portal in ["ftp://vpn.test", "file:///etc/passwd", "vpn.test"] {
            let refused = Client::new(portal, "itoa_x");
            assert!(matches!(refused, Err(ClientError::Network(_))), "{portal}");
        }
    }
}
