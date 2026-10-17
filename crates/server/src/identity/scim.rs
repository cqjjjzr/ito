//! SCIM 2.0 user status lookup and canary health verification.

use super::{
    build_idp_error,
    oidc::{OidcHttpClient, discover_provider, read_client_secret},
};
use crate::{
    App,
    config::Scim,
    db::account::IdpStatus,
    error::{Result, format_error_chain},
};
use openidconnect::{ClientId, OAuth2TokenResponse, core::CoreClient};
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use std::time::{Duration, Instant};

async fn fetch_status_token(app: &App, scim: &Scim) -> Result<String> {
    let mut cached = app.identity_cache.status_token.lock().await;
    if let Some((token, until)) = cached.as_ref()
        && Instant::now() < *until
    {
        return Ok(token.clone());
    }
    let client = CoreClient::from_provider_metadata(
        discover_provider(app).await?,
        ClientId::new(scim.client_id.clone()),
        Some(read_client_secret(&scim.secret_file)?),
    );
    let token = client
        .exchange_client_credentials()
        .map_err(build_idp_error)?
        .request_async(&OidcHttpClient(&app.http_client))
        .await
        .map_err(|e| build_idp_error(format_error_chain(&e)))?;
    // Cap the cached token lifetime to 24 hours so large `expires_in` values cannot overflow.
    let lifetime = token
        .expires_in()
        .unwrap_or(Duration::from_secs(60))
        .min(Duration::from_hours(24));
    let value = token.access_token().secret().clone();
    *cached = Some((
        value.clone(),
        Instant::now() + lifetime.saturating_sub(Duration::from_secs(10)),
    ));
    Ok(value)
}

/// SCIM 2.0 `User` resource containing only the fields queried by the controller.
#[derive(Deserialize)]
struct ScimUser {
    id: String,
    /// Whether the user account is active. Defaults to `true` because `active` is optional in
    /// SCIM 2.0.
    #[serde(default = "default_active")]
    active: bool,
}

fn default_active() -> bool {
    true
}

/// Fetches the SCIM `User` with ID `subject`, returning `None` on HTTP 404.
async fn get_user(app: &App, scim: &Scim, subject: &str) -> Result<Option<ScimUser>> {
    let mut url = Url::parse(&scim.url).map_err(build_idp_error)?;
    url.path_segments_mut()
        .map_err(|_| build_idp_error("bad scim.url"))?
        .pop_if_empty()
        .extend(["Users", subject]);
    url.query_pairs_mut().append_pair("attributes", "id,active");
    let response = app
        .http_client
        .get(url)
        .bearer_auth(fetch_status_token(app, scim).await?)
        .header("accept", "application/scim+json")
        .send()
        .await
        .map_err(|e| build_idp_error(format_error_chain(&e)))?;
    match response.status() {
        StatusCode::NOT_FOUND => Ok(None),
        StatusCode::OK => {
            let user: ScimUser = response.json().await.map_err(build_idp_error)?;
            (user.id == subject)
                .then_some(Some(user))
                .ok_or_else(|| build_idp_error("user lookup returned another user"))
        }
        status => Err(build_idp_error(format!("user lookup returned {status}"))),
    }
}

/// Verifies that the configured `health_subject` canary user is still reported as active by SCIM.
/// If an upstream directory outage causes SCIM to return 404 or `active: false` for all users, this
/// check fails and prevents the controller from revoking user accounts.
async fn verify_canary_active(app: &App, scim: &Scim) -> Result<()> {
    let id = &scim.health_subject;
    if id.is_empty() {
        return Ok(());
    }
    match get_user(app, scim, id).await? {
        Some(u) if u.active => Ok(()),
        _ => Err(build_idp_error("health identity is not active")),
    }
}

/// Queries the account status of `subject` over SCIM, confirming negative results against
/// `health_subject` before returning them.
pub async fn lookup(app: &App, scim: &Scim, subject: &str) -> Result<IdpStatus> {
    let status = match get_user(app, scim, subject).await? {
        Some(u) if u.active => return Ok(IdpStatus::Active),
        Some(_) => IdpStatus::Disabled,
        None => IdpStatus::Missing,
    };
    verify_canary_active(app, scim).await?;
    Ok(status)
}

/// Queries the account status of `subject` during OIDC sign-in, or returns `Active` when SCIM is
/// not configured.
pub async fn lookup_at_login(app: &App, subject: &str) -> Result<IdpStatus> {
    match &app.config.scim {
        Some(cfg) => lookup(app, cfg, subject).await,
        None => Ok(IdpStatus::Active),
    }
}
