use super::devices::{
    DeviceView, build_device_views, find_device_account, read_device_status, respond_device,
    respond_device_config,
};
use crate::{
    App,
    db::{Tx, agent_credential, device},
    devices::{self, DeviceKey, Psk},
    error::{Code, Result, conflict, forbidden, invalid, not_found},
    http::{
        extract::{AuthenticatedAgent, IfMatch, JsonBody, build_account_actor},
        secrets,
    },
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use ito_shared::api::{DeviceConfig, DeviceStatus};
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

/// Get its device
#[utoipa::path(get, path = "/agent/device", tag = "agent",
    security(("agent" = [])),
    responses((status = 200, body = DeviceView)))]
pub async fn get_agent_device(
    State(app): State<Arc<App>>,
    agent: AuthenticatedAgent,
) -> Result<Response> {
    respond_device(&app, agent.device).await
}

/// Set or renew its device's key
///
/// Sets or renews the device's WireGuard public key for `key_lifetime`.
#[utoipa::path(post, path = "/agent/key", tag = "agent",
    security(("agent" = [])),
    params(IfMatch), request_body = DeviceKey,
    responses((status = 200, body = DeviceView)))]
pub async fn set_agent_key(
    State(app): State<Arc<App>>,
    agent: AuthenticatedAgent,
    if_match: IfMatch,
    JsonBody(input): JsonBody<DeviceKey>,
) -> Result<Response> {
    let (mut tx, old) = agent.begin(&app).await?;
    if_match.validate(old.revision)?;
    let new = devices::apply_key(
        &mut tx,
        &app.server_keys,
        app.config.key_lifetime,
        &old,
        input,
    )
    .await?;
    let new = devices::save(&mut tx, &old, new).await?;
    tx.audit(&agent.actor(), "device.key", &old.id).await?;
    tx.commit().await?;
    respond_device(&app, new).await
}

/// Set its device's preshared key
#[utoipa::path(put, path = "/agent/psk", tag = "agent",
    security(("agent" = [])),
    params(IfMatch), request_body = Psk,
    responses((status = 200, body = DeviceView)))]
pub async fn set_agent_psk(
    State(app): State<Arc<App>>,
    agent: AuthenticatedAgent,
    if_match: IfMatch,
    JsonBody(input): JsonBody<Psk>,
) -> Result<Response> {
    let (mut tx, old) = agent.begin(&app).await?;
    if_match.validate(old.revision)?;
    let new = devices::save(&mut tx, &old, devices::apply_psk(old.clone(), input)?).await?;
    tx.audit(&agent.actor(), "device.psk", &old.id).await?;
    tx.commit().await?;
    respond_device(&app, new).await
}

/// Get its device's client configuration
///
/// Wait for `ready` to be `true` before bringing up the client tunnel. Pass the returned `ETag` in
/// `If-None-Match` to receive `304 Not Modified` when the configuration has not changed.
#[utoipa::path(get, path = "/agent/config", tag = "agent",
    security(("agent" = [])),
    params(("If-None-Match" = Option<String>, Header, description = "An earlier `ETag` of this response.")),
    responses((status = 200, body = DeviceConfig), (status = 304)))]
pub async fn get_agent_config(
    State(app): State<Arc<App>>,
    agent: AuthenticatedAgent,
    headers: HeaderMap,
) -> Result<Response> {
    respond_device_config(&app, agent.device, &headers).await
}

/// Get its device's kernel status
#[utoipa::path(get, path = "/agent/status", tag = "agent",
    security(("agent" = [])),
    responses((status = 200, body = DeviceStatus)))]
pub async fn get_agent_status(
    State(app): State<Arc<App>>,
    agent: AuthenticatedAgent,
) -> Result<Json<DeviceStatus>> {
    read_device_status(&app, agent.device).await
}

/// Revoke its device
///
/// Clears the device's WireGuard public key and deletes its agent credential, while keeping the
/// device record and its assigned addresses.
#[utoipa::path(post, path = "/agent/revoke", tag = "agent",
    security(("agent" = [])),
    responses((status = 204)))]
pub async fn revoke_agent(
    State(app): State<Arc<App>>,
    agent: AuthenticatedAgent,
) -> Result<StatusCode> {
    let (mut tx, old) = agent.begin(&app).await?;
    let new = devices::revoke(&mut tx, &app.approvals, old.clone()).await?;
    devices::save(&mut tx, &old, new).await?;
    tx.audit(&agent.actor(), "device.revoked", &old.id).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Request body for claiming a device after interactive approval.
#[derive(Deserialize, ToSchema)]
pub struct Claim {
    /// Agent secret (32 random bytes encoded as unpadded base64url) whose SHA-256 hex digest
    /// matches the approved request ID.
    secret: String,
    /// Agent's WireGuard public key in standard base64.
    public_key: String,
    /// Expected device ID when the agent requested a specific device (`ito-agent login --device`).
    /// If the request was approved for a different device, the claim fails with
    /// `claim_device_mismatch` without modifying the approved device.
    #[serde(default)]
    device_id: Option<String>,
}

/// Claimed device and newly issued agent bearer token.
#[derive(Serialize, ToSchema)]
pub struct Claimed {
    /// Bearer token (`itoa_<secret>`) for authenticating subsequent agent requests.
    token: String,
    device: DeviceView,
}

/// Claim an approved device
///
/// Returns `202 Accepted` while waiting for a user to approve the claim request. Once approved,
/// binds `public_key` to the device, replaces its agent credential, and returns `200 OK` with the
/// new bearer token. Repeating the call within 2 minutes of the first claim issues a fresh token
/// so the agent can recover from a lost response.
#[utoipa::path(post, path = "/agent/claim", tag = "agent",
    security(()),
    request_body = Claim,
    responses((status = 200, body = Claimed), (status = 202, description = "Not approved yet.")))]
pub async fn claim_device(
    State(app): State<Arc<App>>,
    JsonBody(input): JsonBody<Claim>,
) -> Result<Response> {
    secrets::is_secret_format(&input.secret)
        .ok_or_else(|| invalid("secret must be 32 bytes of unpadded base64url"))?;
    let request = secrets::digest_sha256(&input.secret);
    // Acquire the database write lock before reading `approvals` so a concurrent device revocation
    // cannot race with a claim in progress.
    let mut tx = app.db.begin_write().await?;
    let Some(approval) = app.approvals.claim(&request, Utc::now()) else {
        return Ok(StatusCode::ACCEPTED.into_response());
    };
    if input
        .device_id
        .is_some_and(|asked| asked != approval.device_id)
    {
        return Err(conflict(Code::ClaimDeviceMismatch));
    }
    let old = device::Entity::find_by_id(&approval.device_id)
        .one(&*tx)
        .await?
        .ok_or_else(not_found)?;
    (!old.deleting).ok_or_else(not_found)?;
    (!old.blocked).ok_or_else(forbidden)?;
    find_device_account(&*tx, &old)
        .await?
        .active()
        .ok_or_else(forbidden)?;
    let key = DeviceKey {
        public_key: Some(input.public_key),
    };
    let lifetime = app.config.key_lifetime;
    let new = devices::apply_key(&mut tx, &app.server_keys, lifetime, &old, key).await?;
    let new = devices::save(&mut tx, &old, new).await?;
    let token = replace_agent_credential(&tx, &new.id).await?;
    let actor = build_account_actor(&approval.account_id);
    tx.audit(&actor, "device.claimed", &new.id).await?;
    tx.commit().await?;
    let mut views = build_device_views(&app, vec![new]).await?;
    let device = views.pop().expect("one device");
    Ok(Json(Claimed { token, device }).into_response())
}

/// Replaces any existing agent credential on `device_id` with a newly generated one and returns
/// the bearer token (`itoa_<secret>`).
async fn replace_agent_credential(tx: &Tx, device_id: &str) -> Result<String> {
    devices::delete_agent_credentials(tx, device_id).await?;
    let secret = secrets::generate_secret();
    let c = agent_credential::Model {
        id: secrets::digest_sha256(&secret),
        device_id: device_id.into(),
        created_at: Utc::now(),
    };
    tx.insert::<agent_credential::ActiveModel>(c).await?;
    Ok(format!("itoa_{secret}"))
}
