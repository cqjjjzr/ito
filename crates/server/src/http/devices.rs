use crate::{
    App,
    addressing::{self, Addresses},
    approvals,
    db::*,
    devices::{self, DeviceKey, Psk, Settings},
    error::{Code, Result, conflict, forbidden, invalid, not_found, unavailable},
    http::{
        extract::{
            AuthenticatedAdmin, AuthenticatedUser, IfMatch, JsonBody, OptionalIfMatch,
            respond_tagged,
        },
        interfaces::build_dns_search,
        secrets,
    },
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use ito_shared::api::{DeviceConfig, DeviceStatus, DisabledReason};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use utoipa::ToSchema;

// --- Device views and lookups ---

/// Device record combined with the reason it is currently disabled, if any.
#[derive(Serialize, ToSchema)]
#[schema(as = Device)]
pub struct DeviceView {
    #[serde(flatten)]
    device: device::Model,
    /// Reason the device's peer is excluded from the kernel, or `null` when enabled.
    disabled_reason: Option<DisabledReason>,
}

/// Builds `DeviceView` values for `devices`, querying their owning accounts in a single batch.
pub(super) async fn build_device_views(
    app: &App,
    devices: Vec<device::Model>,
) -> Result<Vec<DeviceView>> {
    let account_ids: Vec<&String> = devices.iter().map(|d| &d.account_id).collect();
    let accounts: BTreeMap<String, account::Model> = account::Entity::find()
        .filter(account::Column::Id.is_in(account_ids))
        .all(&app.db.conn)
        .await?
        .into_iter()
        .map(|a| (a.id.clone(), a))
        .collect();
    let now = Utc::now();
    devices
        .into_iter()
        .map(|d| {
            let a = accounts.get(&d.account_id).ok_or_else(not_found)?;
            let disabled_reason = devices::determine_disabled_reason(&d, &app.config, a, now);
            Ok(DeviceView {
                device: d,
                disabled_reason,
            })
        })
        .collect()
}

/// Responds with the device view tagged with its revision `ETag`.
pub(super) async fn respond_device(app: &App, d: device::Model) -> Result<Response> {
    let revision = d.revision;
    let mut views = build_device_views(app, vec![d]).await?;
    Ok(respond_tagged(revision, views.pop().expect("one device")))
}

async fn find_owned_device(
    c: &impl ConnectionTrait,
    user: &AuthenticatedUser,
    id: &str,
) -> Result<device::Model> {
    device::Entity::find_by_id(id)
        .one(c)
        .await?
        .filter(|d| user.owns(&d.account_id))
        .ok_or_else(not_found)
}

pub(super) async fn find_device_account(
    c: &impl ConnectionTrait,
    d: &device::Model,
) -> Result<account::Model> {
    account::Entity::find_by_id(&d.account_id)
        .one(c)
        .await?
        .ok_or_else(not_found)
}

// --- Device CRUD and route mutations ---

/// List devices
///
/// Members see their own devices; administrators see all devices.
#[utoipa::path(get, path = "/devices", tag = "devices",
    security(("session" = [])),
    responses((status = 200, body = Vec<DeviceView>)))]
pub async fn list_devices(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<DeviceView>>> {
    let mut find = device::Entity::find();
    if !user.admin {
        find = find.filter(device::Column::AccountId.eq(&user.account_id));
    }
    let devices = find.all(&app.db.conn).await?;
    Ok(Json(build_device_views(&app, devices).await?))
}

/// Get a device
#[utoipa::path(get, path = "/devices/{id}", tag = "devices",
    security(("session" = [])),
    responses((status = 200, body = DeviceView)))]
pub async fn get_device(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Response> {
    let d = find_owned_device(&app.db.conn, &user, &id).await?;
    respond_device(&app, d).await
}

/// Parameters for creating a new device.
#[derive(Deserialize, ToSchema)]
pub struct NewDevice {
    /// Owning account ID. Only administrators may specify another account; defaults to the
    /// signed-in user's account.
    account_id: Option<String>,
    interface_id: String,
    name: String,
    /// Optional single-label DNS name to publish in the interface's `dns_zone`.
    dns_name: Option<String>,
    #[serde(flatten)]
    addresses: Addresses,
}

/// Create a device
///
/// When both `addresses` and `allocate_addresses` are empty, the server automatically allocates one
/// free host address in each IP family that has available pool space and quota.
#[utoipa::path(post, path = "/devices", tag = "devices",
    security(("session" = [], "csrf" = [])),
    request_body = NewDevice,
    responses((status = 201, body = DeviceView)))]
pub async fn create_device(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    JsonBody(input): JsonBody<NewDevice>,
) -> Result<Response> {
    let account_id = input.account_id.unwrap_or_else(|| user.account_id.clone());
    user.owns(&account_id).ok_or_else(forbidden)?;
    let mut tx = user.begin(&app).await?;
    let a = account::Entity::find_by_id(&account_id)
        .one(&*tx)
        .await?
        .ok_or_else(not_found)?;
    a.active().ok_or_else(forbidden)?;
    (app.config.interfaces.contains_key(&input.interface_id)).ok_or_else(not_found)?;
    let mut d = device::Model {
        id: generate_id(),
        account_id,
        interface_id: input.interface_id,
        name: String::new(),
        note: String::new(),
        dns_name: None,
        preshared_key: String::new(),
        public_key: None,
        key_expires_at: None,
        grants: Strings::default(),
        client_addresses: Strings::default(),
        extra_allowed_ips: Strings::default(),
        paused: false,
        blocked: false,
        deleting: false,
        revision: 1,
        applied_revision: 0,
        applied_enabled: false,
        apply_error: String::new(),
        created_at: Utc::now(),
    };
    addressing::assign(&tx, &app.config, &mut d, &a, input.addresses).await?;
    let settings = Settings {
        name: Some(input.name),
        dns_name: input.dns_name,
        ..Settings::default()
    };
    let d = devices::apply_settings(&tx, &app.config, d, settings).await?;
    tx.insert::<device::ActiveModel>(d.clone()).await?;
    devices::notify(&mut tx, None, Some(&d));
    tx.audit(&user.actor(), "device.created", &d.id).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, respond_device(&app, d).await?).into_response())
}

/// Change a device's settings
#[utoipa::path(patch, path = "/devices/{id}", tag = "devices",
    security(("session" = [], "csrf" = [])),
    params(IfMatch), request_body = Settings,
    responses((status = 200, body = DeviceView)))]
pub async fn patch_device(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    if_match: IfMatch,
    JsonBody(input): JsonBody<Settings>,
) -> Result<Response> {
    let mut tx = user.begin(&app).await?;
    let old = find_owned_device(&*tx, &user, &id).await?;
    if_match.validate(old.revision)?;
    let new = devices::apply_settings(&tx, &app.config, old.clone(), input).await?;
    let new = devices::save(&mut tx, &old, new).await?;
    tx.audit(&user.actor(), "device.updated", &id).await?;
    tx.commit().await?;
    respond_device(&app, new).await
}

/// Set a device's preshared key
#[utoipa::path(put, path = "/devices/{id}/psk", tag = "devices",
    security(("session" = [], "csrf" = [])),
    params(IfMatch), request_body = Psk,
    responses((status = 200, body = DeviceView)))]
pub async fn set_device_psk(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    if_match: IfMatch,
    JsonBody(input): JsonBody<Psk>,
) -> Result<Response> {
    let mut tx = user.begin(&app).await?;
    let old = find_owned_device(&*tx, &user, &id).await?;
    if_match.validate(old.revision)?;
    (!old.blocked || user.admin).ok_or_else(forbidden)?;
    let new = devices::save(&mut tx, &old, devices::apply_psk(old.clone(), input)?).await?;
    tx.audit(&user.actor(), "device.psk", &id).await?;
    tx.commit().await?;
    respond_device(&app, new).await
}

/// Set a device's addresses
#[utoipa::path(put, path = "/devices/{id}/addresses", tag = "devices",
    security(("session" = [], "csrf" = [])),
    params(IfMatch), request_body = Addresses,
    responses((status = 200, body = DeviceView)))]
pub async fn set_device_addresses(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    if_match: IfMatch,
    JsonBody(input): JsonBody<Addresses>,
) -> Result<Response> {
    let mut tx = user.begin(&app).await?;
    let old = find_owned_device(&*tx, &user, &id).await?;
    if_match.validate(old.revision)?;
    (!old.deleting).ok_or_else(not_found)?;
    (!old.blocked || user.admin).ok_or_else(forbidden)?;
    let a = find_device_account(&*tx, &old).await?;
    let mut new = old.clone();
    addressing::assign(&tx, &app.config, &mut new, &a, input).await?;
    let new = devices::save(&mut tx, &old, new).await?;
    tx.audit(&user.actor(), "device.addresses", &id).await?;
    tx.commit().await?;
    respond_device(&app, new).await
}

/// Extra server-side routes for a device.
#[derive(Deserialize, ToSchema)]
pub struct AllowedIps {
    allowed_ips: Vec<String>,
}

/// Set a device's extra server-side routes
///
/// Adds prefixes to the peer's `AllowedIPs` on the server interface without changing the device's
/// pool grants. A prefix that another device on the same interface already routes, or one inside a
/// pool that overlaps another device's grants, is rejected. Extra routes of different devices may
/// nest; WireGuard sends the overlap to the longer prefix.
#[utoipa::path(put, path = "/devices/{id}/allowed-ips", tag = "devices",
    security(("session" = ["admin"], "csrf" = [])),
    params(IfMatch), request_body = AllowedIps,
    responses((status = 200, body = DeviceView)))]
pub async fn set_device_allowed_ips(
    State(app): State<Arc<App>>,
    AuthenticatedAdmin(admin): AuthenticatedAdmin,
    Path(id): Path<String>,
    if_match: IfMatch,
    JsonBody(input): JsonBody<AllowedIps>,
) -> Result<Response> {
    let mut tx = admin.begin(&app).await?;
    let old = find_owned_device(&*tx, &admin, &id).await?;
    if_match.validate(old.revision)?;
    let new = devices::apply_extra_routes(&tx, &app.config, old.clone(), input.allowed_ips).await?;
    let new = devices::save(&mut tx, &old, new).await?;
    tx.audit(&admin.actor(), "device.allowed_ips", &id).await?;
    tx.commit().await?;
    respond_device(&app, new).await
}

// --- Device lifecycle, blocking, and key binding ---

/// Delete a device
///
/// Revokes the device and marks it `deleting`. The reconciler removes the peer from the kernel and
/// then deletes the database record. `If-Match` is optional so concurrent edits cannot block
/// deletion.
#[utoipa::path(delete, path = "/devices/{id}", tag = "devices",
    security(("session" = [], "csrf" = [])),
    params(OptionalIfMatch),
    responses((status = 200, body = DeviceView)))]
pub async fn delete_device(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    if_match: Option<IfMatch>,
) -> Result<Response> {
    let mut tx = user.begin(&app).await?;
    let old = find_owned_device(&*tx, &user, &id).await?;
    if let Some(m) = &if_match {
        m.validate(old.revision)?;
    }
    (!old.blocked || user.admin).ok_or_else(forbidden)?;
    let mut new = devices::revoke(&mut tx, &app.approvals, old.clone()).await?;
    new.deleting = true;
    let new = devices::save(&mut tx, &old, new).await?;
    tx.audit(&user.actor(), "device.deleted", &id).await?;
    tx.commit().await?;
    respond_device(&app, new).await
}

/// Block a device
///
/// Removes the device's peer from the kernel, blocks agent authentication, cancels pending claim
/// approvals, and prevents non-administrators from modifying its keys, addresses, or deletion
/// state. `If-Match` is optional.
#[utoipa::path(post, path = "/devices/{id}/block", tag = "devices",
    security(("session" = ["admin"], "csrf" = [])),
    params(OptionalIfMatch),
    responses((status = 200, body = DeviceView)))]
pub async fn block_device(
    State(app): State<Arc<App>>,
    AuthenticatedAdmin(admin): AuthenticatedAdmin,
    Path(id): Path<String>,
    if_match: Option<IfMatch>,
) -> Result<Response> {
    set_blocked(&app, &admin, &id, if_match, true).await
}

/// Unblock a device
#[utoipa::path(post, path = "/devices/{id}/unblock", tag = "devices",
    security(("session" = ["admin"], "csrf" = [])),
    params(OptionalIfMatch),
    responses((status = 200, body = DeviceView)))]
pub async fn unblock_device(
    State(app): State<Arc<App>>,
    AuthenticatedAdmin(admin): AuthenticatedAdmin,
    Path(id): Path<String>,
    if_match: Option<IfMatch>,
) -> Result<Response> {
    set_blocked(&app, &admin, &id, if_match, false).await
}

/// Sets the `blocked` flag on a device for an administrator, checking `if_match` when provided.
async fn set_blocked(
    app: &App,
    admin: &AuthenticatedUser,
    id: &str,
    if_match: Option<IfMatch>,
    blocked: bool,
) -> Result<Response> {
    let mut tx = admin.begin(app).await?;
    let old = find_owned_device(&*tx, admin, id).await?;
    if let Some(m) = &if_match {
        m.validate(old.revision)?;
    }
    (!old.deleting).ok_or_else(not_found)?;
    let new = device::Model {
        blocked,
        ..old.clone()
    };
    let new = devices::save(&mut tx, &old, new).await?;
    let action = if blocked {
        "device.blocked"
    } else {
        "device.unblocked"
    };
    tx.audit(&admin.actor(), action, id).await?;
    if blocked {
        app.approvals.forget_device(id);
    }
    tx.commit().await?;
    respond_device(app, new).await
}

/// Revoke a device
///
/// Clears the device's WireGuard public key, deletes its agent credential, and cancels any pending
/// claim approvals, while keeping the device record and its assigned addresses. `If-Match` is
/// optional.
#[utoipa::path(post, path = "/devices/{id}/revoke", tag = "devices",
    security(("session" = [], "csrf" = [])),
    params(OptionalIfMatch),
    responses((status = 200, body = DeviceView)))]
pub async fn revoke_device(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    if_match: Option<IfMatch>,
) -> Result<Response> {
    let mut tx = user.begin(&app).await?;
    let old = find_owned_device(&*tx, &user, &id).await?;
    if let Some(m) = &if_match {
        m.validate(old.revision)?;
    }
    let new = devices::revoke(&mut tx, &app.approvals, old.clone()).await?;
    let new = devices::save(&mut tx, &old, new).await?;
    tx.audit(&user.actor(), "device.revoked", &id).await?;
    tx.commit().await?;
    respond_device(&app, new).await
}

/// Request body for approving an agent claim on a device.
#[derive(Deserialize, ToSchema)]
pub struct ClaimApproval {
    /// Lowercase 64-character hex SHA-256 digest of the agent's claim secret.
    id: String,
    /// Unix timestamp in seconds when the agent generated the login request (must be within the
    /// last 15 minutes).
    t: i64,
}

/// Approve an agent for a device
///
/// Authorizes the agent holding the secret whose SHA-256 digest is `id` to claim this device via
/// `POST /agent/claim` within 10 minutes. Approvals are stored in memory only, up to 5 pending
/// approvals per account.
#[utoipa::path(post, path = "/devices/{id}/claims", tag = "devices",
    security(("session" = [], "csrf" = [])),
    request_body = ClaimApproval,
    responses((status = 204)))]
pub async fn approve_claim(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    JsonBody(input): JsonBody<ClaimApproval>,
) -> Result<StatusCode> {
    let is_sha256_hex = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    is_sha256_hex(&input.id).ok_or_else(|| invalid("id must be 64 lowercase hex digits"))?;
    let now = Utc::now();
    let made =
        chrono::DateTime::from_timestamp(input.t, 0).ok_or_else(|| invalid("t is not a time"))?;
    let fresh =
        made <= now + chrono::TimeDelta::minutes(1) && now - made <= approvals::REQUEST_LIFETIME;
    fresh.ok_or_else(|| invalid("the request expired: start again on the computer"))?;
    let tx = user.begin(&app).await?;
    let d = find_owned_device(&*tx, &user, &id).await?;
    (!d.deleting).ok_or_else(not_found)?;
    (!d.blocked).ok_or_else(forbidden)?;
    find_device_account(&*tx, &d)
        .await?
        .active()
        .ok_or_else(forbidden)?;
    app.approvals
        .approve(input.id, d.id, user.account_id.clone(), now)
        .map_err(conflict)?;
    tx.audit(&user.actor(), "device.claim_approved", &id)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Set or renew a device's key
///
/// Sets or renews the device's WireGuard public key for `key_lifetime`.
#[utoipa::path(post, path = "/devices/{id}/key", tag = "devices",
    security(("session" = [], "csrf" = [])),
    params(IfMatch), request_body = DeviceKey,
    responses((status = 200, body = DeviceView)))]
pub async fn set_device_key(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    if_match: IfMatch,
    JsonBody(input): JsonBody<DeviceKey>,
) -> Result<Response> {
    let mut tx = user.begin(&app).await?;
    let old = find_owned_device(&*tx, &user, &id).await?;
    if_match.validate(old.revision)?;
    (!old.blocked || user.admin).ok_or_else(forbidden)?;
    (!old.deleting).ok_or_else(not_found)?;
    find_device_account(&*tx, &old)
        .await?
        .active()
        .ok_or_else(forbidden)?;
    let new = devices::apply_key(
        &mut tx,
        &app.server_keys,
        app.config.key_lifetime,
        &old,
        input,
    )
    .await?;
    let new = devices::save(&mut tx, &old, new).await?;
    tx.audit(&user.actor(), "device.key", &id).await?;
    tx.commit().await?;
    respond_device(&app, new).await
}

// --- Client configuration and live kernel status ---

pub(super) async fn respond_device_config(
    app: &App,
    d: device::Model,
    headers: &HeaderMap,
) -> Result<Response> {
    let c = &app.db.conn;
    let i = app
        .config
        .interfaces
        .get(&d.interface_id)
        .ok_or_else(not_found)?;
    let status = app.interface_status(&d.interface_id);
    let a = find_device_account(c, &d).await?;
    let credential = agent_credential::Entity::find()
        .filter(agent_credential::Column::DeviceId.eq(&d.id))
        .one(c)
        .await?;
    // Synthesize a `pools` route profile when the interface defines no explicit route profiles.
    let (route_profiles, default_profile_id) = if i.route_profiles.is_empty() {
        let pools = crate::config::RouteProfile {
            id: "pools".into(),
            name: "Pools".into(),
            allowed_ips: i.pools.iter().map(|p| p.prefix.to_string()).collect(),
        };
        (vec![pools], "pools".to_string())
    } else {
        (i.route_profiles.clone(), i.default_profile_id.clone())
    };
    let reason = devices::determine_disabled_reason(&d, &app.config, &a, Utc::now());
    let enabled = reason.is_none();
    let ready = d.applied_revision == d.revision
        && status.applied
        && d.apply_error.is_empty()
        && status.apply_error.is_empty()
        && d.applied_enabled == enabled;
    let body = DeviceConfig {
        device_id: d.id,
        revision: d.revision,
        enabled,
        disabled_reason: reason,
        ready,
        addresses: d.client_addresses.0,
        grants: d.grants.0,
        public_key: d.public_key,
        preshared_key: d.preshared_key,
        server_public_key: app
            .server_keys
            .get(&d.interface_id)
            .map(|k| k.public.clone())
            .unwrap_or_default(),
        endpoint: i.endpoint.clone(),
        route_profiles: route_profiles
            .into_iter()
            .map(|p| ito_shared::api::RouteProfile {
                id: p.id,
                name: p.name,
                allowed_ips: p.allowed_ips,
            })
            .collect(),
        default_profile_id,
        dns: i.dns.clone(),
        dns_search: build_dns_search(i),
        mtu: i.client_mtu,
        keepalive: i.keepalive,
        key_expires_at: d.key_expires_at,
        agent_credential_issued_at: credential.map(|c| c.created_at),
    };
    let json = serde_json::to_string(&body).expect("serializable");
    let etag = format!("\"{}\"", secrets::digest_sha256(&json));
    if headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|v| v.as_bytes() == etag.as_bytes())
    {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
    }
    Ok(([(header::ETAG, etag)], Json(body)).into_response())
}

/// Reads the live WireGuard peer state of `d` from the kernel.
pub(super) async fn read_device_status(app: &App, d: device::Model) -> Result<Json<DeviceStatus>> {
    let name = &d.interface_id;
    app.config
        .interfaces
        .contains_key(name)
        .ok_or_else(not_found)?;
    let link = app.kernel.read_link(name).await?;
    if let Some(l) = &link
        && l.alias != format!("ito:{name}")
    {
        return Err(unavailable(Code::InterfaceOwnershipMismatch, name));
    }
    let peer = link.as_ref().and_then(|l| {
        l.peers
            .iter()
            .find(|p| d.public_key.as_deref() == Some(&p.public_key))
    });
    Ok(Json(DeviceStatus {
        device_id: d.id,
        interface_id: d.interface_id.clone(),
        observed_at: Utc::now(),
        interface_present: link.is_some(),
        interface_up: link.as_ref().is_some_and(|l| l.up),
        peer_present: peer.is_some(),
        addresses: d.client_addresses.0,
        allowed_ips: peer.map(|p| p.allowed_ips.clone()),
        endpoint: peer.map(|p| p.endpoint.clone()),
        handshake: peer.and_then(|p| p.handshake),
        receive_bytes: peer.map_or(0, |p| p.receive_bytes),
        transmit_bytes: peer.map_or(0, |p| p.transmit_bytes),
    }))
}

/// Get a device's client configuration
///
/// Wait for `ready` to be `true` before bringing up the client tunnel. Pass the returned `ETag` in
/// `If-None-Match` to receive `304 Not Modified` when the configuration has not changed.
#[utoipa::path(get, path = "/devices/{id}/config", tag = "devices",
    security(("session" = [])),
    params(("If-None-Match" = Option<String>, Header, description = "An earlier `ETag` of this response.")),
    responses((status = 200, body = DeviceConfig), (status = 304)))]
pub async fn get_device_config(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let d = find_owned_device(&app.db.conn, &user, &id).await?;
    respond_device_config(&app, d, &headers).await
}

/// Get a device's kernel status
#[utoipa::path(get, path = "/devices/{id}/status", tag = "devices",
    security(("session" = [])),
    responses((status = 200, body = DeviceStatus)))]
pub async fn get_device_status(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<DeviceStatus>> {
    let d = find_owned_device(&app.db.conn, &user, &id).await?;
    read_device_status(&app, d).await
}
