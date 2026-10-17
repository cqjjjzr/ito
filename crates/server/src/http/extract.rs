use crate::{
    App,
    db::*,
    error::{Code, Error, Result, forbidden, invalid, unauthorized},
    http::secrets,
};
use axum::extract::{FromRequest, OptionalFromRequestParts, Request};
use axum::{
    Json,
    extract::FromRequestParts,
    http::{HeaderMap, Method, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, sea_query::Expr};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Arc;

// --- Request body, query, and ETag extractors ---

/// JSON request body extractor that converts deserialization failures into RFC 9457 API errors.
pub struct JsonBody<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for JsonBody<T> {
    type Rejection = Error;

    async fn from_request(req: Request, state: &S) -> Result<Self> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(JsonBody(value)),
            Err(rejection) => Err(match rejection.status() {
                StatusCode::UNSUPPORTED_MEDIA_TYPE => Error::new(Code::UnsupportedMediaType),
                StatusCode::PAYLOAD_TOO_LARGE => Error::new(Code::RequestTooLarge),
                _ => invalid(rejection.body_text()),
            }),
        }
    }
}

/// URL query parameter extractor that converts deserialization failures into RFC 9457 API errors.
pub struct QueryParams<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for QueryParams<T> {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self> {
        axum::extract::Query::<T>::from_request_parts(parts, state)
            .await
            .map(|q| QueryParams(q.0))
            .map_err(|rejection| invalid(rejection.body_text()))
    }
}

/// Extractor for the `If-Match` precondition header required by state-changing requests.
#[derive(utoipa::IntoParams)]
#[into_params(names("If-Match"), parameter_in = Header)]
pub struct IfMatch(
    /// Quoted revision ETag of the resource, such as `"4"`.
    #[param(value_type = String)]
    pub i64,
);

impl<S: Send + Sync> FromRequestParts<S> for IfMatch {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self> {
        let value = parts
            .headers
            .get(header::IF_MATCH)
            .ok_or_else(|| Error::new(Code::PreconditionRequired))?;
        value
            .to_str()
            .ok()
            .and_then(|v| v.strip_circumfix('"', '"'))
            .and_then(|v| v.parse().ok())
            .map(IfMatch)
            .ok_or_else(|| invalid("If-Match must be a quoted revision"))
    }
}

/// OpenAPI parameter descriptor for endpoints that accept an optional `If-Match` header.
#[derive(utoipa::IntoParams)]
#[into_params(names("If-Match"), parameter_in = Header)]
pub struct OptionalIfMatch(
    /// The resource's `ETag`, such as `"4"`; checked when sent.
    #[param(value_type = Option<String>)]
    #[expect(dead_code, reason = "only documents the header")]
    Option<i64>,
);

/// Allows `If-Match` to be omitted on administrative or revocation endpoints where concurrent edits
/// should not block the action.
impl<S: Send + Sync> OptionalFromRequestParts<S> for IfMatch {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Option<Self>> {
        if !parts.headers.contains_key(header::IF_MATCH) {
            return Ok(None);
        }
        <Self as FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map(Some)
    }
}

impl IfMatch {
    pub fn validate(&self, revision: i64) -> Result<()> {
        (self.0 == revision).ok_or_else(|| Error::new(Code::RevisionConflict))
    }
}

/// Serializes `body` as JSON with `revision` in the `ETag` response header.
pub fn respond_tagged(revision: i64, body: impl Serialize) -> Response {
    ([(header::ETAG, format!("\"{revision}\""))], Json(body)).into_response()
}

// --- Browser session and agent authentication extractors ---

/// Builds the name of the browser cookie `purpose`, such as `session`: `__Host-ito_session` when
/// `cookie_secure` is enabled, or `ito_session` otherwise.
pub fn build_cookie_name(app: &App, purpose: &str) -> String {
    let prefix = if app.config.cookie_secure {
        "__Host-"
    } else {
        ""
    };
    format!("{prefix}ito_{purpose}")
}

pub fn extract_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .flat_map(|h| h.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(k, v)| (k == name).then(|| v.strip_circumfix('"', '"').unwrap_or(v)))
}

/// Formats the audit log actor for the account `account_id` as `account:<id>`.
pub fn build_account_actor(account_id: &str) -> String {
    format!("account:{account_id}")
}

/// Authenticated browser session extracted from the request cookies.
pub struct AuthenticatedUser {
    pub account_id: String,
    pub admin: bool,
    pub session_id: String,
    pub session_expires_at: DateTime<Utc>,
    pub csrf_token: String,
}

impl AuthenticatedUser {
    /// Opens a write transaction and verifies inside the transaction that the session has not been
    /// revoked or expired.
    pub async fn begin(&self, app: &App) -> Result<Tx> {
        let tx = app.db.begin_write().await?;
        find_live_session(&*tx, &self.session_id).await?;
        Ok(tx)
    }

    pub fn owns(&self, account_id: &str) -> bool {
        self.admin || self.account_id == account_id
    }

    /// Formats the audit log actor for this user as `account:<id>`.
    pub fn actor(&self) -> String {
        build_account_actor(&self.account_id)
    }
}

impl FromRequestParts<Arc<App>> for AuthenticatedUser {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self> {
        let id = extract_cookie(&parts.headers, &build_cookie_name(app, "session"))
            .filter(|id| secrets::is_secret_format(id))
            .ok_or_else(unauthorized)?;
        let s = find_live_session(&app.db.conn, &secrets::digest_sha256(id)).await?;
        let now = Utc::now();
        let idle = (now - s.last_seen).to_std().unwrap_or_default();
        (idle <= app.config.session_idle).ok_or_else(unauthorized)?;
        if !matches!(parts.method, Method::GET | Method::HEAD) {
            let read_header = |name: &str| {
                parts
                    .headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
            };
            let same_origin = read_header("origin") == app.config.public_url;
            (same_origin && secrets::constant_eq(read_header("x-csrf-token"), &s.csrf))
                .ok_or_else(forbidden)?;
        }
        // Throttle `last_seen` writes to at most once per minute (or half of `session_idle` when
        // shorter).
        if idle > (app.config.session_idle / 2).min(std::time::Duration::from_secs(60)) {
            let tx = app.db.begin_write().await?;
            session::Entity::update_many()
                .col_expr(session::Column::LastSeen, Expr::value(now))
                .filter(session::Column::Id.eq(&s.id))
                .exec(&*tx)
                .await?;
            tx.commit().await?;
        }
        Ok(AuthenticatedUser {
            account_id: s.account_id,
            admin: s.admin,
            session_id: s.id,
            session_expires_at: s.expires_at,
            csrf_token: s.csrf,
        })
    }
}

async fn find_live_session(c: &impl ConnectionTrait, id: &str) -> Result<session::Model> {
    let s = session::Entity::find_by_id(id)
        .one(c)
        .await?
        .ok_or_else(unauthorized)?;
    (Utc::now() < s.expires_at).ok_or_else(unauthorized)?;
    Ok(s)
}

/// Extractor that requires an authenticated browser session with administrator privileges.
pub struct AuthenticatedAdmin(pub AuthenticatedUser);

impl FromRequestParts<Arc<App>> for AuthenticatedAdmin {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self> {
        let user = AuthenticatedUser::from_request_parts(parts, app).await?;
        user.admin.ok_or_else(forbidden)?;
        Ok(AuthenticatedAdmin(user))
    }
}

/// Authenticated device agent extracted from the `Authorization: Bearer itoa_<secret>` header.
pub struct AuthenticatedAgent {
    pub device: device::Model,
    credential_id: String,
}

impl AuthenticatedAgent {
    /// Formats the audit log actor for this agent as `device:<id>`.
    pub fn actor(&self) -> String {
        format!("device:{}", self.device.id)
    }

    /// Opens a write transaction and verifies inside the transaction that the agent credential,
    /// device, and owning account are still active.
    pub async fn begin(&self, app: &App) -> Result<(Tx, device::Model)> {
        let tx = app.db.begin_write().await?;
        let d = find_agent_device(&*tx, &self.credential_id).await?;
        Ok((tx, d))
    }
}

/// Loads the device for `credential_id` and verifies that the credential, device, and account are
/// active.
async fn find_agent_device(c: &impl ConnectionTrait, credential_id: &str) -> Result<device::Model> {
    let credential = agent_credential::Entity::find_by_id(credential_id)
        .one(c)
        .await?
        .ok_or_else(unauthorized)?;
    let d = device::Entity::find_by_id(&credential.device_id)
        .one(c)
        .await?
        .ok_or_else(unauthorized)?;
    let a = account::Entity::find_by_id(&d.account_id)
        .one(c)
        .await?
        .ok_or_else(unauthorized)?;
    (!d.deleting && !d.blocked && a.active()).ok_or_else(unauthorized)?;
    Ok(d)
}

impl FromRequestParts<Arc<App>> for AuthenticatedAgent {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self> {
        let credential_id = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer itoa_"))
            .filter(|id| secrets::is_secret_format(id))
            .map(secrets::digest_sha256)
            .ok_or_else(unauthorized)?;
        let device = find_agent_device(&app.db.conn, &credential_id).await?;
        Ok(AuthenticatedAgent {
            device,
            credential_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookies_are_found_by_their_exact_name() {
        for (case, headers, found) in [
            ("one cookie", &["a=1"][..], Some("1")),
            ("among others", &["x=0; a=1; y=2"], Some("1")),
            ("without spaces", &["x=0;a=1"], Some("1")),
            ("in a later header", &["x=0", "a=1"], Some("1")),
            ("quoted", &["a=\"1\""], Some("1")),
            ("first of two", &["a=1; a=2"], Some("1")),
            ("empty", &["a="], Some("")),
            ("absent", &["x=0"], None),
            ("name as a suffix", &["xa=1"], None),
            ("name as a prefix", &["ab=1"], None),
            ("no value", &["a"], None),
        ] {
            let mut map = HeaderMap::new();
            for h in headers {
                map.append(header::COOKIE, h.parse().unwrap());
            }
            assert_eq!(extract_cookie(&map, "a"), found, "{case}");
        }
    }
}
