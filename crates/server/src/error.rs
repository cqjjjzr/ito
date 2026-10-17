use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::fmt;

// --- Error codes ---

/// Defines the [`Code`] enum and its JSON string value, HTTP status, and summary title.
///
/// `$code` uses `:tt` rather than `:literal` so `utoipa::ToSchema` can inspect the
/// `#[serde(rename)]` string literal at macro expansion time; otherwise the published schema would
/// list the variant names instead of the wire values.
macro_rules! codes {
    ($($variant:ident = $code:tt, $status:ident, $title:literal;)*) => {
        /// Machine-readable error code returned in API error responses.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, utoipa::ToSchema)]
        pub enum Code {
            $(#[serde(rename = $code)] $variant,)*
        }

        impl Code {
            /// All defined error codes in documentation order.
            pub const ALL: &[Code] = &[$(Code::$variant),*];

            pub fn as_str(self) -> &'static str {
                match self { $(Code::$variant => $code,)* }
            }

            pub fn status(self) -> StatusCode {
                match self { $(Code::$variant => StatusCode::$status,)* }
            }

            pub fn title(self) -> &'static str {
                match self { $(Code::$variant => $title,)* }
            }
        }
    };
}

// Within each HTTP status, the first variant is the fallback code used when converting bare
// framework status responses into RFC 9457 Problem Details.
codes! {
    InvalidRequest = "invalid_request", BAD_REQUEST, "Malformed or out-of-range input.";
    InvalidCredentials = "invalid_credentials", UNAUTHORIZED, "Missing, expired or revoked session or agent credential.";
    InvalidLogin = "invalid_login", UNAUTHORIZED, "The sign-in did not complete.";
    Forbidden = "forbidden", FORBIDDEN, "Not allowed, or a missing or wrong CSRF token or Origin.";
    OutsidePool = "outside_pool", FORBIDDEN, "A grant lies outside every pool of the interface.";
    IdentityMappingInvalid = "identity_mapping_invalid", FORBIDDEN, "The user status fetch does not know the signed-in subject.";
    NotFound = "not_found", NOT_FOUND, "No such resource, or not yours.";
    MethodNotAllowed = "method_not_allowed", METHOD_NOT_ALLOWED, "The resource does not support this method.";
    RequestTimeout = "request_timeout", REQUEST_TIMEOUT, "The request took too long.";
    Conflict = "conflict", CONFLICT, "A unique value is already taken.";
    AddressConflict = "address_conflict", CONFLICT, "An address or route is already assigned elsewhere.";
    AddressQuotaExceeded = "address_quota_exceeded", CONFLICT, "The account's address quota would be exceeded.";
    PoolExhausted = "pool_exhausted", CONFLICT, "No free block of the requested size.";
    KeyConflict = "key_conflict", CONFLICT, "The key belongs to a server or another device, or this device is blocked.";
    DnsNameTaken = "dns_name_taken", CONFLICT, "Another device publishes that name.";
    SelfBlockForbidden = "self_block_forbidden", CONFLICT, "Administrators cannot block themselves.";
    ClaimLimitReached = "claim_limit_reached", CONFLICT, "The account has the most agent approvals pending; wait for them to be claimed or expire.";
    ClaimTaken = "claim_taken", CONFLICT, "Another account approved this agent request.";
    ClaimDeviceMismatch = "claim_device_mismatch", CONFLICT, "The request was approved for a device other than the one the agent asks for.";
    RevisionConflict = "revision_conflict", PRECONDITION_FAILED, "If-Match is stale.";
    RequestTooLarge = "request_too_large", PAYLOAD_TOO_LARGE, "The body is over 64 KiB.";
    UnsupportedMediaType = "unsupported_media_type", UNSUPPORTED_MEDIA_TYPE, "The body is not application/json.";
    PreconditionRequired = "precondition_required", PRECONDITION_REQUIRED, "If-Match is missing.";
    InternalError = "internal_error", INTERNAL_SERVER_ERROR, "A bug; the log has the cause.";
    IdentityUnavailable = "identity_unavailable", SERVICE_UNAVAILABLE, "The identity provider did not answer as expected.";
    SecretUnavailable = "secret_unavailable", SERVICE_UNAVAILABLE, "A configured secret file cannot be read.";
    KernelUnavailable = "kernel_unavailable", SERVICE_UNAVAILABLE, "An ip or wg command could not run.";
    KernelCommandFailed = "kernel_command_failed", SERVICE_UNAVAILABLE, "An ip or wg command failed.";
    InterfaceOwnershipMismatch = "interface_ownership_mismatch", SERVICE_UNAVAILABLE, "The interface name belongs to a link the controller does not own.";
    InterfaceNameInUse = "interface_name_in_use", SERVICE_UNAVAILABLE, "The interface name belongs to a link that is not WireGuard.";
    DatabaseUnavailable = "database_unavailable", SERVICE_UNAVAILABLE, "The database did not answer.";
}

// --- Error type and constructors ---

/// Controller error combining a client-facing [`Code`], an optional client-visible `detail`, and an
/// internal `cause` recorded only in server logs.
#[derive(Clone, Debug)]
pub struct Error {
    pub code: Code,
    /// Actionable message returned to the client in the `detail` field of the Problem Details body.
    /// Must never expose internal server paths, database schema details, or upstream secrets.
    pub detail: Option<String>,
    /// Internal diagnostic message logged on the server and omitted from HTTP responses.
    pub cause: Option<String>,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn new(code: Code) -> Self {
        Self {
            code,
            detail: None,
            cause: None,
        }
    }

    pub fn detail(mut self, detail: impl fmt::Display) -> Self {
        self.detail = Some(detail.to_string());
        self
    }

    pub fn cause(mut self, cause: impl fmt::Display) -> Self {
        self.cause = Some(cause.to_string());
        self
    }

    pub fn cause_contains(&self, text: &str) -> bool {
        self.cause.as_deref().is_some_and(|c| c.contains(text))
    }
}

pub fn invalid(detail: impl fmt::Display) -> Error {
    Error::new(Code::InvalidRequest).detail(detail)
}

pub fn unauthorized() -> Error {
    Error::new(Code::InvalidCredentials)
}

pub fn forbidden() -> Error {
    Error::new(Code::Forbidden)
}

pub fn not_found() -> Error {
    Error::new(Code::NotFound)
}

pub fn conflict(code: Code) -> Error {
    Error::new(code)
}

pub fn unavailable(code: Code, cause: impl fmt::Display) -> Error {
    Error::new(code).cause(cause)
}

pub fn internal(cause: impl fmt::Display) -> Error {
    Error::new(Code::InternalError).cause(cause)
}

/// Formats an error and its causal chain into a single colon-separated string.
pub fn format_error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut next = e.source();
    while let Some(e) = next {
        out.push_str(": ");
        out.push_str(&e.to_string());
        next = e.source();
    }
    out
}

/// Formats the error as `code: detail: cause` (omitting empty fields) for server logs.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code.as_str())?;
        for part in [&self.detail, &self.cause].into_iter().flatten() {
            write!(f, ": {part}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

impl From<sea_orm::DbErr> for Error {
    fn from(error: sea_orm::DbErr) -> Self {
        match error.sql_err() {
            // Application checks reject duplicates before hitting SQLite; if a constraint violation
            // still occurs, return `conflict` and keep the SQLite error in server logs only.
            Some(sea_orm::SqlErr::UniqueConstraintViolation(cause)) => {
                conflict(Code::Conflict).cause(cause)
            }
            _ => unavailable(Code::DatabaseUnavailable, error),
        }
    }
}

// --- RFC 9457 Problem Details response ---

tokio::task_local! {
    /// Request UUID bound by HTTP middleware and reported in the Problem Details `instance` field.
    pub static REQUEST_ID: String;
}

/// Returns the problem documentation URI path (`/api/v1/problems/<code_str>`) used as `type`.
pub fn format_problem_type(code: Code) -> String {
    format!("/api/v1/problems/{}", code.as_str())
}

/// An error response, as RFC 9457 problem details (`application/problem+json`).
///
/// `code` is one of the codes in the table below; `type` is a page documenting it.
#[derive(Serialize, utoipa::ToSchema)]
pub struct Problem {
    /// Problem type URI (`/api/v1/problems/CODE`) documenting the error code.
    #[serde(rename = "type")]
    kind: String,
    /// Short human-readable summary for this error code.
    title: &'static str,
    /// HTTP status code.
    status: u16,
    /// Specific explanation of what failed in this request, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    /// Request occurrence URI (`urn:uuid:REQUEST-ID`), matching `x-request-id` and server logs.
    #[serde(skip_serializing_if = "Option::is_none")]
    instance: Option<String>,
    code: Code,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (code, detail, cause) = (self.code.as_str(), &self.detail, &self.cause);
        // Log 5xx errors and failed OIDC sign-ins at error/warn level; log ordinary 4xx client
        // rejections at debug level.
        match self.code {
            c if c.status().is_server_error() => {
                tracing::error!(code, detail, cause, "request failed");
            }
            Code::InvalidLogin => tracing::warn!(code, detail, cause, "sign-in failed"),
            Code::Conflict if cause.is_some() => {
                tracing::warn!(code, cause, "unique value taken without an admission check");
            }
            _ => tracing::debug!(code, detail, cause, "request refused"),
        }
        let instance = REQUEST_ID
            .try_with(|id| uuid::Uuid::parse_str(id).ok())
            .ok()
            .flatten()
            .map(|id| format!("urn:uuid:{id}"));
        let body = Problem {
            kind: format_problem_type(self.code),
            title: self.code.title(),
            status: self.code.status().as_u16(),
            detail: self.detail,
            instance,
            code: self.code,
        };
        (
            self.code.status(),
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(body),
        )
            .into_response()
    }
}
