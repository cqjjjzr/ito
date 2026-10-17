//! OpenID Connect authentication and SCIM 2.0 user status client.

use crate::error::{Code, Error, unavailable};
use openidconnect::ProviderMetadataWithLogout;
use std::time::Instant;

pub mod oidc;
pub mod scim;

/// Cached OIDC provider metadata and SCIM OAuth2 client-credentials access token.
#[derive(Default)]
pub struct IdentityCache {
    pub(crate) provider: tokio::sync::Mutex<Option<(ProviderMetadataWithLogout, Instant)>>,
    pub(crate) status_token: tokio::sync::Mutex<Option<(String, Instant)>>,
}

pub(crate) fn build_idp_error(detail: impl std::fmt::Display) -> Error {
    unavailable(Code::IdentityUnavailable, detail)
}
