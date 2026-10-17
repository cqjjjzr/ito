//! OpenID Connect provider discovery and authorization-code sign-in.

use super::build_idp_error;
use crate::{
    App,
    config::read_secret,
    error::{Code, Error, Result, format_error_chain, unavailable},
};
use base64::Engine as _;
use openidconnect::http;
use openidconnect::{
    AsyncHttpClient, AuthorizationCode, ClientId, ClientSecret, CsrfToken, HttpClientError,
    HttpRequest, HttpResponse, IssuerUrl, LogoutRequest, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, PostLogoutRedirectUrl, ProviderMetadataWithLogout, RedirectUrl, Scope,
    TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient},
};
use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

pub fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        // Disable redirects so an identity provider endpoint cannot redirect requests elsewhere.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .expect("static HTTP client configuration")
}

/// Adapter that executes `openidconnect` HTTP requests through the controller's `reqwest::Client`.
pub struct OidcHttpClient<'a>(pub &'a reqwest::Client);

impl<'c> AsyncHttpClient<'c> for OidcHttpClient<'_> {
    type Error = HttpClientError<reqwest::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let request = request.try_into().map_err(Box::new)?;
            let response = self.0.execute(request).await.map_err(Box::new)?;
            let mut builder = http::Response::builder()
                .status(response.status())
                .version(response.version());
            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }
            let body = response.bytes().await.map_err(Box::new)?;
            builder.body(body.to_vec()).map_err(HttpClientError::Http)
        })
    }
}

/// Cache lifetime for OIDC discovery metadata and signing keys.
const DISCOVERY_TTL: Duration = Duration::from_secs(600);

/// Returns the OIDC discovery metadata for the configured issuer, refreshing it every 10 minutes.
pub async fn discover_provider(app: &App) -> Result<ProviderMetadataWithLogout> {
    let mut cached = app.identity_cache.provider.lock().await;
    if let Some((metadata, at)) = cached.as_ref()
        && at.elapsed() < DISCOVERY_TTL
    {
        return Ok(metadata.clone());
    }
    let issuer = IssuerUrl::new(app.config.oidc.issuer.clone()).map_err(build_idp_error)?;
    let metadata =
        ProviderMetadataWithLogout::discover_async(issuer, &OidcHttpClient(&app.http_client))
            .await
            .map_err(|e| build_idp_error(format_error_chain(&e)))?;
    *cached = Some((metadata.clone(), Instant::now()));
    Ok(metadata)
}

/// Builds the provider's logout confirmation URL, when RP-initiated logout is supported.
pub async fn logout_url(app: &App) -> Result<Option<String>> {
    let provider = discover_provider(app).await?;
    let Some(endpoint) = provider.additional_metadata().end_session_endpoint.clone() else {
        return Ok(None);
    };
    if !matches!(endpoint.url().scheme(), "http" | "https") {
        return Err(build_idp_error("unsupported logout URL scheme"));
    }
    let redirect = PostLogoutRedirectUrl::new(format!("{}/", app.config.public_url))
        .map_err(build_idp_error)?;
    // Omit id_token_hint so Keycloak asks before ending the browser's SSO session.
    Ok(Some(
        LogoutRequest::from(endpoint)
            .set_client_id(ClientId::new(app.config.oidc.client_id.clone()))
            .set_post_logout_redirect_uri(redirect)
            .http_get_url()
            .into(),
    ))
}

pub fn read_client_secret(path: &std::path::Path) -> Result<ClientSecret> {
    read_secret(path)
        .map(ClientSecret::new)
        .map_err(|e| unavailable(Code::SecretUnavailable, e))
}

/// Ephemeral state stored in the browser's login cookie during an OIDC sign-in flow.
pub struct LoginFlow {
    pub state: String,
    pub pkce_verifier: String,
    pub nonce: String,
}

/// Verified user claims extracted from the OIDC ID token.
pub struct LoginClaims {
    /// Subject identifier (`sub`).
    pub subject: String,
    /// Display name (`name`), falling back to `subject` when absent.
    pub name: String,
    /// Group names from the `groups` claim, or empty when absent.
    pub groups: Vec<String>,
}

/// Builds an `invalid_login` error while keeping the internal provider failure cause in the server
/// logs only.
fn build_login_error(cause: impl std::fmt::Display) -> Error {
    Error::new(Code::InvalidLogin)
        .detail("the identity provider's answer was refused")
        .cause(cause)
}

async fn build_login_client(
    app: &App,
    redirect_url: &str,
) -> Result<
    CoreClient<
        openidconnect::EndpointSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointNotSet,
        openidconnect::EndpointMaybeSet,
        openidconnect::EndpointMaybeSet,
    >,
> {
    let oidc = &app.config.oidc;
    let redirect = RedirectUrl::new(redirect_url.into())
        .map_err(|e| unavailable(Code::IdentityUnavailable, e))?;
    Ok(CoreClient::from_provider_metadata(
        discover_provider(app).await?,
        ClientId::new(oidc.client_id.clone()),
        Some(read_client_secret(&oidc.secret_file)?),
    )
    .set_redirect_uri(redirect))
}

/// Starts an authorization-code sign-in flow and returns the provider redirect URL and cookie
/// state.
pub async fn start_login(app: &App, redirect_url: &str) -> Result<(String, LoginFlow)> {
    let client = build_login_client(app, redirect_url).await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".into()))
        .set_pkce_challenge(challenge)
        .url();
    let flow = LoginFlow {
        state: state.secret().clone(),
        pkce_verifier: verifier.secret().clone(),
        nonce: nonce.secret().clone(),
    };
    Ok((url.to_string(), flow))
}

/// Exchanges the authorization `code`, verifies the ID token's signature, issuer, audience,
/// authorized party (`azp`), expiration, and nonce, and extracts its user claims.
pub async fn complete_login(
    app: &App,
    redirect_url: &str,
    code: String,
    pkce_verifier: &str,
    nonce: &str,
) -> Result<LoginClaims> {
    let client = build_login_client(app, redirect_url).await?;
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(build_login_error)?
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.into()))
        .request_async(&OidcHttpClient(&app.http_client))
        .await
        .map_err(|e| build_login_error(format_error_chain(&e)))?;
    let id_token = token
        .id_token()
        .ok_or_else(|| build_login_error("no ID token"))?;
    let algorithms = discover_provider(app)
        .await?
        .id_token_signing_alg_values_supported()
        .clone();
    let verifier = client.id_token_verifier().set_allowed_algs(algorithms);
    let claims = id_token
        .claims(&verifier, &Nonce::new(nonce.into()))
        .map_err(build_login_error)?;
    if let Some(azp) = claims.authorized_party()
        && **azp != app.config.oidc.client_id
    {
        return Err(build_login_error("ID token was issued to another client"));
    }
    let subject = claims.subject().to_string();
    let name = claims
        .name()
        .and_then(|n| n.get(None))
        .map_or(subject.clone(), |n| n.to_string());
    // Extract the custom `groups` claim from the JWT payload after signature verification above.
    let payload = id_token.to_string();
    let payload = payload.split('.').nth(1).and_then(|p| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(p)
            .ok()
    });
    let groups = payload
        .and_then(|p| serde_json::from_slice::<serde_json::Value>(&p).ok())
        .and_then(|v| serde_json::from_value(v["groups"].clone()).ok())
        .unwrap_or_default();
    Ok(LoginClaims {
        subject,
        name,
        groups,
    })
}
