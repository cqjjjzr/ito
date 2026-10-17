use crate::{
    App, accounts,
    db::*,
    error::{Code, Error, Result, forbidden, invalid},
    http::{
        extract::{self, AuthenticatedUser, QueryParams, build_account_actor, build_cookie_name},
        secrets,
    },
    identity,
};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header},
    response::{AppendHeaders, IntoResponse, Redirect, Response},
};
use chrono::Utc;
use sea_orm::{ColumnTrait, EntityTrait, ExprTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const AUTH_PATH: &str = "/api/v1/auth";

/// Builds the OIDC redirect URI that the identity provider sends the browser back to.
fn build_callback_url(app: &App) -> String {
    format!("{}{AUTH_PATH}/callback", app.config.public_url)
}

fn build_http_only_cookie(app: &App, value: String) -> (header::HeaderName, String) {
    build_script_cookie(app, format!("{value}; HttpOnly"))
}

/// Builds a `Set-Cookie` header for a cookie readable by same-origin scripts.
fn build_script_cookie(app: &App, value: String) -> (header::HeaderName, String) {
    let secure = if app.config.cookie_secure {
        "; Secure"
    } else {
        ""
    };
    (header::SET_COOKIE, format!("{value}; SameSite=Lax{secure}"))
}

/// Start a sign-in
///
/// Redirects the browser to the OpenID Connect provider. The OAuth state, PKCE verifier, and nonce
/// are stored in a 10-minute `HttpOnly` cookie so unfinished sign-ins do not allocate server state.
#[utoipa::path(get, path = "/auth/login", tag = "session",
    security(()),
    responses((status = 303, description = "Redirect to the identity provider.")))]
pub async fn login(State(app): State<Arc<App>>) -> Result<Response> {
    let (url, flow) = identity::oidc::start_login(&app, &build_callback_url(&app)).await?;
    let flow = format!("{}.{}.{}", flow.state, flow.pkce_verifier, flow.nonce);
    let cookie = build_http_only_cookie(
        &app,
        format!(
            "{}={flow}; Path=/; Max-Age=600",
            build_cookie_name(&app, "login")
        ),
    );
    Ok(([cookie], Redirect::to(&url)).into_response())
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct OidcCallbackQuery {
    /// Authorization code returned by the identity provider on success.
    code: Option<String>,
    state: String,
    /// Error code returned by the identity provider when sign-in fails or is cancelled.
    error: Option<String>,
}

/// Builds an `invalid_login` error when the browser's login cookie is missing or does not match
/// `state`.
fn build_restart_login_error(cause: impl std::fmt::Display) -> Error {
    Error::new(Code::InvalidLogin)
        .detail("start the sign-in again")
        .cause(cause)
}

/// Finish a sign-in
///
/// Handles the OpenID Connect callback, sets the session and CSRF cookies, and redirects to `/`.
#[utoipa::path(get, path = "/auth/callback", tag = "session",
    security(()),
    params(OidcCallbackQuery),
    responses((status = 303, description = "Signed in; redirect to `/`.")))]
pub async fn finish_login(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    QueryParams(query): QueryParams<OidcCallbackQuery>,
) -> Result<Response> {
    // Log the provider's error string without echoing it to the browser.
    if let Some(error) = query.error {
        let refused = Error::new(Code::InvalidLogin)
            .detail("the sign-in was cancelled or refused; start it again")
            .cause(format!("identity provider: {error}"));
        return Err(refused);
    }
    let code = query.code.ok_or_else(|| invalid("code is missing"))?;
    let flow = extract::extract_cookie(&headers, &build_cookie_name(&app, "login"))
        .ok_or_else(|| build_restart_login_error("missing login cookie"))?;
    let [state, verifier, nonce] = flow.split('.').collect::<Vec<_>>()[..] else {
        return Err(build_restart_login_error("malformed login cookie"));
    };
    secrets::constant_eq(state, &query.state)
        .ok_or_else(|| build_restart_login_error("state mismatch"))?;
    let claims =
        identity::oidc::complete_login(&app, &build_callback_url(&app), code, verifier, nonce)
            .await?;
    let (subject, name, groups) = (claims.subject, claims.name, claims.groups);
    let admin = groups
        .iter()
        .any(|g| app.config.oidc.admin_groups.contains(g));

    let started = Utc::now();
    let status = identity::scim::lookup_at_login(&app, &subject).await;
    let mut tx = app.db.begin_write().await?;
    let a =
        accounts::provision_at_login(&mut tx, &app.approvals, &subject, &name, started, &status)
            .await?;
    // The account keeps the status it was found with, even when it may not sign in.
    if let Err(e) = status {
        tx.commit().await?;
        return Err(e);
    }
    if !a.active() {
        tx.commit().await?;
        return Err(forbidden());
    }
    // Prune expired or idle sessions and any prior session from the same browser before inserting
    // the new session.
    let idle = chrono::TimeDelta::from_std(app.config.session_idle).expect("validated lifetime");
    session::Entity::delete_many()
        .filter(
            session::Column::ExpiresAt
                .lt(started)
                .or(session::Column::LastSeen.lt(started - idle)),
        )
        .exec(&*tx)
        .await?;
    if let Some(old) = extract::extract_cookie(&headers, &build_cookie_name(&app, "session")) {
        session::Entity::delete_by_id(secrets::digest_sha256(old))
            .exec(&*tx)
            .await?;
    }
    let secret = secrets::generate_secret();
    let csrf = secrets::generate_secret();
    let lifetime = app.config.session_lifetime;
    tx.insert::<session::ActiveModel>(session::Model {
        id: secrets::digest_sha256(&secret),
        account_id: a.id.clone(),
        admin,
        csrf: csrf.clone(),
        expires_at: started + chrono::TimeDelta::from_std(lifetime).expect("validated lifetime"),
        last_seen: started,
    })
    .await?;
    tx.audit(&build_account_actor(&a.id), "session.created", &a.id)
        .await?;
    tracing::info!(account_id = %a.id, ?groups, admin, "signed in");
    tx.commit().await?;
    let session = build_http_only_cookie(
        &app,
        format!(
            "{}={secret}; Path=/; Max-Age={}",
            build_cookie_name(&app, "session"),
            lifetime.as_secs()
        ),
    );
    let csrf = build_script_cookie(
        &app,
        format!(
            "{}={csrf}; Path=/; Max-Age={}",
            build_cookie_name(&app, "csrf"),
            lifetime.as_secs()
        ),
    );
    let clear = build_http_only_cookie(
        &app,
        format!("{}=; Path=/; Max-Age=0", build_cookie_name(&app, "login")),
    );
    Ok((AppendHeaders([session, csrf, clear]), Redirect::to("/")).into_response())
}

/// Navigation after ending the local browser session.
#[derive(Serialize, utoipa::ToSchema)]
pub struct LogoutView {
    /// Provider logout confirmation URL, or `/` if unsupported or unavailable.
    redirect_url: String,
}

/// End the browser session
///
/// Clears the local session and returns a provider logout URL for browser navigation.
/// Local logout succeeds even if provider discovery fails or logout is unsupported.
#[utoipa::path(post, path = "/auth/logout", tag = "session",
    security(("session" = [], "csrf" = [])),
    responses((status = 200, body = LogoutView)))]
pub async fn logout(State(app): State<Arc<App>>, user: AuthenticatedUser) -> Result<Response> {
    let tx = app.db.begin_write().await?;
    session::Entity::delete_by_id(&user.session_id)
        .exec(&*tx)
        .await?;
    tx.commit().await?;
    let clear = build_http_only_cookie(
        &app,
        format!("{}=; Path=/; Max-Age=0", build_cookie_name(&app, "session")),
    );
    let clear_csrf = build_script_cookie(
        &app,
        format!("{}=; Path=/; Max-Age=0", build_cookie_name(&app, "csrf")),
    );
    let redirect_url = match identity::oidc::logout_url(&app).await {
        Ok(url) => url.unwrap_or_else(|| "/".into()),
        Err(error) => {
            tracing::warn!(%error, "provider logout unavailable; local session ended");
            "/".into()
        }
    };
    Ok((
        AppendHeaders([clear, clear_csrf]),
        Json(LogoutView { redirect_url }),
    )
        .into_response())
}

/// Current browser session details.
#[derive(Serialize, utoipa::ToSchema)]
pub struct SessionView {
    account_id: String,
    /// Whether the session has administrator privileges, as determined by `oidc.admin_groups` at
    /// sign-in.
    admin: bool,
    expires_at: chrono::DateTime<Utc>,
    /// CSRF token for the session, also set in the `__Host-ito_csrf` cookie. Must be sent in the
    /// `X-CSRF-Token` header on every request other than `GET` and `HEAD`.
    csrf_token: String,
}

/// Get the browser session
#[utoipa::path(get, path = "/session", tag = "session",
    security(("session" = [])),
    responses((status = 200, body = SessionView)))]
pub async fn get_session(user: AuthenticatedUser) -> Json<SessionView> {
    Json(SessionView {
        account_id: user.account_id,
        admin: user.admin,
        expires_at: user.session_expires_at,
        csrf_token: user.csrf_token,
    })
}
