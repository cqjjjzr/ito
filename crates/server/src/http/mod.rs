//! The HTTP API: routes, middleware and request handlers.

use crate::{
    App,
    error::{self, Code, Error, Result, not_found},
};
use axum::{
    Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use std::{sync::Arc, time::Duration};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::{DefaultOnFailure, DefaultOnResponse, TraceLayer},
};
use utoipa::OpenApi;
use utoipa_axum::{router::OpenApiRouter, routes};

pub mod accounts;
pub mod agent;
pub mod devices;
pub mod extract;
pub mod interfaces;
pub mod metrics;
pub mod openapi;
pub mod pages;
pub mod secrets;
pub mod session;

pub(crate) fn build_api() -> OpenApiRouter<Arc<App>> {
    use {accounts as acc, agent, devices as dev, interfaces as ifc, session};
    #[rustfmt::skip]
    let v1 = OpenApiRouter::new()
        .routes(routes!(session::login))
        .routes(routes!(session::finish_login))
        .routes(routes!(session::logout))
        .routes(routes!(session::get_session))
        .routes(routes!(acc::list_accounts))
        .routes(routes!(acc::get_account))
        .routes(routes!(acc::set_account_policy))
        .routes(routes!(acc::refresh_accounts))
        .routes(routes!(acc::list_audit))
        .routes(routes!(ifc::list_interfaces))
        .routes(routes!(ifc::get_interface))
        .routes(routes!(ifc::list_diagnostics))
        .routes(routes!(dev::list_devices, dev::create_device))
        .routes(routes!(dev::get_device, dev::patch_device, dev::delete_device))
        .routes(routes!(dev::set_device_psk))
        .routes(routes!(dev::set_device_addresses))
        .routes(routes!(dev::set_device_allowed_ips))
        .routes(routes!(dev::block_device))
        .routes(routes!(dev::unblock_device))
        .routes(routes!(dev::revoke_device))
        .routes(routes!(dev::approve_claim))
        .routes(routes!(dev::set_device_key))
        .routes(routes!(dev::get_device_config))
        .routes(routes!(dev::get_device_status))
        .routes(routes!(agent::get_agent_device))
        .routes(routes!(agent::set_agent_key))
        .routes(routes!(agent::set_agent_psk))
        .routes(routes!(agent::get_agent_config))
        .routes(routes!(agent::get_agent_status))
        .routes(routes!(agent::revoke_agent))
        .routes(routes!(agent::claim_device));
    OpenApiRouter::with_openapi(openapi::ApiDoc::openapi()).nest("/api/v1", v1)
}

pub fn build_router(app: Arc<App>) -> Router {
    // Log each HTTP request at `INFO` only when `log.requests` is enabled; otherwise log at
    // `DEBUG` so reverse-proxy access logs are not duplicated by default.
    let requests_level = if app.config.log.requests {
        tracing::Level::INFO
    } else {
        tracing::Level::DEBUG
    };
    Router::new()
        .merge(Router::from(build_api()))
        .route("/api/v1/problems/{code}", get(get_problem_page))
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(check_ready))
        .fallback(pages::serve_page)
        .layer(DefaultBodyLimit::max(64 << 10))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        // Place `convert_to_problems` outside `TimeoutLayer` so bare framework status responses
        // (such as 405 Method Not Allowed or 408 Request Timeout) are formatted as RFC 9457
        // Problem Details.
        .layer(middleware::map_response(convert_to_problems))
        .layer(middleware::from_fn(render_problem_pages))
        .layer(middleware::map_response(add_security_headers))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(middleware::from_fn(scope_request_id))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|r: &Request| {
                    let request_id = r
                        .headers()
                        .get("x-request-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    tracing::info_span!(
                        "request",
                        method = %r.method(),
                        path = r.uri().path(),
                        request_id
                    )
                })
                .on_response(DefaultOnResponse::new().level(requests_level))
                .on_failure(DefaultOnFailure::new().level(requests_level)),
        )
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .with_state(app)
}

/// Binds the request's `x-request-id` header to task-local storage so error responses can include
/// it in their `instance` field.
async fn scope_request_id(request: Request, next: Next) -> Response {
    let id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    error::REQUEST_ID.scope(id, next.run(request)).await
}

/// Converts bare framework error responses (such as 405 or 408) into RFC 9457 Problem Details
/// responses.
async fn convert_to_problems(response: Response) -> Response {
    let status = response.status();
    let problem = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v == "application/problem+json");
    if problem || !(status.is_client_error() || status.is_server_error()) {
        return response;
    }
    let code = Code::ALL.iter().copied().find(|c| c.status() == status);
    let fallback = if status.is_client_error() {
        Code::InvalidRequest
    } else {
        Code::InternalError
    };
    Error::new(code.unwrap_or(fallback)).into_response()
}

/// Renders RFC 9457 Problem Details responses as the web portal's HTML error page when a browser
/// navigation request prefers `text/html` (such as during an OIDC login callback). API clients and
/// scripts continue to receive `application/problem+json`.
async fn render_problem_pages(request: Request, next: Next) -> Response {
    let accept = request.headers().get(header::ACCEPT);
    let navigating = accept
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"));
    let response = next.run(request).await;
    let problem = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v == "application/problem+json");
    if !navigating || !problem {
        return response;
    }
    let (parts, body) = response.into_parts();
    match axum::body::to_bytes(body, 64 << 10).await {
        Ok(json) => pages::render_problem_page(parts.status, &json)
            .unwrap_or_else(|| Response::from_parts(parts, json.into())),
        Err(e) => Error::new(Code::InternalError).cause(e).into_response(),
    }
}

/// Serves the human-readable documentation page for an error code at `/api/v1/problems/{code}`
/// (referenced by the `type` URI in RFC 9457 responses).
async fn get_problem_page(Path(code): Path<String>) -> Result<Response> {
    let code = Code::ALL
        .iter()
        .copied()
        .find(|c| c.as_str() == code)
        .ok_or_else(not_found)?;
    let status = code.status();
    let problem = serde_json::json!({
        "type": error::format_problem_type(code),
        "title": code.title(),
        "status": status.as_u16(),
        "code": code,
    });
    if let Some(page) = pages::render_problem_page(StatusCode::OK, problem.to_string().as_bytes()) {
        return Ok(page);
    }
    let page = format!(
        "<!doctype html><meta charset=utf-8><title>{c}</title><h1>{c}</h1>\
         <p>{} {}</p><p>{}</p>",
        status.as_u16(),
        status.canonical_reason().unwrap_or_default(),
        code.title(),
        c = code.as_str(),
    );
    Ok(Html(page).into_response())
}

/// Sets default security and cache-control headers on API responses unless already set by the
/// static asset handler.
async fn add_security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::REFERRER_POLICY, "no-referrer"),
        (
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'",
        ),
    ] {
        headers
            .entry(name)
            .or_insert(HeaderValue::from_static(value));
    }
    response
}

/// Returns `200 OK` when the SQLite database connection pool responds to a ping.
async fn check_ready(State(app): State<Arc<App>>) -> Result<&'static str> {
    app.db.conn.ping().await?;
    Ok("ok")
}
