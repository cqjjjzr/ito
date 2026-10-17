use crate::{
    App, config,
    error::{Result, not_found},
    http::extract::{AuthenticatedAdmin, AuthenticatedUser},
};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

/// Configured WireGuard interface combined with its server public key and reconciliation status.
#[derive(Serialize, ToSchema)]
#[schema(as = Interface)]
pub struct InterfaceView {
    /// Linux interface name and API identifier.
    name: String,
    public_key: String,
    /// Whether the configured state has been applied to and verified in the kernel.
    applied: bool,
    /// Error from the latest reconciliation pass, or empty when applied or when viewed by a
    /// non-administrator.
    apply_error: String,
    #[serde(flatten)]
    settings: config::Interface,
}

/// Builds the list of DNS search domains sent to clients of `i`, appending `dns_zone` after
/// `dns_search` if present.
pub(super) fn build_dns_search(i: &config::Interface) -> Vec<String> {
    let mut domains = i.dns_search.clone();
    if !i.dns_zone.is_empty() && !domains.contains(&i.dns_zone) {
        domains.push(i.dns_zone.clone());
    }
    domains
}

/// Builds the API view for interface `name`, redacting `apply_error` for non-administrators.
fn build_interface_view(
    app: &App,
    user: &AuthenticatedUser,
    name: &str,
    settings: &config::Interface,
) -> InterfaceView {
    let status = app.interface_status(name);
    InterfaceView {
        name: name.into(),
        public_key: app
            .server_keys
            .get(name)
            .map(|k| k.public.clone())
            .unwrap_or_default(),
        applied: status.applied,
        apply_error: if user.admin {
            status.apply_error
        } else {
            String::new()
        },
        settings: config::Interface {
            dns_search: build_dns_search(settings),
            ..settings.clone()
        },
    }
}

/// List interfaces
#[utoipa::path(get, path = "/interfaces", tag = "interfaces",
    security(("session" = [])),
    responses((status = 200, body = Vec<InterfaceView>)))]
pub async fn list_interfaces(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
) -> Json<Vec<InterfaceView>> {
    let all = app.config.interfaces.iter();
    Json(
        all.map(|(name, i)| build_interface_view(&app, &user, name, i))
            .collect(),
    )
}

/// Get an interface
#[utoipa::path(get, path = "/interfaces/{id}", tag = "interfaces",
    security(("session" = [])),
    responses((status = 200, body = InterfaceView)))]
pub async fn get_interface(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Json<InterfaceView>> {
    let settings = app.config.interfaces.get(&id).ok_or_else(not_found)?;
    Ok(Json(build_interface_view(&app, &user, &id, settings)))
}

/// Live kernel state and reconciliation error for a single WireGuard interface.
#[derive(Serialize, ToSchema)]
#[schema(as = Diagnostic)]
pub struct InterfaceDiagnostic {
    interface_id: String,
    apply_error: String,
    /// Observed kernel link and peers, or `null` if the interface is absent or could not be read.
    observed: Option<crate::kernel::Link>,
    observation_error: Option<String>,
}

/// List the kernel state of every interface
#[utoipa::path(get, path = "/diagnostics", tag = "interfaces",
    security(("session" = ["admin"])),
    responses((status = 200, body = Vec<InterfaceDiagnostic>)))]
pub async fn list_diagnostics(
    State(app): State<Arc<App>>,
    _: AuthenticatedAdmin,
) -> Json<Vec<InterfaceDiagnostic>> {
    let mut out = Vec::new();
    for name in app.config.interfaces.keys() {
        let observed = app.kernel.read_link(name).await;
        out.push(InterfaceDiagnostic {
            interface_id: name.clone(),
            apply_error: app.interface_status(name).apply_error,
            observation_error: observed.as_ref().err().map(|e| e.to_string()),
            observed: observed.ok().flatten(),
        });
    }
    Json(out)
}
