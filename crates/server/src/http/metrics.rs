use crate::{App, db::*, error::Result};
use axum::{
    Router,
    extract::State,
    http::header,
    response::{IntoResponse, Response},
    routing::get,
};
use sea_orm::{ColumnTrait, EntityTrait, ExprTrait, PaginatorTrait, QueryFilter, sea_query::Expr};
use std::sync::Arc;

/// The router for `/metrics` in Prometheus text format, served on `metrics_listen`.
pub fn build_router(app: Arc<App>) -> Router {
    Router::new()
        .route("/metrics", get(render_metrics))
        .with_state(app)
}

async fn render_metrics(State(app): State<Arc<App>>) -> Result<Response> {
    let c = &app.db.conn;
    let mut gauges = vec![
        (
            "ito_devices_pending",
            device::Entity::find()
                .filter(
                    Expr::col(device::Column::AppliedRevision)
                        .ne(Expr::col(device::Column::Revision)),
                )
                .count(c)
                .await?,
        ),
        (
            "ito_device_apply_errors",
            device::Entity::find()
                .filter(device::Column::ApplyError.ne(""))
                .count(c)
                .await?,
        ),
        (
            "ito_interface_apply_errors",
            app.interface_status
                .lock()
                .expect("status lock")
                .values()
                .filter(|s| !s.apply_error.is_empty())
                .count() as u64,
        ),
    ];
    if app.config.scim.is_some() {
        gauges.push((
            "ito_account_idp_check_errors",
            account::Entity::find()
                .filter(account::Column::IdpCheckError.eq(true))
                .count(c)
                .await?,
        ));
    }
    let body: String = gauges
        .iter()
        .map(|(name, n)| format!("# TYPE {name} gauge\n{name} {n}\n"))
        .collect();
    Ok(([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], body).into_response())
}
