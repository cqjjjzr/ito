use crate::{
    App, accounts,
    addressing::{self, Quota},
    db::*,
    error::{Code, Result, conflict, invalid, not_found},
    http::extract::{
        AuthenticatedAdmin, AuthenticatedUser, IfMatch, JsonBody, QueryParams, respond_tagged,
    },
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::Response,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};
use utoipa::{IntoParams, ToSchema};

/// Account record combined with its effective quota limits and current address usage.
#[derive(Serialize, ToSchema)]
pub struct AccountView {
    #[serde(flatten)]
    account: account::Model,
    limits: Quota,
    /// Number of addresses currently in use per IP family, formatted as decimal strings.
    usage: Quota,
}

/// Builds `AccountView` values for `accounts`, querying their device grants in a single batch.
async fn build_account_views(app: &App, accounts: Vec<account::Model>) -> Result<Vec<AccountView>> {
    let ids: Vec<&String> = accounts.iter().map(|a| &a.id).collect();
    let mut grants: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for d in device::Entity::find()
        .filter(device::Column::AccountId.is_in(ids))
        .filter(device::Column::Deleting.eq(false))
        .all(&app.db.conn)
        .await?
    {
        grants.entry(d.account_id).or_default().extend(d.grants.0);
    }
    accounts
        .into_iter()
        .map(|a| {
            let [v4, v6] = addressing::count_usage(grants.get(&a.id).map_or(&[], Vec::as_slice))?;
            Ok(AccountView {
                limits: accounts::resolve_quota(&app.config, &a),
                usage: Quota {
                    ipv4: v4.to_string(),
                    ipv6: v6.to_string(),
                },
                account: a,
            })
        })
        .collect()
}

/// Responds with the account view tagged with its revision `ETag`.
async fn respond_account(app: &App, a: account::Model) -> Result<Response> {
    let revision = a.revision;
    let mut views = build_account_views(app, vec![a]).await?;
    Ok(respond_tagged(revision, views.pop().expect("one account")))
}

/// List accounts
#[utoipa::path(get, path = "/accounts", tag = "accounts",
    security(("session" = ["admin"])),
    responses((status = 200, body = Vec<AccountView>)))]
pub async fn list_accounts(
    State(app): State<Arc<App>>,
    _: AuthenticatedAdmin,
) -> Result<Json<Vec<AccountView>>> {
    let accounts = account::Entity::find().all(&app.db.conn).await?;
    Ok(Json(build_account_views(&app, accounts).await?))
}

/// Get an account
///
/// Members can read their own account; administrators can read any account.
#[utoipa::path(get, path = "/accounts/{id}", tag = "accounts",
    security(("session" = [])),
    responses((status = 200, body = AccountView)))]
pub async fn get_account(
    State(app): State<Arc<App>>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<Response> {
    let a = account::Entity::find_by_id(&id)
        .one(&app.db.conn)
        .await?
        .filter(|a| user.owns(&a.id))
        .ok_or_else(not_found)?;
    respond_account(&app, a).await
}

/// Administrative policy settings for an account.
#[derive(Deserialize, ToSchema)]
#[schema(as = Policy)]
pub struct AccountPolicyInput {
    /// Whether the account is blocked. Blocking an account immediately terminates its browser
    /// sessions and revokes its devices.
    blocked: bool,
    /// Per-account address limits. Empty strings inherit the installation defaults from `[quota]`.
    quota: Quota,
}

/// Set an account's policy
#[utoipa::path(put, path = "/accounts/{id}/policy", tag = "accounts",
    security(("session" = ["admin"], "csrf" = [])),
    params(IfMatch), request_body = AccountPolicyInput,
    responses((status = 200, body = AccountView)))]
pub async fn set_account_policy(
    State(app): State<Arc<App>>,
    AuthenticatedAdmin(admin): AuthenticatedAdmin,
    Path(id): Path<String>,
    if_match: IfMatch,
    JsonBody(input): JsonBody<AccountPolicyInput>,
) -> Result<Response> {
    addressing::parse_limits(&input.quota)?;
    let mut tx = admin.begin(&app).await?;
    let old = account::Entity::find_by_id(&id)
        .one(&*tx)
        .await?
        .ok_or_else(not_found)?;
    if_match.validate(old.revision)?;
    if input.blocked && old.id == admin.account_id {
        return Err(conflict(Code::SelfBlockForbidden));
    }
    let new = account::Model {
        blocked: input.blocked,
        quota_ipv4: input.quota.ipv4,
        quota_ipv6: input.quota.ipv6,
        ..old.clone()
    };
    let a = accounts::save(&mut tx, &app.approvals, &old, new).await?;
    tx.audit(&admin.actor(), "account.policy", &a.id).await?;
    tx.commit().await?;
    respond_account(&app, a).await
}

/// Check every account's user status now
///
/// Triggers an immediate background SCIM status sweep across all accounts and returns `202
/// Accepted` without waiting for completion. Requires the `[scim]` configuration section.
#[utoipa::path(post, path = "/accounts/refresh", tag = "accounts",
    security(("session" = ["admin"], "csrf" = [])),
    responses((status = 202, description = "The sweep is starting.")))]
pub async fn refresh_accounts(
    State(app): State<Arc<App>>,
    _: AuthenticatedAdmin,
) -> Result<StatusCode> {
    accounts::request_sweep(&app)?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Deserialize, IntoParams)]
pub struct AuditPageQuery {
    /// Maximum number of entries to return, up to `1000` (default `100`).
    limit: Option<u64>,
    /// Return only entries older than this audit log ID.
    before: Option<String>,
}

/// List audit entries
///
/// Returns audit log entries ordered from newest to oldest.
#[utoipa::path(get, path = "/audit", tag = "accounts",
    security(("session" = ["admin"])),
    params(AuditPageQuery),
    responses((status = 200, body = Vec<audit::Model>)))]
pub async fn list_audit(
    State(app): State<Arc<App>>,
    _: AuthenticatedAdmin,
    QueryParams(page): QueryParams<AuditPageQuery>,
) -> Result<Json<Vec<audit::Model>>> {
    let limit = page.limit.unwrap_or(100);
    if limit > 1000 {
        return Err(invalid("limit must be at most 1000"));
    }
    let mut q = audit::Entity::find().order_by_desc(audit::Column::Id);
    if let Some(before) = page.before {
        q = q.filter(audit::Column::Id.lt(before));
    }
    Ok(Json(q.limit(limit).all(&app.db.conn).await?))
}
