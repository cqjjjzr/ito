//! Account quota resolution, persistence, and SCIM status synchronization.

use crate::{
    App,
    addressing::Quota,
    config::{Config, Scim},
    db::{account::IdpStatus, *},
    devices,
    error::{Code, Error, Result, invalid, not_found},
    identity,
};
use chrono::{DateTime, Utc};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

/// Returns the effective address quota for `a`, falling back to installation defaults for empty
/// fields.
pub fn resolve_quota(config: &Config, a: &account::Model) -> Quota {
    let or_default =
        |own: &str, default: &str| if own.is_empty() { default } else { own }.to_string();
    Quota {
        ipv4: or_default(&a.quota_ipv4, &config.quota.ipv4),
        ipv6: or_default(&a.quota_ipv6, &config.quota.ipv6),
    }
}

/// Persists an updated account record with the next revision. If the account transitions from
/// active to inactive, deletes all of its sessions and suspends all of its devices.
pub async fn save(
    tx: &mut Tx,
    approvals: &crate::approvals::AgentApprovals,
    old: &account::Model,
    mut new: account::Model,
) -> Result<account::Model> {
    new.revision = old.revision + 1;
    tx.update::<account::ActiveModel>(new.clone()).await?;
    if old.active() && !new.active() {
        session::Entity::delete_many()
            .filter(session::Column::AccountId.eq(&new.id))
            .exec(&**tx)
            .await?;
        for d in device::Entity::find()
            .filter(device::Column::AccountId.eq(&new.id))
            .all(&**tx)
            .await?
        {
            let suspended = devices::suspend(tx, approvals, d.clone()).await?;
            devices::save(tx, &d, suspended).await?;
        }
    }
    Ok(new)
}

/// Finds or creates the account for `subject` at OIDC sign-in, applies the identity provider
/// status check `status` that began at `started`, and updates `display_name` when the account is
/// active.
pub async fn provision_at_login(
    tx: &mut Tx,
    approvals: &crate::approvals::AgentApprovals,
    subject: &str,
    name: &str,
    started: DateTime<Utc>,
    status: &Result<IdpStatus>,
) -> Result<account::Model> {
    let existing = account::Entity::find()
        .filter(account::Column::Subject.eq(subject))
        .one(&**tx)
        .await?;
    let a = match existing {
        Some(a) => a,
        None => {
            let status = status.as_ref().map_err(Error::clone)?;
            if *status == IdpStatus::Missing {
                return Err(Error::new(Code::IdentityMappingInvalid));
            }
            let a = account::Model {
                id: generate_id(),
                subject: subject.into(),
                display_name: name.into(),
                blocked: false,
                idp_status: *status,
                idp_checked_at: None,
                idp_check_error: false,
                quota_ipv4: String::new(),
                quota_ipv6: String::new(),
                revision: 1,
                created_at: started,
            };
            tx.insert::<account::ActiveModel>(a.clone()).await?;
            a
        }
    };
    let a = apply_idp_status(tx, approvals, a, started, status).await?;
    if status.is_err() || !a.active() || a.display_name == name {
        return Ok(a);
    }
    let new = account::Model {
        display_name: name.into(),
        ..a.clone()
    };
    save(tx, approvals, &a, new).await
}

/// Applies the result of an identity provider status check that began at `started`, ignoring stale
/// checks when `idp_checked_at` is already newer.
pub async fn apply_idp_status(
    tx: &mut Tx,
    approvals: &crate::approvals::AgentApprovals,
    a: account::Model,
    started: DateTime<Utc>,
    result: &Result<IdpStatus>,
) -> Result<account::Model> {
    if a.idp_checked_at.is_some_and(|t| t >= started) {
        return Ok(a);
    }
    let new_status = match result {
        Ok(status) => *status,
        Err(_) => {
            if a.idp_check_error {
                return Ok(a);
            }
            let new = account::Model {
                idp_check_error: true,
                ..a.clone()
            };
            return save(tx, approvals, &a, new).await;
        }
    };
    let new = account::Model {
        idp_status: new_status,
        idp_checked_at: Some(started),
        idp_check_error: false,
        ..a.clone()
    };
    let new = save(tx, approvals, &a, new).await?;
    if a.idp_status != new_status {
        let action = format!("account.{new_status:?}").to_lowercase();
        tx.audit("identity", &action, &new.id).await?;
    }
    Ok(new)
}

fn require_scim_config(app: &App) -> Result<&Scim> {
    app.config
        .scim
        .as_ref()
        .ok_or_else(|| invalid("user status fetch is not configured"))
}

/// Queries the SCIM endpoint `scim` once for every account in the database and updates its status.
pub async fn sweep_once(app: &App, scim: &Scim) -> Result<()> {
    for listed in account::Entity::find().all(&app.db.conn).await? {
        let started = Utc::now();
        let result = identity::scim::lookup(app, scim, &listed.subject).await;
        // Re-read the account inside the write transaction so concurrent edits made while the SCIM
        // HTTP request was in flight are not overwritten.
        let saved: Result<()> = async {
            let mut tx = app.db.begin_write().await?;
            let a = account::Entity::find_by_id(&listed.id)
                .one(&*tx)
                .await?
                .ok_or_else(not_found)?;
            apply_idp_status(&mut tx, &app.approvals, a, started, &result).await?;
            tx.commit().await
        }
        .await;
        if let Err(e) = saved.and(result) {
            tracing::warn!(account_id = %listed.id, error = %e, "status check failed");
        }
    }
    Ok(())
}

/// Triggers an immediate SCIM status sweep if `[scim]` is configured.
pub fn request_sweep(app: &App) -> Result<()> {
    require_scim_config(app)?;
    app.sweep_notify.notify_one();
    Ok(())
}

/// Periodically runs [`sweep_once`] every `scim.interval`, or immediately when woken by
/// [`request_sweep`].
pub async fn sweep(app: std::sync::Arc<App>, scim: Scim) {
    loop {
        if let Err(e) = sweep_once(&app, &scim).await {
            tracing::error!(error = %e, "status sweep failed");
        }
        // Notifications that arrive while `sweep_once` is running are stored by `Notify` and cause
        // the next wait to complete immediately.
        let _ = tokio::time::timeout(scim.interval, app.sweep_notify.notified()).await;
    }
}
