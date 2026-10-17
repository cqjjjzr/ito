use crate::{
    App, InterfaceStatus,
    config::Interface,
    db::*,
    devices,
    error::{Code, Result, unavailable},
    kernel::{self, Link},
};
use base64::Engine as _;
use chrono::Utc;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

// --- Reconciliation plan and pass ---

/// Maximum interval between reconciliation passes. In addition to applying committed database
/// changes, periodic passes repair out-of-band kernel changes and remove peers whose keys have
/// expired.
const PASS_INTERVAL: Duration = Duration::from_secs(60);

/// Runs the background reconciliation loop across all configured interfaces.
pub async fn run(app: Arc<App>) {
    loop {
        if let Err(e) = sync(&app).await {
            tracing::error!(error = %e, "reconcile pass failed");
        }
        // Any commit during the pass above resolves `wait_kernel_changed` immediately so another
        // pass runs right away.
        let _ = tokio::time::timeout(PASS_INTERVAL, app.db.wait_kernel_changed()).await;
    }
}

struct RequestedPeer {
    allowed_ips: Vec<String>,
    psk: String,
}

/// Desired and observed state of a single WireGuard interface during a reconciliation pass.
struct InterfaceReconcilePlan {
    name: String,
    interface: Interface,
    devices: BTreeMap<String, device::Model>,
    enabled: BTreeMap<String, bool>,
    /// Desired WireGuard peers keyed by public key.
    requested_peers: BTreeMap<String, RequestedPeer>,
    link: Option<Link>,
    /// Whether a kernel read confirmed no obsolete peer keys or AllowedIPs remain. Revocation
    /// clears public keys in the database, so deletion must verify cleanup against the whole plan.
    removals_verified: bool,
    error: Option<String>,
}

impl InterfaceReconcilePlan {
    /// Records `error` as the interface's error unless an earlier step already failed.
    fn record_first_error(&mut self, error: impl ToString) {
        self.error.get_or_insert_with(|| error.to_string());
    }

    fn is_peer_installed(&self, key: &str, peer: &RequestedPeer) -> bool {
        self.link.as_ref().is_some_and(|l| {
            l.peers.iter().any(|p| {
                p.public_key == key
                    && p.allowed_ips == peer.allowed_ips
                    && p.preshared_key == peer.psk
            })
        })
    }

    fn set_link(&mut self, link: Option<Link>) {
        self.removals_verified = link.iter().flat_map(|l| &l.peers).all(|p| {
            self.requested_peers
                .get(&p.public_key)
                .is_some_and(|wanted| p.allowed_ips == wanted.allowed_ips)
        });
        self.link = link;
    }
}

/// Reconciles every configured interface with the kernel and records the outcome in the database.
pub async fn sync(app: &App) -> Result<()> {
    if let Err(e) = retire_unconfigured(app).await {
        tracing::warn!(error = %e, "cannot retire unconfigured interfaces");
    }

    let mut plans = build_reconcile_plans(app).await?;
    for plan in &mut plans {
        match read_from_kernel(app, &plan.name).await {
            Ok(link) => plan.set_link(link),
            Err(e) => plan.record_first_error(e),
        }
    }

    // Bring down disabled interfaces and remove peers that should not be present first, so
    // revocations take effect even if subsequent interface setup steps fail.
    for plan in plans.iter_mut().filter(|p| p.error.is_none()) {
        let name = plan.name.clone();
        let down = plan.interface.disabled && plan.link.as_ref().is_some_and(|l| l.up);
        if down && let Err(e) = kernel::run!(app.kernel, "ip link set dev {name} down").await {
            plan.record_first_error(e);
        }
        let unwanted: Vec<String> = plan
            .link
            .iter()
            .flat_map(|l| &l.peers)
            .map(|p| p.public_key.clone())
            .filter(|key| !plan.requested_peers.contains_key(key))
            .collect();
        for key in &unwanted {
            if let Err(e) = kernel::run!(app.kernel, "wg set {name} peer {key} remove").await {
                plan.record_first_error(e);
            }
        }
        if down || !unwanted.is_empty() {
            match app.kernel.read_link(&name).await {
                Ok(link) => plan.set_link(link),
                Err(e) => {
                    plan.removals_verified = false;
                    plan.record_first_error(e);
                }
            }
        }
    }

    // Configure each interface link (keys, port, MTU, addresses, up state).
    for plan in plans.iter_mut().filter(|p| p.error.is_none()) {
        match sync_link(app, &plan.name, &plan.interface, plan.link.take()).await {
            Ok(link) => plan.link = link,
            Err(e) => plan.record_first_error(e),
        }
    }

    // Add or update peers whose kernel state differs from the desired state.
    for plan in plans
        .iter_mut()
        .filter(|p| p.error.is_none() && p.link.is_some())
    {
        let name = plan.name.clone();
        let missing: Vec<(String, String, String)> = plan
            .requested_peers
            .iter()
            .filter(|(k, w)| !plan.is_peer_installed(k, w))
            .map(|(k, w)| {
                // Passing an all-zero 32-byte key to `wg set ... preshared-key` clears the PSK.
                let psk = match w.psk.as_str() {
                    "" => base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
                    psk => psk.into(),
                };
                (k.clone(), w.allowed_ips.join(","), psk)
            })
            .collect();
        for (key, allowed, psk) in missing {
            let set = kernel::run!(
                app.kernel,
                "wg set {name} peer {key} preshared-key /dev/stdin allowed-ips {allowed}",
                stdin = psk
            );
            if let Err(e) = set.await {
                plan.record_first_error(e);
            }
        }
    }

    // Re-read each interface from the kernel and verify that the observed state matches the plan.
    for plan in plans.iter_mut().filter(|p| p.error.is_none()) {
        match app.kernel.read_link(&plan.name).await {
            Ok(link) => {
                plan.set_link(link);
                if let Err(e) = verify_link(app, plan) {
                    plan.record_first_error(e);
                }
            }
            Err(e) => plan.record_first_error(e),
        }
    }
    save_state_to_db(app, plans).await
}

async fn build_reconcile_plans(app: &App) -> Result<Vec<InterfaceReconcilePlan>> {
    let read_txn = app.db.begin_read().await?;
    let c = &read_txn;
    let now = Utc::now();
    let mut plans = Vec::new();
    for (name, interface) in &app.config.interfaces {
        let devices = device::Entity::find()
            .filter(device::Column::InterfaceId.eq(name))
            .all(c)
            .await?;
        let account_ids: BTreeSet<_> = devices.iter().map(|d| d.account_id.clone()).collect();
        let accounts: BTreeMap<_, _> = account::Entity::find()
            .filter(account::Column::Id.is_in(account_ids))
            .all(c)
            .await?
            .into_iter()
            .map(|a| (a.id.clone(), a))
            .collect();
        let mut plan = InterfaceReconcilePlan {
            name: name.clone(),
            interface: interface.clone(),
            devices: BTreeMap::new(),
            enabled: BTreeMap::new(),
            requested_peers: BTreeMap::new(),
            link: None,
            removals_verified: false,
            error: None,
        };
        for d in devices {
            let on =
                devices::determine_disabled_reason(&d, &app.config, &accounts[&d.account_id], now)
                    .is_none();
            if on && let Some(key) = &d.public_key {
                plan.requested_peers.insert(
                    key.clone(),
                    RequestedPeer {
                        allowed_ips: devices::collect_allowed_ips(&d),
                        psk: d.preshared_key.clone(),
                    },
                );
            }
            plan.enabled.insert(d.id.clone(), on);
            plan.devices.insert(d.id.clone(), d);
        }
        plans.push(plan);
    }
    Ok(plans)
}

// --- Kernel link synchronization and verification ---

/// Prefix of the netlink `ifalias` tag that identifies interfaces managed by Ito.
const ALIAS_PREFIX: &str = "ito:";

fn format_alias(name: &str) -> String {
    format!("{ALIAS_PREFIX}{name}")
}

/// Reads an interface link from the kernel and verifies that it carries the `ito:<name>` alias if
/// it already exists.
async fn read_from_kernel(app: &App, name: &str) -> Result<Option<Link>> {
    let link = app.kernel.read_link(name).await?;
    if let Some(l) = &link
        && l.alias != format_alias(name)
    {
        return Err(unavailable(
            Code::InterfaceOwnershipMismatch,
            format!("{name} belongs to another owner ({})", l.alias),
        ));
    }
    Ok(link)
}

/// Reconciles an owned interface link's settings (excluding peers), running commands only when the
/// kernel state differs from `i`.
async fn sync_link(
    app: &App,
    name: &str,
    i: &Interface,
    link: Option<Link>,
) -> Result<Option<Link>> {
    let k = &app.kernel;
    let alias = format_alias(name);
    if i.disabled {
        return Ok(link);
    }
    let key = app
        .server_keys
        .get(name)
        .expect("every configured interface has a key");
    let mut changed = false;
    let mtu = i.mtu.to_string();
    let link = match link {
        Some(l) => l,
        None => {
            kernel::run!(k, "ip link add dev {name} mtu {mtu} type wireguard").await?;
            // Set the interface alias in a separate command because `ip link add` ignores `alias`.
            // A link left without it would read as foreign forever, so remove it on failure.
            if let Err(error) = kernel::run!(k, "ip link set dev {name} alias {alias}").await {
                if let Err(cleanup) = kernel::run!(k, "ip link delete dev {name}").await {
                    tracing::warn!(interface = name, error = %cleanup, "cannot remove newly created unlabelled link");
                }
                return Err(error);
            }
            changed = true;
            k.read_link(name).await?.unwrap_or_default()
        }
    };
    if link.public_key != key.public || link.listen_port != i.listen_port {
        let port = i.listen_port.to_string();
        let key = base64::engine::general_purpose::STANDARD.encode(key.private);
        kernel::run!(
            k,
            "wg set {name} private-key /dev/stdin listen-port {port}",
            stdin = key
        )
        .await?;
        changed = true;
    }
    if link.mtu != i.mtu {
        kernel::run!(k, "ip link set dev {name} mtu {mtu}").await?;
        changed = true;
    }
    let extra: Vec<&String> = link
        .addresses
        .iter()
        .filter(|a| !i.addresses.contains(a) && !is_link_local(a))
        .collect();
    let missing = i.addresses.iter().any(|a| !link.addresses.contains(a));
    for address in &extra {
        // Deleting a primary IPv4 address can also remove secondary addresses in the same subnet,
        // so ignore "Cannot assign requested address" if an address is already gone.
        if let Err(e) = kernel::run!(k, "ip address delete {address} dev {name}").await
            && !e.cause_contains("Cannot assign requested address")
        {
            return Err(e);
        }
    }
    if missing || !extra.is_empty() {
        for address in i.addresses.iter() {
            kernel::run!(k, "ip address replace {address} dev {name}").await?;
        }
        changed = true;
    }
    if !link.up {
        kernel::run!(k, "ip link set dev {name} up").await?;
        changed = true;
    }
    if changed {
        k.read_link(name).await
    } else {
        Ok(Some(link))
    }
}

fn is_link_local(address: &str) -> bool {
    match address.parse::<ipnet::IpNet>().map(|p| p.addr()) {
        Ok(std::net::IpAddr::V4(a)) => a.is_link_local(),
        Ok(std::net::IpAddr::V6(a)) => a.is_unicast_link_local(),
        Err(_) => false,
    }
}

fn verify_link(app: &App, plan: &InterfaceReconcilePlan) -> std::result::Result<(), String> {
    let (name, i) = (&plan.name, &plan.interface);
    let Some(link) = &plan.link else {
        return if i.disabled {
            Ok(())
        } else {
            Err(format!("{name} is missing"))
        };
    };
    if link.alias != format_alias(name) {
        return Err(format!("{name} has alias {:?}", link.alias));
    }
    if i.disabled {
        return if link.up || !link.peers.is_empty() {
            Err(format!("{name} is not down and empty"))
        } else {
            Ok(())
        };
    }
    let public_key = app.server_keys.get(name).map(|k| k.public.as_str());
    if !link.up
        || Some(link.public_key.as_str()) != public_key
        || link.listen_port != i.listen_port
        || link.mtu != i.mtu
    {
        return Err(format!("{name} link settings differ after apply"));
    }
    if let Some(a) = i.addresses.iter().find(|a| !link.addresses.contains(a)) {
        return Err(format!("{name} lacks address {a}"));
    }
    if link.peers.len() != plan.requested_peers.len()
        || plan
            .requested_peers
            .iter()
            .any(|(k, w)| !plan.is_peer_installed(k, w))
    {
        return Err(format!("{name} peers differ after apply"));
    }
    Ok(())
}

// --- Database state persistence and link retirement ---

async fn save_state_to_db(app: &App, plans: Vec<InterfaceReconcilePlan>) -> Result<()> {
    let mut tx = app.db.begin_write().await?;
    for plan in &plans {
        let name = &plan.name;
        // Record only a generic interface failure on individual devices so kernel error messages do
        // not leak details about other accounts' peers.
        let failed = plan
            .error
            .as_ref()
            .map(|_| format!("interface {name} failed to apply"));
        for mut d in device::Entity::find()
            .filter(device::Column::InterfaceId.eq(name))
            .all(&*tx)
            .await?
        {
            let seen = plan.devices.get(&d.id);
            let unchanged = seen
                .is_some_and(|s| devices::extract_peer_view(s) == devices::extract_peer_view(&d));
            if d.deleting && unchanged && plan.removals_verified {
                device::Entity::delete_by_id(&d.id).exec(&*tx).await?;
                if d.dns_name.is_some() {
                    tx.mark_dns_changed();
                }
                continue;
            }
            if let Some(error) = &failed {
                if &d.apply_error != error {
                    d.apply_error = error.clone();
                    tx.update::<device::ActiveModel>(d).await?;
                }
                continue;
            }
            if !unchanged || d.deleting {
                continue;
            }
            let on = plan.enabled[&d.id];
            if d.applied_revision != d.revision
                || d.applied_enabled != on
                || !d.apply_error.is_empty()
            {
                d.applied_revision = d.revision;
                d.applied_enabled = on;
                d.apply_error.clear();
                tx.update::<device::ActiveModel>(d).await?;
            }
        }
    }
    tx.commit().await?;
    let mut status = app.interface_status.lock().expect("status lock");
    for plan in plans {
        let error = plan.error.unwrap_or_default();
        let old = status.insert(
            plan.name.clone(),
            InterfaceStatus {
                applied: error.is_empty(),
                apply_error: error.clone(),
            },
        );
        let old_error = old.map(|o| o.apply_error).unwrap_or_default();
        if !error.is_empty() && error != old_error {
            tracing::warn!(interface = %plan.name, %error, "apply failed");
        } else if error.is_empty() && !old_error.is_empty() {
            tracing::info!(interface = %plan.name, "apply recovered");
        }
    }
    Ok(())
}

async fn retire_unconfigured(app: &App) -> Result<()> {
    let k = &app.kernel;
    let mut delete_failed_names = Vec::new();
    for (name, alias) in k.list_links().await? {
        if !alias.starts_with(ALIAS_PREFIX) || app.config.interfaces.contains_key(&name) {
            continue;
        }
        if let Err(e) = kernel::run!(k, "ip link delete dev {name}").await {
            tracing::warn!(interface = %name, error = %e, "cannot delete a retired link");
            delete_failed_names.push(name);
        }
    }
    let live_names: Vec<&String> = app.config.interfaces.keys().collect();
    let mut tx = app.db.begin_write().await?;
    for mut d in device::Entity::find()
        .filter(device::Column::InterfaceId.is_not_in(live_names))
        .filter(device::Column::InterfaceId.is_not_in(&delete_failed_names))
        .all(&*tx)
        .await?
    {
        if d.deleting {
            device::Entity::delete_by_id(&d.id).exec(&*tx).await?;
            if d.dns_name.is_some() {
                tx.mark_dns_changed();
            }
            continue;
        }
        if d.applied_revision != d.revision || d.applied_enabled || !d.apply_error.is_empty() {
            d.applied_revision = d.revision;
            d.applied_enabled = false;
            d.apply_error.clear();
            tx.update::<device::ActiveModel>(d).await?;
        }
    }
    tx.commit().await
}
