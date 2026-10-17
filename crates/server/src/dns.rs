use crate::{App, db::*, devices};
use hickory_proto::rr::{
    LowerName, Name, RData, Record, RecordSet, RecordType, RrKey,
    rdata::{A, AAAA, NS, SOA},
};
use hickory_server::{
    Server,
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{AxfrPolicy, Catalog, ZoneType},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

struct Zone {
    handler: Arc<InMemoryZoneHandler>,
    origin: Name,
    ttl: u32,
}

type Records = BTreeMap<RrKey, Arc<RecordSet>>;

fn is_address(key: &RrKey) -> bool {
    matches!(key.record_type, RecordType::A | RecordType::AAAA)
}

impl Zone {
    fn qualify(&self, label: &str) -> Option<Name> {
        Name::from_ascii(label)
            .ok()?
            .append_domain(&self.origin)
            .ok()
    }

    /// Builds the `A` and `AAAA` record sets for `label` in this zone.
    fn build_address_sets(&self, label: &str, addresses: &[IpAddr]) -> Records {
        let Some(name) = self.qualify(label) else {
            return Records::new();
        };
        let mut sets = Records::new();
        for address in addresses {
            let data = match address {
                IpAddr::V4(a) => RData::A(A(*a)),
                IpAddr::V6(a) => RData::AAAA(AAAA(*a)),
            };
            let key = RrKey::new(LowerName::new(&name), data.record_type());
            let set = sets.entry(key).or_insert_with(|| {
                Arc::new(RecordSet::with_ttl(
                    name.clone(),
                    data.record_type(),
                    self.ttl,
                ))
            });
            Arc::make_mut(set).insert(Record::from_rdata(name.clone(), self.ttl, data), 0);
        }
        sets
    }

    /// Atomically replaces all `A` and `AAAA` records in the zone with `new` and increments the
    /// `SOA` serial if the record set changed.
    async fn replace(&self, new: Records) {
        let mut records = self.handler.records_mut().await;
        let old: Records = records
            .iter()
            .filter(|(k, _)| is_address(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if old == new {
            return;
        }
        records.retain(|k, _| !is_address(k));
        records.extend(new);
        let key = RrKey::new(LowerName::new(&self.origin), RecordType::SOA);
        let soa = records
            .get(&key)
            .and_then(|set| set.records_without_rrsigs().next().cloned());
        if let Some(mut record) = soa
            && let RData::SOA(soa) = &mut record.data
        {
            soa.increment_serial();
            records.insert(key, Arc::new(RecordSet::from(record)));
        }
    }
}

/// Reloads all device `dns_name` records from the database into their respective interface zones.
async fn reload(zones: &BTreeMap<String, Zone>, app: &App) -> Result<(), sea_orm::DbErr> {
    let mut sets: BTreeMap<&str, Records> =
        zones.keys().map(|z| (z.as_str(), Records::new())).collect();
    for d in device::Entity::find()
        .filter(device::Column::DnsName.is_not_null())
        .all(&app.db.conn)
        .await?
    {
        let interface = app.config.interfaces.get(&d.interface_id);
        let Some(name) = interface
            .map(|i| i.dns_zone.as_str())
            .filter(|z| !z.is_empty())
        else {
            continue;
        };
        let label = d.dns_name.as_deref().unwrap_or_default();
        let records = zones[name].build_address_sets(label, &devices::collect_dns_addresses(&d));
        sets.get_mut(name).expect("a set per zone").extend(records);
    }
    for (name, records) in sets {
        zones[name].replace(records).await;
    }
    Ok(())
}

/// Starts the authoritative UDP and TCP DNS server for all configured interface zones and returns
/// the bound socket address.
pub async fn serve(app: Arc<App>) -> Result<SocketAddr, String> {
    let dns = app.config.dns.clone().ok_or("DNS is not configured")?;
    // Append a trailing dot to form a fully qualified domain name.
    let parse_fqdn = |s: &str| Name::from_ascii(format!("{s}.")).map_err(|e| e.to_string());
    let server_name = parse_fqdn(&dns.name_server)?;
    // Initialize the in-memory SOA serial from the current Unix timestamp so it increases across
    // process restarts.
    let serial = chrono::Utc::now().timestamp() as u32;
    let mut zones = BTreeMap::new();
    let mut catalog = Catalog::new();
    for name in app.config.interfaces.values().map(|i| &i.dns_zone) {
        if name.is_empty() || zones.contains_key(name) {
            continue;
        }
        let origin = parse_fqdn(name)?;
        let mut handler =
            InMemoryZoneHandler::empty(origin.clone(), ZoneType::Primary, AxfrPolicy::Deny);
        let soa = SOA::new(
            server_name.clone(),
            parse_fqdn(&format!("hostmaster.{name}"))?,
            serial,
            3600,
            600,
            86400,
            dns.ttl,
        );
        handler.upsert_mut(
            Record::from_rdata(origin.clone(), dns.ttl, RData::SOA(soa)),
            serial,
        );
        handler.upsert_mut(
            Record::from_rdata(origin.clone(), dns.ttl, RData::NS(NS(server_name.clone()))),
            serial,
        );
        let handler = Arc::new(handler);
        catalog.upsert(LowerName::new(&origin), vec![handler.clone()]);
        let zone = Zone {
            handler,
            origin,
            ttl: dns.ttl,
        };
        zones.insert(name.clone(), zone);
    }
    reload(&zones, &app).await.map_err(|e| e.to_string())?;

    let mut server = Server::new(catalog);
    let udp = tokio::net::UdpSocket::bind(dns.listen)
        .await
        .map_err(|e| format!("DNS listener {}: {e}", dns.listen))?;
    let address = udp.local_addr().map_err(|e| e.to_string())?;
    let tcp = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|e| format!("DNS listener {address}: {e}"))?;
    server.register_socket(udp);
    server.register_listener(tcp, Duration::from_secs(5), 64);
    tokio::spawn(async move {
        if let Err(e) = server.block_until_done().await {
            tracing::error!(error = %e, "DNS server stopped");
        }
    });
    tokio::spawn(async move {
        loop {
            // Reload immediately when a committed transaction modifies DNS records, or every 60
            // seconds to retry any failed reload.
            let _ = tokio::time::timeout(Duration::from_secs(60), app.db.wait_dns_changed()).await;
            if let Err(e) = reload(&zones, &app).await {
                tracing::error!(error = %e, "DNS update failed");
            }
        }
    });
    Ok(address)
}
