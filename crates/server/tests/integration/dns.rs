//! The authoritative DNS zone of device names.

use crate::common::*;
use axum::http::StatusCode;
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use ito::config::{Dns, Pool};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};

/// Starts a controller whose interfaces share the zone `vpn.example.test`, where `wg0` also has
/// the IPv6 pool `fd00::/64`.
async fn start_dns_env() -> Env {
    start_env_with(|c| {
        c.dns = Some(Dns {
            listen: "127.0.0.1:0".parse().unwrap(),
            name_server: "ns.example.test".into(),
            ttl: 60,
        });
        for i in c.interfaces.values_mut() {
            i.dns_zone = "vpn.example.test".into();
        }
        let wg0 = c.interfaces.get_mut("wg0").unwrap();
        wg0.addresses.push("fd00::1/64".into());
        wg0.pools.push(Pool {
            prefix: "fd00::/64".parse().unwrap(),
            ..Pool::default()
        });
    })
    .await
}

/// Creates a device on `interface_id` that publishes `dns_name`, returning its ID.
async fn create_named_device(env: &Env, s: &Session, interface_id: &str, dns_name: &str) -> String {
    let body = json!({ "interface_id": interface_id, "name": "x", "dns_name": dns_name });
    let reply = env.call(s, "POST", "/api/v1/devices", None, body).await;
    read_id(&reply.expect(StatusCode::CREATED))
}

async fn resolve(server: SocketAddr, name: &str, kind: RecordType) -> Message {
    let mut query = Message::query();
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query.to_vec().unwrap(), server)
        .await
        .unwrap();
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

/// Resolves `name` as `A` until the answer has `code`. The zone follows committed changes in a
/// task of its own, so a change shows after a moment; give up after five seconds.
async fn resolve_until(server: SocketAddr, name: &str, code: ResponseCode) -> Message {
    let wait = async {
        loop {
            let answer = resolve(server, name, RecordType::A).await;
            if answer.response_code == code {
                return answer;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .unwrap_or_else(|_| panic!("{name} never answered {code:?}"))
}

/// Reads the data of each answer record as text.
fn read_answers(message: &Message) -> Vec<String> {
    message.answers.iter().map(|r| r.data.to_string()).collect()
}

#[tokio::test]
async fn names_resolve_to_device_addresses_in_any_case() {
    let env = start_dns_env().await;
    let user = env.sign_in("user", false).await;
    create_named_device(&env, &user, "wg0", "laptop").await;
    let server = ito::dns::serve(env.app.clone()).await.unwrap();
    let answer = resolve(server, "LAPTOP.vpn.example.test.", RecordType::A).await;
    assert_eq!(read_answers(&answer), ["10.0.0.2"]);
    assert!(answer.authoritative);
}

#[tokio::test]
async fn ipv6_addresses_resolve_as_aaaa() {
    let env = start_dns_env().await;
    let user = env.sign_in("user", false).await;
    create_named_device(&env, &user, "wg0", "laptop").await;
    let server = ito::dns::serve(env.app.clone()).await.unwrap();
    let answer = resolve(server, "laptop.vpn.example.test.", RecordType::AAAA).await;
    assert_eq!(read_answers(&answer), ["fd00::2"]);
}

#[tokio::test]
async fn interfaces_with_one_zone_share_it() {
    let env = start_dns_env().await;
    let user = env.sign_in("user", false).await;
    create_named_device(&env, &user, "wg1", "phone").await;
    let server = ito::dns::serve(env.app.clone()).await.unwrap();
    let answer = resolve(server, "phone.vpn.example.test.", RecordType::A).await;
    assert_eq!(read_answers(&answer), ["10.1.0.2"]);
}

#[tokio::test]
async fn unknown_names_do_not_exist() {
    let env = start_dns_env().await;
    let server = ito::dns::serve(env.app.clone()).await.unwrap();
    let answer = resolve(server, "other.vpn.example.test.", RecordType::A).await;
    assert_eq!(answer.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn names_outside_the_zone_are_refused() {
    let env = start_dns_env().await;
    let server = ito::dns::serve(env.app.clone()).await.unwrap();
    let answer = resolve(server, "example.org.", RecordType::A).await;
    assert_eq!(answer.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn zone_transfers_are_refused() {
    let env = start_dns_env().await;
    let server = ito::dns::serve(env.app.clone()).await.unwrap();
    let answer = resolve(server, "vpn.example.test.", RecordType::AXFR).await;
    assert_eq!(answer.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn the_zone_apex_names_the_name_server() {
    let env = start_dns_env().await;
    let server = ito::dns::serve(env.app.clone()).await.unwrap();
    let ns = resolve(server, "vpn.example.test.", RecordType::NS).await;
    assert_eq!(read_answers(&ns), ["ns.example.test."]);
    let soa = resolve(server, "vpn.example.test.", RecordType::SOA).await;
    let soa = read_answers(&soa);
    assert!(
        soa[0].starts_with("ns.example.test. hostmaster.vpn.example.test. "),
        "{soa:?}"
    );
}

#[tokio::test]
async fn cleared_names_leave_the_zone() {
    let env = start_dns_env().await;
    let user = env.sign_in("user", false).await;
    let id = create_named_device(&env, &user, "wg0", "laptop").await;
    let server = ito::dns::serve(env.app.clone()).await.unwrap();
    let revision = env.read_device_row(&id).await.unwrap().revision;
    let path = format!("/api/v1/devices/{id}");
    let cleared = json!({ "dns_name": "" });
    let reply = env
        .call(&user, "PATCH", &path, Some(revision), cleared)
        .await;
    reply.expect(StatusCode::OK);
    resolve_until(server, "laptop.vpn.example.test.", ResponseCode::NXDomain).await;
}

#[tokio::test]
async fn deleted_devices_leave_the_zone() {
    let env = start_dns_env().await;
    let user = env.sign_in("user", false).await;
    let id = create_named_device(&env, &user, "wg0", "laptop").await;
    let server = ito::dns::serve(env.app.clone()).await.unwrap();
    let path = format!("/api/v1/devices/{id}");
    let reply = env.call(&user, "DELETE", &path, None, Value::Null).await;
    reply.expect(StatusCode::OK);
    env.sync().await;
    resolve_until(server, "laptop.vpn.example.test.", ResponseCode::NXDomain).await;
}

#[tokio::test]
async fn names_given_later_join_the_zone() {
    let env = start_dns_env().await;
    let user = env.sign_in("user", false).await;
    let d = env.create_device(&user, "wg0").await;
    let server = ito::dns::serve(env.app.clone()).await.unwrap();
    let path = format!("/api/v1/devices/{}", read_id(&d));
    let named = json!({ "dns_name": "laptop" });
    let reply = env
        .call(&user, "PATCH", &path, read_revision(&d), named)
        .await;
    reply.expect(StatusCode::OK);
    let answer = resolve_until(server, "laptop.vpn.example.test.", ResponseCode::NoError).await;
    assert_eq!(read_answers(&answer), ["10.0.0.2"]);
}

#[tokio::test]
async fn names_are_unique_across_interfaces() {
    let env = start_dns_env().await;
    let user = env.sign_in("user", false).await;
    create_named_device(&env, &user, "wg0", "laptop").await;
    let body = json!({ "interface_id": "wg1", "name": "x", "dns_name": "Laptop" });
    let reply = env.call(&user, "POST", "/api/v1/devices", None, body).await;
    assert_eq!(reply.code(), "dns_name_taken");
}

#[tokio::test]
async fn clients_search_the_zone() {
    let env = start_dns_env().await;
    let user = env.sign_in("user", false).await;
    let d = env.create_device(&user, "wg0").await;
    let path = format!("/api/v1/devices/{}/config", read_id(&d));
    let config = env.get(&user, &path).await.expect(StatusCode::OK);
    assert_eq!(config["dns_search"], json!(["vpn.example.test"]));
}
