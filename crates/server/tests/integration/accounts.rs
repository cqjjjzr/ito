//! Accounts through the API: who may read them, their usage, policy and the audit log.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::{Value, json};

#[tokio::test]
async fn members_cannot_list_accounts() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    assert_eq!(env.get(&user, "/api/v1/accounts").await.code(), "forbidden");
}

#[tokio::test]
async fn members_cannot_read_other_accounts() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let other = env.sign_in("other", false).await;
    let path = format!("/api/v1/accounts/{}", other.account_id);
    assert_eq!(env.get(&user, &path).await.code(), "not_found");
}

#[tokio::test]
async fn accounts_report_address_usage_against_their_limits() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let block = json!([{ "pool": "10.0.0.0/24", "prefix_length": 29 }]);
    let body = json!({ "interface_id": "wg0", "name": "router", "allocate_grants": block });
    let reply = env
        .call(&admin, "POST", "/api/v1/devices", None, body)
        .await;
    reply.expect(StatusCode::CREATED);
    let path = format!("/api/v1/accounts/{}", admin.account_id);
    let a = env.get(&admin, &path).await.expect(StatusCode::OK);
    // One automatic host address and a block of eight.
    assert_eq!(a["usage"], json!({ "ipv4": "9", "ipv6": "0" }));
    assert_eq!(a["limits"], json!({ "ipv4": "16", "ipv6": "/64" }));
}

#[tokio::test]
async fn invalid_quotas_are_refused() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let user = env.sign_in("user", false).await;
    for (ipv4, ipv6) in [("many", ""), ("/33", ""), ("-1", ""), ("", "/129")] {
        let policy = json!({ "blocked": false, "quota": { "ipv4": ipv4, "ipv6": ipv6 } });
        let reply = env.set_policy(&admin, &user.account_id, policy).await;
        assert_eq!(reply.code(), "invalid_request", "{ipv4:?} {ipv6:?}");
    }
}

#[tokio::test]
async fn policy_changes_are_audited() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let user = env.sign_in("user", false).await;
    let policy = json!({ "blocked": false, "quota": { "ipv4": "4", "ipv6": "" } });
    let reply = env.set_policy(&admin, &user.account_id, policy).await;
    reply.expect(StatusCode::OK);
    let audit = env
        .get(&admin, "/api/v1/audit")
        .await
        .expect(StatusCode::OK);
    let entry = json!({
        "actor": format!("account:{}", admin.account_id),
        "action": "account.policy",
        "resource_id": user.account_id,
    });
    let first = &audit[0];
    let seen = json!({
        "actor": first["actor"],
        "action": first["action"],
        "resource_id": first["resource_id"],
    });
    assert_eq!(seen, entry);
}

#[tokio::test]
async fn administrators_cannot_block_themselves() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let policy = json!({ "blocked": true, "quota": { "ipv4": "", "ipv6": "" } });
    let reply = env.set_policy(&admin, &admin.account_id, policy).await;
    assert_eq!(reply.code(), "self_block_forbidden");
}

#[tokio::test]
async fn blocking_an_account_ends_its_sessions() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let user = env.sign_in("user", false).await;
    let policy = json!({ "blocked": true, "quota": { "ipv4": "", "ipv6": "" } });
    let reply = env.set_policy(&admin, &user.account_id, policy).await;
    reply.expect(StatusCode::OK);
    let reply = env.get(&user, "/api/v1/session").await;
    assert_eq!(reply.code(), "invalid_credentials");
}

#[tokio::test]
async fn audit_pages_hold_at_most_1000_entries() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let reply = env.get(&admin, "/api/v1/audit?limit=1001").await;
    assert_eq!(reply.code(), "invalid_request");
}

#[tokio::test]
async fn status_refresh_needs_scim() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    let reply = env
        .call(
            &admin,
            "POST",
            "/api/v1/accounts/refresh",
            None,
            Value::Null,
        )
        .await;
    assert_eq!(reply.code(), "invalid_request");
}
