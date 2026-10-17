//! Interfaces through the API: their views, apply errors and kernel diagnostics.

use crate::common::*;
use axum::http::StatusCode;
use ito::kernel::Link;
use serde_json::json;

/// Leaves a foreign link named `wg0` in the kernel so that applying `wg0` fails.
async fn fail_to_apply_wg0(env: &Env) {
    env.kernel.insert_link("wg0", Link::default());
    env.sync().await;
}

#[tokio::test]
async fn interfaces_are_listed_with_their_server_keys() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let list = env
        .get(&user, "/api/v1/interfaces")
        .await
        .expect(StatusCode::OK);
    let seen: Vec<_> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|i| (i["name"].clone(), i["public_key"].clone()))
        .collect();
    let keys = [derive_test_key(1), derive_test_key(2)];
    assert_eq!(
        seen,
        [
            (json!("wg0"), json!(keys[0])),
            (json!("wg1"), json!(keys[1]))
        ]
    );
}

#[tokio::test]
async fn unknown_interfaces_are_not_found() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let reply = env.get(&user, "/api/v1/interfaces/wg9").await;
    assert_eq!(reply.code(), "not_found");
}

#[tokio::test]
async fn administrators_see_apply_errors() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    fail_to_apply_wg0(&env).await;
    let i = env
        .get(&admin, "/api/v1/interfaces/wg0")
        .await
        .expect(StatusCode::OK);
    assert_eq!(i["applied"], false);
    let error = i["apply_error"].as_str().unwrap();
    assert!(error.contains("interface_ownership_mismatch"), "{error}");
}

#[tokio::test]
async fn members_do_not_see_apply_errors() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    fail_to_apply_wg0(&env).await;
    let i = env
        .get(&user, "/api/v1/interfaces/wg0")
        .await
        .expect(StatusCode::OK);
    assert_eq!(
        (&i["applied"], &i["apply_error"]),
        (&json!(false), &json!(""))
    );
}

#[tokio::test]
async fn diagnostics_show_the_observed_links() {
    let env = start_env().await;
    let admin = env.sign_in("admin", true).await;
    env.sync().await;
    let list = env
        .get(&admin, "/api/v1/diagnostics")
        .await
        .expect(StatusCode::OK);
    let observed = &list[0]["observed"];
    assert_eq!(list[0]["interface_id"], "wg0");
    let key = derive_test_key(1);
    assert_eq!(
        (&observed["public_key"], &observed["up"]),
        (&json!(key), &json!(true))
    );
}

#[tokio::test]
async fn members_cannot_read_diagnostics() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let reply = env.get(&user, "/api/v1/diagnostics").await;
    assert_eq!(reply.code(), "forbidden");
}
