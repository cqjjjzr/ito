//! Rules every API request follows: CSRF protection, revision preconditions, and JSON bodies.

use crate::common::*;
use axum::{
    body::Body,
    http::{HeaderValue, StatusCode},
};
use serde_json::{Value, json};

/// Sends a note change for a fresh device of a fresh member, with `change` applied to the request.
async fn send_note_change(env: &Env, change: impl FnOnce(&mut axum::http::Request<Body>)) -> Reply {
    let user = env.sign_in("user", false).await;
    let d = env.create_device(&user, "wg0").await;
    let path = format!("/api/v1/devices/{}", read_id(&d));
    let revision = read_revision(&d).unwrap();
    let mut request = env
        .build_request(&user, "PATCH", &path)
        .header("content-type", "application/json")
        .header("if-match", format!("\"{revision}\""))
        .body(Body::from(json!({ "note": "x" }).to_string()))
        .unwrap();
    change(&mut request);
    env.send(request).await
}

#[tokio::test]
async fn writes_need_the_portal_origin_and_the_csrf_token() {
    for (case, header, value) in [
        ("foreign origin", "origin", Some("http://attacker.test")),
        ("missing origin", "origin", None),
        ("wrong token", "x-csrf-token", Some("wrong")),
        ("missing token", "x-csrf-token", None),
    ] {
        let env = start_env().await;
        let reply = send_note_change(&env, |r| match value {
            Some(v) => {
                r.headers_mut().insert(header, HeaderValue::from_static(v));
            }
            None => {
                r.headers_mut().remove(header);
            }
        })
        .await;
        assert_eq!(reply.code(), "forbidden", "{case}");
    }
}

#[tokio::test]
async fn writes_without_if_match_are_refused() {
    let env = start_env().await;
    let reply = send_note_change(&env, |r| {
        r.headers_mut().remove("if-match");
    })
    .await;
    assert_eq!(reply.code(), "precondition_required");
}

#[tokio::test]
async fn writes_with_a_stale_if_match_are_refused() {
    let env = start_env().await;
    let stale = HeaderValue::from_static("\"99\"");
    let reply = send_note_change(&env, |r| {
        r.headers_mut().insert("if-match", stale);
    })
    .await;
    assert_eq!(reply.code(), "revision_conflict");
}

#[tokio::test]
async fn malformed_if_match_is_invalid() {
    for value in ["1", "\"one\"", "W/\"1\""] {
        let env = start_env().await;
        let malformed = HeaderValue::from_static(value);
        let reply = send_note_change(&env, |r| {
            r.headers_mut().insert("if-match", malformed);
        })
        .await;
        assert_eq!(reply.code(), "invalid_request", "{value}");
    }
}

#[tokio::test]
async fn bodies_other_than_json_are_unsupported() {
    let env = start_env().await;
    let text = HeaderValue::from_static("text/plain");
    let reply = send_note_change(&env, |r| {
        r.headers_mut().insert("content-type", text);
    })
    .await;
    assert_eq!(reply.code(), "unsupported_media_type");
}

#[tokio::test]
async fn bodies_over_64_kib_are_refused() {
    let env = start_env().await;
    let note = "x".repeat(64 << 10);
    let reply = send_note_change(&env, |r| {
        *r.body_mut() = Body::from(json!({ "note": note }).to_string());
    })
    .await;
    assert_eq!(reply.code(), "request_too_large");
}

#[tokio::test]
async fn unknown_body_fields_are_ignored() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let body = json!({ "interface_id": "wg0", "name": "x", "surprise": 1 });
    let d = env
        .call(&user, "POST", "/api/v1/devices", None, body)
        .await
        .expect(StatusCode::CREATED);
    assert_eq!(d.get("surprise"), None);
}

#[tokio::test]
async fn unsupported_methods_answer_a_problem() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    let reply = env
        .call(&user, "PUT", "/api/v1/session", None, Value::Null)
        .await;
    assert_eq!(reply.code(), "method_not_allowed");
}
