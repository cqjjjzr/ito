//! Endpoints outside the JSON API: health checks, metrics and problem pages.

use crate::common::*;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ito::{config::Scim, error::Code};

async fn read_metrics(env: &Env) -> String {
    let router = ito::http::metrics::build_router(env.app.clone());
    let request = Request::get("/metrics").body(Body::empty()).unwrap();
    let reply = send(&router, request).await;
    assert_eq!(reply.status, StatusCode::OK);
    reply.text
}

#[tokio::test]
async fn health_checks_answer_ok() {
    let env = start_env().await;
    for path in ["/health/live", "/health/ready"] {
        let reply = env
            .send(Request::get(path).body(Body::empty()).unwrap())
            .await;
        assert_eq!(
            (reply.status, reply.text.as_str()),
            (StatusCode::OK, "ok"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn metrics_count_devices_waiting_for_the_reconciler() {
    let env = start_env().await;
    let user = env.sign_in("user", false).await;
    env.create_device(&user, "wg0").await;
    assert!(
        read_metrics(&env)
            .await
            .contains("\nito_devices_pending 1\n")
    );
    env.sync().await;
    assert!(
        read_metrics(&env)
            .await
            .contains("\nito_devices_pending 0\n")
    );
}

#[tokio::test]
async fn metrics_count_status_check_errors_only_with_scim() {
    let env = start_env().await;
    assert!(
        !read_metrics(&env)
            .await
            .contains("ito_account_idp_check_errors")
    );
    let env = env.restart(|c| {
        c.scim = Some(Scim {
            url: "http://identity.test/scim/v2".into(),
            ..Scim::default()
        });
    });
    let metrics = read_metrics(&env).await;
    assert!(
        metrics.contains("\nito_account_idp_check_errors 0\n"),
        "{metrics}"
    );
}

#[tokio::test]
async fn every_error_code_has_a_problem_page() {
    let env = start_env().await;
    for code in Code::ALL.iter().map(|c| c.as_str()) {
        let path = format!("/api/v1/problems/{code}");
        let reply = env
            .send(Request::get(path).body(Body::empty()).unwrap())
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{code}");
        assert!(reply.text.contains(code), "{code}");
    }
}

#[tokio::test]
async fn unknown_error_codes_have_no_problem_page() {
    let env = start_env().await;
    let request = Request::get("/api/v1/problems/nonsense")
        .body(Body::empty())
        .unwrap();
    assert_eq!(env.send(request).await.code(), "not_found");
}
