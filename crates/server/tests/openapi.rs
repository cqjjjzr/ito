//! The published OpenAPI document must match the code. `just openapi` rewrites it.

#[test]
fn published_spec_is_current() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/modules/ROOT/attachments/openapi.json"
    );
    let spec = ito::http::openapi::build_spec().to_pretty_json().unwrap() + "\n";
    if std::env::var_os("UPDATE_OPENAPI").is_some() {
        std::fs::write(path, &spec).unwrap();
    }
    let published = std::fs::read_to_string(path).unwrap_or_default();
    assert!(published == spec, "{path} is stale; run `just openapi`");
}

#[test]
fn error_codes_are_published_as_sent() {
    let spec = serde_json::to_value(ito::http::openapi::build_spec()).unwrap();
    let published = &spec["components"]["schemas"]["Code"]["enum"];
    let sent: Vec<&str> = ito::error::Code::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(published, &serde_json::json!(sent));
}
