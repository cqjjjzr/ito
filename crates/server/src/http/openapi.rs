use super::build_api;
use crate::error::{self, Code};
use axum::http::StatusCode;
use utoipa::{
    Modify, OpenApi,
    openapi::{
        RefOr, ResponseBuilder,
        content::ContentBuilder,
        schema::{Ref, Schema},
        security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
    },
};

#[derive(OpenApi)]
#[openapi(
    info(description = include_str!("api.md")),
    servers((url = "/", description = "The controller's `public_url`.")),
    components(schemas(error::Problem)),
    modifiers(&Security),
    tags(
        (name = "session", description = "OpenID Connect sign-in and browser session management."),
        (name = "accounts", description = "User accounts, account policies, SCIM status checks, and audit logs. Members can read their own account; administrators can manage all accounts."),
        (name = "interfaces", description = "Configured WireGuard interfaces, address pools, server public keys, and kernel reconciliation state."),
        (name = "devices", description = "WireGuard peer devices, keys, address grants, and agent claim approvals. Members manage their own devices; administrators manage all devices."),
        (name = "agent", description = "Endpoints called by the host agent (`ito-agent`) using a per-device bearer credential."),
    )
)]
pub(crate) struct ApiDoc;

struct Security;

impl Modify for Security {
    fn modify(&self, spec: &mut utoipa::openapi::OpenApi) {
        let c = spec.components.get_or_insert_default();
        c.add_security_scheme(
            "session",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                "__Host-ito_session",
                "Browser session secret sent in the `__Host-ito_session` cookie (`ito_session` when `cookie_secure = false`).",
            ))),
        );
        c.add_security_scheme(
            "csrf",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "X-CSRF-Token",
                "CSRF token read from the `__Host-ito_csrf` cookie and sent in the `X-CSRF-Token` header on mutating requests.",
            ))),
        );
        c.add_security_scheme(
            "agent",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "Device agent credential, sent as `Authorization: Bearer itoa_SECRET`.",
                    ))
                    .build(),
            ),
        );
    }
}

/// Builds the complete OpenAPI 3.1 specification for the HTTP API.
pub fn build_spec() -> utoipa::openapi::OpenApi {
    let mut spec = build_api().into_openapi();
    // Attach RFC 9457 Problem Details as the default error response on every operation.
    let error = ResponseBuilder::new()
        .description(
            "RFC 9457 Problem Details error response; see the `Problem` schema for error codes.",
        )
        .content(
            "application/problem+json",
            ContentBuilder::new()
                .schema(Some(Ref::from_schema_name("Problem")))
                .build(),
        )
        .build();
    for item in spec.paths.paths.values_mut() {
        for op in [
            &mut item.get,
            &mut item.put,
            &mut item.post,
            &mut item.delete,
            &mut item.patch,
        ]
        .into_iter()
        .flatten()
        {
            // Fill in the canonical HTTP reason phrase for responses with an empty description.
            for (status, response) in &mut op.responses.responses {
                if let (RefOr::T(r), Ok(code)) = (response, status.parse::<StatusCode>())
                    && r.description.is_empty()
                {
                    r.description = code.canonical_reason().unwrap_or_default().into();
                }
            }
            op.responses
                .responses
                .insert("default".into(), RefOr::T(error.clone()));
        }
    }
    // Append a markdown table of all `Code` variants to the `Problem` schema description.
    if let Some(RefOr::T(Schema::Object(problem))) = spec
        .components
        .as_mut()
        .and_then(|c| c.schemas.get_mut("Problem"))
    {
        let rows: String = Code::ALL
            .iter()
            .map(|c| {
                format!(
                    "\n| `{}` | {} | {} |",
                    c.as_str(),
                    c.status().as_u16(),
                    c.title()
                )
            })
            .collect();
        let intro = problem.description.take().unwrap_or_default();
        problem.description = Some(format!(
            "{intro}\n\n| Code | Status | Title |\n|---|---|---|{rows}"
        ));
    }
    spec
}
