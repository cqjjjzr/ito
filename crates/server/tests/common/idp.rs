use base64::Engine as _;
use openidconnect::{
    Audience, ClientId, IdTokenClaims, IssuerUrl, Nonce, StandardClaims, SubjectIdentifier,
    core::{
        CoreEdDsaPrivateSigningKey, CoreGenderClaim, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    },
};
use serde_json::json;
use sha2::Digest as _;
use wiremock::{
    Match, Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{body_string_contains, method, path, path_regex},
};

/// The Ed25519 key that signs ID tokens; its public half is served as the realm's JWKS.
const SIGNING_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIH+VsWFhh227j/iGgzexf1myFljv2KSYvWazNjcJoO0O\n-----END PRIVATE KEY-----\n";
const SIGNING_KEY_X: &str = "0kfkaU4Gq9i2KNbAd9pJBOe5xTRbKW4-9FOegW3etjo";

/// An identity provider on wiremock: the OpenID Connect realm `ito` and a SCIM user service.
pub struct Idp {
    pub server: MockServer,
}

/// Starts an identity provider that serves discovery, signing keys and client-credentials tokens.
/// SCIM users and ID tokens are added per test.
pub async fn start_idp() -> Idp {
    let server = MockServer::start().await;
    let issuer = format!("{}/realms/ito", server.uri());
    let discovery = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/auth"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/certs"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
    });
    Mock::given(method("GET"))
        .and(path("/realms/ito/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(discovery))
        .mount(&server)
        .await;
    let keys = json!({ "keys": [{ "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "x": SIGNING_KEY_X }] });
    Mock::given(method("GET"))
        .and(path("/realms/ito/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(keys))
        .mount(&server)
        .await;
    let token = json!({ "access_token": "status", "token_type": "Bearer", "expires_in": 300 });
    Mock::given(method("POST"))
        .and(path("/realms/ito/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token))
        .mount(&server)
        .await;
    Idp { server }
}

/// Claims of the next ID token: the sign-in's `nonce` and PKCE `challenge` from the authorization
/// URL, the authorized party `azp`, and the user's `groups`.
pub struct IdToken {
    pub nonce: String,
    pub challenge: String,
    pub azp: String,
    pub groups: Option<serde_json::Value>,
}

impl Idp {
    pub fn issuer(&self) -> String {
        format!("{}/realms/ito", self.server.uri())
    }

    pub fn scim_url(&self) -> String {
        format!("{}/scim/v2", self.server.uri())
    }

    /// Serves the SCIM user `id` as active or not. Users never served answer 404.
    pub async fn serve_scim_user(&self, id: &str, active: bool) {
        Mock::given(method("GET"))
            .and(path(format!("/scim/v2/Users/{id}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "id": id, "active": active })),
            )
            .mount(&self.server)
            .await;
    }

    /// Counts the SCIM user lookups received so far.
    pub async fn count_scim_lookups(&self) -> usize {
        let requests = self.server.received_requests().await.unwrap();
        let lookups = requests
            .iter()
            .filter(|r| path_regex("^/scim/v2/Users/").matches(r));
        lookups.count()
    }

    /// Answers authorization-code exchanges with an ID token for the subject `user-1` with `token`'s
    /// claims, if the code verifier matches its challenge.
    pub async fn serve_id_token(&self, token: IdToken) {
        Mock::given(method("POST"))
            .and(path("/realms/ito/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(IdTokenResponder {
                issuer: self.issuer(),
                token,
            })
            .mount(&self.server)
            .await;
    }
}

struct IdTokenResponder {
    issuer: String,
    token: IdToken,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Groups {
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<serde_json::Value>,
}

impl openidconnect::AdditionalClaims for Groups {}

impl Respond for IdTokenResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        // The form body parses as the query of a URL.
        let mut form = reqwest::Url::parse("http://form.invalid/").unwrap();
        form.set_query(Some(&String::from_utf8_lossy(&request.body)));
        let verifier = form
            .query_pairs()
            .find(|(k, _)| k == "code_verifier")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sha2::Sha256::digest(verifier.as_bytes()));
        if challenge != self.token.challenge {
            return ResponseTemplate::new(400).set_body_json(json!({ "error": "invalid_grant" }));
        }
        let now = chrono::Utc::now();
        let claims = IdTokenClaims::<Groups, CoreGenderClaim>::new(
            IssuerUrl::new(self.issuer.clone()).unwrap(),
            vec![Audience::new("portal".into())],
            now + chrono::Duration::minutes(5),
            now,
            StandardClaims::new(SubjectIdentifier::new("user-1".into())),
            Groups {
                groups: self.token.groups.clone(),
            },
        )
        .set_nonce(Some(Nonce::new(self.token.nonce.clone())))
        .set_authorized_party(Some(ClientId::new(self.token.azp.clone())));
        let key = CoreEdDsaPrivateSigningKey::from_ed25519_pem(SIGNING_KEY, None).unwrap();
        let id_token = openidconnect::IdToken::<
            Groups,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        >::new(claims, &key, CoreJwsSigningAlgorithm::EdDsa, None, None)
        .unwrap();
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "user",
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": id_token.to_string(),
        }))
    }
}
