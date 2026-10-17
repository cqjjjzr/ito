//! Shared fixtures: a controller on a temporary database and a fake kernel, signed-in sessions,
//! devices with agents, and request helpers.

pub mod idp;
pub mod kernel;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, request},
};
use base64::Engine as _;
use chrono::{TimeDelta, Utc};
use http_body_util::BodyExt;
use ito::{
    App, accounts,
    config::{Config, Interface, Pool},
    db::*,
    http::{
        self,
        extract::build_cookie_name,
        secrets::{digest_sha256, generate_secret},
    },
    kernel::KernelDriver,
    wireguard_keys::derive_public_key,
};
pub use kernel::FakeKernel;
use sea_orm::EntityTrait;
use serde_json::{Value, json};
use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc};
use tower::ServiceExt;

/// The browser origin of the controller under test.
pub const ORIGIN: &str = "http://portal.test";

/// A controller under test, its fake kernel, and the directory holding its database and secrets.
pub struct Env {
    pub app: Arc<App>,
    pub router: Router,
    pub kernel: Arc<FakeKernel>,
    _dir: tempfile::TempDir,
}

/// A browser session created by [`Env::sign_in`].
pub struct Session {
    pub account_id: String,
    pub cookie: String,
    pub csrf: String,
}

/// A response with its body read: as JSON when it parses, and as text.
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
    pub text: String,
}

impl Reply {
    /// Returns the problem code of an error reply, or "" when the body has none.
    pub fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }

    /// Returns the body after checking the status, showing the body when the status differs.
    pub fn expect(self, status: StatusCode) -> Value {
        assert_eq!(self.status, status, "{}", self.text);
        self.body
    }
}

/// Derives the WireGuard public key of the private key made of 32 bytes `n`. Keys 1 and 2 belong
/// to the servers of `wg0` and `wg1`.
pub fn derive_test_key(n: u8) -> String {
    derive_public_key(&[n; 32])
}

/// Reads the `revision` of a device or account view.
pub fn read_revision(v: &Value) -> Option<i64> {
    v["revision"].as_i64()
}

/// Reads the `id` of a device or account view.
pub fn read_id(v: &Value) -> String {
    v["id"].as_str().unwrap().into()
}

fn write_secret(dir: &Path, name: &str, value: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, value).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

/// Starts a controller with interfaces `wg0` and `wg1`, each with the address `10.N.0.1/24` and the
/// pool `10.N.0.0/24`.
pub async fn start_env() -> Env {
    start_env_with(|_| {}).await
}

/// Starts a controller like [`start_env`] with its configuration changed by `change`.
pub async fn start_env_with(change: impl FnOnce(&mut Config)) -> Env {
    let kernel = Arc::new(FakeKernel::default());
    start_env_on(kernel.clone(), kernel, change).await
}

/// Starts a controller like [`start_env_with`] that drives `kernel` instead of the fake one.
pub async fn start_env_with_kernel(
    kernel: Arc<dyn KernelDriver>,
    change: impl FnOnce(&mut Config),
) -> Env {
    start_env_on(kernel, Arc::default(), change).await
}

async fn start_env_on(
    driver: Arc<dyn KernelDriver>,
    kernel: Arc<FakeKernel>,
    change: impl FnOnce(&mut Config),
) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config {
        public_url: ORIGIN.into(),
        database: dir.path().join("ito.db"),
        ..Config::default()
    };
    config.oidc.issuer = "http://identity.test/realms/ito".into();
    config.oidc.client_id = "portal".into();
    config.oidc.secret_file = write_secret(dir.path(), "oidc", "secret");
    write_secret(dir.path(), "status", "secret");
    for n in 0..2u8 {
        let key = base64::engine::general_purpose::STANDARD.encode([n + 1; 32]);
        let pool = Pool {
            prefix: format!("10.{n}.0.0/24").parse().unwrap(),
            min_prefix_length: Some(28),
            max_prefixes: 4,
            ..Pool::default()
        };
        let interface = Interface {
            private_key_file: write_secret(dir.path(), &format!("wg{n}.key"), &key),
            listen_port: 51820 + i32::from(n),
            endpoint: "vpn.test:51820".into(),
            addresses: vec![format!("10.{n}.0.1/24")],
            pools: vec![pool],
            ..Interface::default()
        };
        config.interfaces.insert(format!("wg{n}"), interface);
    }
    change(&mut config);
    let db = Db::connect(&config.database).await.unwrap();
    let app = App::new(config, db, driver).unwrap();
    Env {
        router: http::build_router(app.clone()),
        app,
        kernel,
        _dir: dir,
    }
}

/// Sends `request` through `router` and reads the whole response.
pub async fn send(router: &Router, request: Request<Body>) -> Reply {
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        text: String::from_utf8_lossy(&bytes).into(),
    }
}

impl Env {
    /// Restarts the controller with its configuration changed by `change`, keeping the database
    /// and the kernel.
    pub fn restart(self, change: impl FnOnce(&mut Config)) -> Env {
        let Env {
            app,
            router,
            kernel,
            _dir,
        } = self;
        drop(router);
        let app = Arc::into_inner(app).expect("nothing else holds the app");
        let mut config = app.config;
        change(&mut config);
        let app = App::new(config, app.db, app.kernel).unwrap();
        Env {
            router: http::build_router(app.clone()),
            app,
            kernel,
            _dir,
        }
    }

    /// Creates an active account for `subject`, checked at the identity provider just now, and a
    /// browser session for it.
    pub async fn sign_in(&self, subject: &str, admin: bool) -> Session {
        let tx = self.app.db.begin_write().await.unwrap();
        let now = Utc::now();
        let account_id = generate_id();
        tx.insert::<account::ActiveModel>(account::Model {
            id: account_id.clone(),
            subject: subject.into(),
            display_name: subject.into(),
            blocked: false,
            idp_status: account::IdpStatus::Active,
            idp_checked_at: Some(now),
            idp_check_error: false,
            quota_ipv4: String::new(),
            quota_ipv6: String::new(),
            revision: 1,
            created_at: now,
        })
        .await
        .unwrap();
        let cookie = generate_secret();
        let csrf = generate_secret();
        tx.insert::<session::ActiveModel>(session::Model {
            id: digest_sha256(&cookie),
            account_id: account_id.clone(),
            admin,
            csrf: csrf.clone(),
            expires_at: now + TimeDelta::hours(1),
            last_seen: now,
        })
        .await
        .unwrap();
        tx.commit().await.unwrap();
        Session {
            account_id,
            cookie,
            csrf,
        }
    }

    pub async fn send(&self, request: Request<Body>) -> Reply {
        send(&self.router, request).await
    }

    /// Starts a browser request from the session `s`: its cookie, the portal origin and its CSRF
    /// token.
    pub fn build_request(&self, s: &Session, method: &str, path: &str) -> request::Builder {
        let cookie = build_cookie_name(&self.app, "session");
        Request::builder()
            .method(method)
            .uri(path)
            .header("cookie", format!("{cookie}={}", s.cookie))
            .header("origin", ORIGIN)
            .header("x-csrf-token", &s.csrf)
    }

    /// Sends a browser request with the JSON `body`, and `If-Match` when `revision` is given.
    pub async fn call(
        &self,
        s: &Session,
        method: &str,
        path: &str,
        revision: Option<i64>,
        body: Value,
    ) -> Reply {
        let mut r = self
            .build_request(s, method, path)
            .header("content-type", "application/json");
        if let Some(revision) = revision {
            r = r.header("if-match", format!("\"{revision}\""));
        }
        self.send(r.body(Body::from(body.to_string())).unwrap())
            .await
    }

    pub async fn get(&self, s: &Session, path: &str) -> Reply {
        self.call(s, "GET", path, None, Value::Null).await
    }

    /// Sends a device-API request with the agent bearer `token`, like [`Env::call`].
    pub async fn call_as_agent(
        &self,
        token: &str,
        method: &str,
        path: &str,
        revision: Option<i64>,
        body: Value,
    ) -> Reply {
        let mut r = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json");
        if let Some(revision) = revision {
            r = r.header("if-match", format!("\"{revision}\""));
        }
        self.send(r.body(Body::from(body.to_string())).unwrap())
            .await
    }

    /// Runs one reconcile pass.
    pub async fn sync(&self) {
        ito::reconcile::sync(&self.app).await.unwrap();
    }

    /// Creates a device named `laptop` on `interface_id` for the session's account.
    pub async fn create_device(&self, s: &Session, interface_id: &str) -> Value {
        let body = json!({ "interface_id": interface_id, "name": "laptop" });
        self.call(s, "POST", "/api/v1/devices", None, body)
            .await
            .expect(StatusCode::CREATED)
    }

    /// Approves, as the session `s`, the agent login request made with `secret` for the device.
    pub async fn approve_claim(&self, s: &Session, device_id: &str, secret: &str) -> Reply {
        let approval = json!({ "id": digest_sha256(secret), "t": Utc::now().timestamp() });
        let path = format!("/api/v1/devices/{device_id}/claims");
        self.call(s, "POST", &path, None, approval).await
    }

    /// Claims a device as an agent holding `secret` and the public key `key`, asking for the device
    /// `device_id` when given.
    pub async fn claim_device(&self, secret: &str, key: &str, device_id: Option<&str>) -> Reply {
        let body = json!({ "secret": secret, "public_key": key, "device_id": device_id });
        let request = Request::post("/api/v1/agent/claim")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        self.send(request).await
    }

    /// Approves and claims the device with `key`, returning the agent bearer token.
    pub async fn set_up_agent(&self, s: &Session, device_id: &str, key: &str) -> String {
        let secret = generate_secret();
        let approval = self.approve_claim(s, device_id, &secret).await;
        approval.expect(StatusCode::NO_CONTENT);
        let claimed = self.claim_device(&secret, key, None).await;
        claimed.expect(StatusCode::OK)["token"]
            .as_str()
            .unwrap()
            .into()
    }

    /// Creates a device on `interface_id` with an agent holding `key`, returning the device ID and
    /// the agent's bearer token.
    pub async fn create_device_with_agent(
        &self,
        s: &Session,
        interface_id: &str,
        key: &str,
    ) -> (String, String) {
        let id = read_id(&self.create_device(s, interface_id).await);
        let token = self.set_up_agent(s, &id, key).await;
        (id, token)
    }

    /// Sets the policy of the account `account_id` as the administrator `admin`.
    pub async fn set_policy(&self, admin: &Session, account_id: &str, policy: Value) -> Reply {
        let revision = self.read_account_row(account_id).await.revision;
        let path = format!("/api/v1/accounts/{account_id}/policy");
        self.call(admin, "PUT", &path, Some(revision), policy).await
    }

    /// Blocks the account `account_id` directly in the database, as an administrator's policy
    /// change does.
    pub async fn block_account(&self, account_id: &str) {
        let mut tx = self.app.db.begin_write().await.unwrap();
        let old = account::Entity::find_by_id(account_id)
            .one(&*tx)
            .await
            .unwrap()
            .unwrap();
        let blocked = account::Model {
            blocked: true,
            ..old.clone()
        };
        accounts::save(&mut tx, &self.app.approvals, &old, blocked)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    /// Ends the key of the device `device_id` a second ago, as if its lifetime ran out.
    pub async fn expire_key(&self, device_id: &str) {
        let tx = self.app.db.begin_write().await.unwrap();
        let d = device::Entity::find_by_id(device_id)
            .one(&*tx)
            .await
            .unwrap()
            .unwrap();
        let expired = device::Model {
            key_expires_at: Some(Utc::now() - TimeDelta::seconds(1)),
            ..d
        };
        tx.update::<device::ActiveModel>(expired).await.unwrap();
        tx.commit().await.unwrap();
    }

    pub async fn read_account_row(&self, id: &str) -> account::Model {
        account::Entity::find_by_id(id)
            .one(&self.app.db.conn)
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn read_device_row(&self, id: &str) -> Option<device::Model> {
        device::Entity::find_by_id(id)
            .one(&self.app.db.conn)
            .await
            .unwrap()
    }
}
