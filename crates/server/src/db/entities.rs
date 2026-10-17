use chrono::{DateTime, Utc};
use sea_orm::{FromJsonQueryResult, entity::prelude::*};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, FromJsonQueryResult)]
#[serde(transparent)]
pub struct Strings(pub Vec<String>);

impl std::ops::Deref for Strings {
    type Target = Vec<String>;

    fn deref(&self) -> &Vec<String> {
        &self.0
    }
}

pub fn generate_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

pub mod account {
    use super::*;

    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        EnumIter,
        DeriveActiveEnum,
        Serialize,
        Deserialize,
        ToSchema,
    )]
    #[sea_orm(rs_type = "String", db_type = "Text")]
    #[serde(rename_all = "snake_case")]
    /// Account status at the identity provider, updated on sign-in or via SCIM polling.
    pub enum IdpStatus {
        #[sea_orm(string_value = "active")]
        Active,
        #[sea_orm(string_value = "disabled")]
        Disabled,
        #[sea_orm(string_value = "missing")]
        Missing,
    }

    /// User account created on first OpenID Connect sign-in.
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, ToSchema)]
    #[sea_orm(table_name = "accounts")]
    #[schema(as = Account)]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        /// OpenID Connect `sub` claim identifying the user at the provider.
        #[sea_orm(unique)]
        pub subject: String,
        pub display_name: String,
        pub blocked: bool,
        pub idp_status: IdpStatus,
        /// When the account's IdP status was last applied, at sign-in or by the SCIM sweep.
        pub idp_checked_at: Option<DateTime<Utc>>,
        /// Whether the most recent SCIM user status check failed.
        pub idp_check_error: bool,
        /// Per-account IPv4 quota override, or empty to use `quota.ipv4`.
        pub quota_ipv4: String,
        /// Per-account IPv6 quota override, or empty to use `quota.ipv6`.
        pub quota_ipv6: String,
        pub revision: i64,
        pub created_at: DateTime<Utc>,
    }

    impl Model {
        pub fn active(&self) -> bool {
            !self.blocked && self.idp_status == IdpStatus::Active
        }
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod session {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "sessions")]
    pub struct Model {
        /// SHA-256 of the random session secret sent in the browser session cookie.
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        /// Whether the user's ID token matched a group in `oidc.admin_groups` at sign-in.
        pub admin: bool,
        pub csrf: String,
        pub expires_at: DateTime<Utc>,
        pub last_seen: DateTime<Utc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::account::Entity",
            from = "Column::AccountId",
            to = "super::account::Column::Id",
            on_delete = "Cascade"
        )]
        Account,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod device {
    use super::*;

    /// WireGuard peer belonging to an account on a single interface.
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, ToSchema)]
    #[sea_orm(table_name = "devices")]
    #[schema(as = DeviceRecord)]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub account_id: String,
        /// Configured interface name in `config.toml`.
        pub interface_id: String,
        pub name: String,
        pub note: String,
        /// Optional label for the device in the interface's DNS zone.
        #[sea_orm(unique)]
        pub dns_name: Option<String>,
        #[serde(skip)]
        pub preshared_key: String,
        #[sea_orm(unique)]
        pub public_key: Option<String>,
        /// Expiration timestamp for `public_key`.
        pub key_expires_at: Option<DateTime<Utc>>,
        /// CIDR prefixes allocated to this device from the interface's pools.
        #[sea_orm(column_type = "Json")]
        #[schema(value_type = Vec<String>)]
        pub grants: Strings,
        /// IP addresses assigned to the client's WireGuard interface.
        #[sea_orm(column_type = "Json")]
        #[schema(value_type = Vec<String>)]
        pub client_addresses: Strings,
        /// Additional server-side AllowedIPs prefixes configured by an administrator.
        #[sea_orm(column_type = "Json")]
        #[schema(value_type = Vec<String>)]
        pub extra_allowed_ips: Strings,
        pub paused: bool,
        /// Whether an administrator blocked the device. Blocked devices keep their key and address
        /// grants, but their peer is removed from the kernel, their agent credential cannot
        /// authenticate, and non-admin owners cannot modify or delete them.
        pub blocked: bool,
        /// Whether the device is marked for deletion and waiting for the reconciler to remove its
        /// peer from the kernel.
        pub deleting: bool,
        pub revision: i64,
        /// Latest device revision that the reconciler applied to and verified in the kernel.
        pub applied_revision: i64,
        /// Whether the peer is currently installed on the kernel interface.
        pub applied_enabled: bool,
        /// Error from the latest reconciliation pass, or empty when applied. Set to
        /// `interface NAME failed to apply` when interface-level setup failed.
        pub apply_error: String,
        pub created_at: DateTime<Utc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::account::Entity",
            from = "Column::AccountId",
            to = "super::account::Column::Id"
        )]
        Account,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod agent_credential {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "agent_credentials")]
    /// Bearer credential issued to a host agent for a single device.
    pub struct Model {
        /// SHA-256 of the random secret sent by the agent as `Authorization: Bearer itoa_<secret>`.
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        /// Device ID (at most one active credential per device).
        #[sea_orm(unique)]
        pub device_id: String,
        /// Timestamp when the credential was issued.
        pub created_at: DateTime<Utc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {
        #[sea_orm(
            belongs_to = "super::device::Entity",
            from = "Column::DeviceId",
            to = "super::device::Column::Id",
            on_delete = "Cascade"
        )]
        Device,
    }

    impl ActiveModelBehavior for ActiveModel {}
}

pub mod audit {
    use super::*;

    /// Audit log entry recording a state change.
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, ToSchema)]
    #[sea_orm(table_name = "audit")]
    #[schema(as = AuditEntry)]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        /// Principal that performed the action (`account:ID`, `device:ID`, or `identity`).
        pub actor: String,
        pub action: String,
        pub resource_id: String,
        pub created_at: DateTime<Utc>,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}
