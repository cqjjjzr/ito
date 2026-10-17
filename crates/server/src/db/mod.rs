use crate::error::{Code, Result, unavailable};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction,
    EntityTrait, Schema, TransactionTrait, sqlx::sqlite::SqliteJournalMode,
};
use std::{fs::OpenOptions, ops::Deref, os::unix::fs::OpenOptionsExt, path::Path, sync::Arc};
use tokio::sync::Notify;

mod entities;
pub use entities::*;

pub struct Db {
    pub conn: DatabaseConnection,
    write_lock: Arc<tokio::sync::Mutex<()>>,
    /// Notifies the reconciler after a committed transaction changes desired kernel state.
    kernel_notify: Arc<Notify>,
    /// Notifies the DNS server after a committed transaction changes DNS zone records.
    dns_notify: Arc<Notify>,
}

/// Serialized database write transaction that notifies the reconciler and DNS server only after a
/// successful commit.
pub struct Tx {
    txn: DatabaseTransaction,
    kernel_changed: bool,
    dns_changed: bool,
    kernel_notify: Arc<Notify>,
    dns_notify: Arc<Notify>,
    _write_guard: tokio::sync::OwnedMutexGuard<()>,
}

impl Db {
    /// Opens or creates the SQLite database at `path` and acquires an exclusive file lock so two
    /// controller processes cannot share the same database file.
    pub async fn connect(path: &Path) -> Result<Self> {
        let build_unavailable_error = |e: &dyn std::fmt::Display| {
            unavailable(
                Code::DatabaseUnavailable,
                format!("{}: {e}", path.display()),
            )
        };
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| build_unavailable_error(&e))?;
        // Keep `lock_file` open for the life of the process. SQLite uses POSIX `fcntl` locks
        // internally, and closing any file descriptor for the same inode would release those locks
        // while connection pool threads are still open.
        lock_file
            .try_lock()
            .map_err(|_| build_unavailable_error(&"another controller has the database open"))?;
        std::mem::forget(lock_file);
        let db_path = path.to_owned();
        let mut options = ConnectOptions::new("sqlite:");
        options
            .sqlx_logging(false)
            .max_connections(8)
            // Enable WAL mode so concurrent readers are not blocked by the single writer.
            .map_sqlx_sqlite_opts(move |o| {
                o.filename(&db_path).journal_mode(SqliteJournalMode::Wal)
            });
        let conn = Database::connect(options).await?;
        let schema = Schema::new(conn.get_database_backend());
        // Create tables in foreign-key dependency order.
        macro_rules! create {
            ($($entity:path),*) => {$(
                conn.execute(&schema.create_table_from_entity($entity).if_not_exists().to_owned()).await?;
            )*};
        }
        create!(
            account::Entity,
            session::Entity,
            device::Entity,
            agent_credential::Entity,
            audit::Entity
        );
        Ok(Self {
            conn,
            write_lock: Arc::default(),
            kernel_notify: Arc::default(),
            dns_notify: Arc::default(),
        })
    }

    pub async fn begin_write(&self) -> Result<Tx> {
        let write_guard = self.write_lock.clone().lock_owned().await;
        Ok(Tx {
            txn: self.conn.begin().await?,
            kernel_changed: false,
            dns_changed: false,
            kernel_notify: self.kernel_notify.clone(),
            dns_notify: self.dns_notify.clone(),
            _write_guard: write_guard,
        })
    }

    /// Starts a transaction to read a consistent snapshot across multiple queries.
    pub async fn begin_read(&self) -> Result<DatabaseTransaction> {
        Ok(self.conn.begin().await?)
    }

    /// Waits until a committed write transaction marks the kernel state as changed.
    pub async fn wait_kernel_changed(&self) {
        self.kernel_notify.notified().await;
    }

    /// Waits until a committed write transaction marks DNS records as changed.
    pub async fn wait_dns_changed(&self) {
        self.dns_notify.notified().await;
    }
}

impl Deref for Tx {
    type Target = DatabaseTransaction;

    fn deref(&self) -> &DatabaseTransaction {
        &self.txn
    }
}

impl Tx {
    /// Commits the transaction and wakes any subsystems marked as changed.
    pub async fn commit(self) -> Result<()> {
        self.txn.commit().await?;
        if self.kernel_changed {
            self.kernel_notify.notify_one();
        }
        if self.dns_changed {
            self.dns_notify.notify_one();
        }
        Ok(())
    }

    /// Marks the transaction as modifying desired kernel WireGuard state.
    pub fn mark_kernel_changed(&mut self) {
        self.kernel_changed = true;
    }

    /// Marks the transaction as modifying DNS zone records.
    pub fn mark_dns_changed(&mut self) {
        self.dns_changed = true;
    }

    pub async fn audit(&self, actor: &str, action: &str, resource_id: &str) -> Result<()> {
        self.insert::<audit::ActiveModel>(audit::Model {
            id: generate_id(),
            actor: actor.into(),
            action: action.into(),
            resource_id: resource_id.into(),
            created_at: chrono::Utc::now(),
        })
        .await
    }

    pub async fn insert<A>(&self, model: <A::Entity as EntityTrait>::Model) -> Result<()>
    where
        A: sea_orm::ActiveModelTrait
            + sea_orm::ActiveModelBehavior
            + Send
            + From<<A::Entity as EntityTrait>::Model>,
        <A::Entity as EntityTrait>::Model: sea_orm::IntoActiveModel<A>,
    {
        A::from(model).reset_all().insert(&self.txn).await?;
        Ok(())
    }

    pub async fn update<A>(&self, model: <A::Entity as EntityTrait>::Model) -> Result<()>
    where
        A: sea_orm::ActiveModelTrait
            + sea_orm::ActiveModelBehavior
            + Send
            + From<<A::Entity as EntityTrait>::Model>,
        <A::Entity as EntityTrait>::Model: sea_orm::IntoActiveModel<A>,
    {
        A::from(model).reset_all().update(&self.txn).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_second_controller_cannot_open_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ito.db");
        let _first = Db::connect(&path).await.unwrap();
        let second = Db::connect(&path).await.err().unwrap();
        assert!(second.cause.unwrap().contains("another controller"));
    }
}
