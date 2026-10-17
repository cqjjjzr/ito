//! On-disk persistence for saved VPN connections (`<state_dir>/<name>.json`).

use crate::{client::DeviceInfo, spec::TunnelSpec};
use ito_shared::api::DeviceConfig;
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

// --- Persisted connection types ---

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Disconnected,
    Disconnecting,
    Connected,
    /// A requested connection failed; periodic synchronization will retry it.
    Errored,
}

impl ConnectionState {
    pub fn wants_connection(self) -> bool {
        matches!(self, Self::Connected | Self::Errored)
    }
}

pub struct LoadedConnections {
    pub connections: Vec<SavedConnection>,
    /// Corrupted connection files (`(name, error_message)`) skipped during loading.
    pub errors: Vec<(String, String)>,
}

/// Persisted state for a single device connection to an Ito portal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedConnection {
    /// Local connection and WireGuard interface name (e.g. `ito-a1b2c3`).
    pub name: String,
    /// Portal base URL, such as `https://vpn.example.com`.
    pub portal: String,
    /// Agent bearer credential (`itoa_<secret>`).
    pub token: String,
    pub device: DeviceInfo,
    /// Base64-encoded WireGuard private key (never sent to the controller).
    pub private_key: String,
    /// Selected server route profile ID, or `None` when using `custom_allowed_ips` or the server
    /// default.
    pub profile_id: Option<String>,
    /// Local `AllowedIPs` override used when `profile_id` is `None`.
    #[serde(default)]
    pub custom_allowed_ips: Option<Vec<String>>,
    pub state: ConnectionState,
    /// Whether controller DNS settings are disabled for this connection.
    pub no_dns: bool,
    /// Cached device configuration and HTTP `ETag` for offline tunnel startup.
    pub config: Option<CachedConfig>,
    /// Last [`TunnelSpec`] applied to the local WireGuard interface.
    pub applied: Option<TunnelSpec>,
    /// Whether the controller rejected the agent credential (`401 Unauthorized`).
    pub revoked: bool,
    /// Error message from the most recent synchronization attempt, if any.
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedConfig {
    pub etag: String,
    pub config: DeviceConfig,
}

// --- State directory operations ---

/// Directory holding `ito-<hex>.json` connection state files with owner-only permissions.
pub struct StateDir {
    path: PathBuf,
}

impl StateDir {
    /// Opens or creates the state directory at `path` and verifies owner-only permissions on Unix.
    pub fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt};
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)?;
            let metadata = fs::symlink_metadata(path)?;
            #[expect(
                unsafe_code,
                reason = "the platform's effective user ID has no std wrapper"
            )]
            // SAFETY: geteuid has no preconditions.
            let owner = unsafe { libc::geteuid() };
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != owner
                || metadata.mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{} must be a private directory owned by this user",
                        path.display()
                    ),
                ));
            }
        }
        #[cfg(not(unix))]
        fs::create_dir_all(path)?;
        Ok(Self { path: path.into() })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Resolves the JSON file path for connection `name` after verifying that `name` matches
    /// `ito-<hex>`.
    fn resolve_file_path(&self, name: &str) -> io::Result<PathBuf> {
        let tail = name.strip_prefix("ito-").unwrap_or_default();
        if tail.is_empty() || !tail.chars().all(|c| c.is_ascii_hexdigit()) {
            let message = format!("{name:?} is not a connection name");
            return Err(io::Error::new(io::ErrorKind::InvalidInput, message));
        }
        Ok(self.path.join(format!("{name}.json")))
    }

    /// Loads all saved connections in the directory, sorted by connection name.
    pub fn load_all(&self) -> io::Result<LoadedConnections> {
        let mut all = Vec::new();
        let mut errors = Vec::new();
        for entry in fs::read_dir(&self.path)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                let name = path
                    .file_stem()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                if self.resolve_file_path(name).is_err() {
                    continue;
                }
                match read_connection_file(&path) {
                    Ok(c) => all.push(c),
                    Err(e) => errors.push((name.into(), format!("{}: {e}", path.display()))),
                }
            }
        }
        all.sort_by(|a: &SavedConnection, b| a.name.cmp(&b.name));
        Ok(LoadedConnections {
            connections: all,
            errors,
        })
    }

    /// Loads connection `name`, returning `Ok(None)` if the file does not exist or `name` is
    /// invalid.
    pub fn load(&self, name: &str) -> io::Result<Option<SavedConnection>> {
        let Ok(path) = self.resolve_file_path(name) else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        read_connection_file(&path).map(Some)
    }

    /// Atomically writes `c` to `<name>.json` via a temporary file rename.
    pub fn save(&self, c: &SavedConnection) -> io::Result<()> {
        let path = self.resolve_file_path(&c.name)?;
        let temporary = path.with_extension("json.new");
        let text = serde_json::to_vec_pretty(c).map_err(io::Error::other)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        io::Write::write_all(&mut file, &text)?;
        file.sync_all()?;
        fs::rename(temporary, path)?;
        #[cfg(unix)]
        fs::File::open(&self.path)?.sync_all()?;
        Ok(())
    }

    pub fn remove(&self, name: &str) -> io::Result<()> {
        fs::remove_file(self.resolve_file_path(name)?)
    }
}

fn read_connection_file(path: &Path) -> io::Result<SavedConnection> {
    let text = fs::read(path)?;
    let connection: SavedConnection = serde_json::from_slice(&text).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: {e}", path.display()),
        )
    })?;
    if path.file_stem() != Some(std::ffi::OsStr::new(&connection.name)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "connection name does not match its file",
        ));
    }
    Ok(connection)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::spec::tests::build_sample_config;

    pub(crate) fn create_private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    pub(crate) fn build_sample_connection(name: &str) -> SavedConnection {
        SavedConnection {
            name: name.into(),
            portal: "https://vpn.test".into(),
            token: "itoa_x".into(),
            device: DeviceInfo {
                id: "d".into(),
                name: "laptop".into(),
                note: String::new(),
                dns_name: None,
                interface_id: "wg0".into(),
                revision: 1,
                key_expires_at: None,
                disabled_reason: None,
            },
            private_key: "KEY=".into(),
            profile_id: None,
            custom_allowed_ips: None,
            state: ConnectionState::Disconnected,
            no_dns: false,
            config: Some(CachedConfig {
                etag: "\"e\"".into(),
                config: build_sample_config(),
            }),
            applied: None,
            revoked: false,
            last_error: None,
        }
    }

    /// Opens a state directory inside a new private directory.
    fn open_state_dir() -> (tempfile::TempDir, StateDir) {
        let dir = create_private_dir();
        let state = StateDir::open(&dir.path().join("state")).unwrap();
        (dir, state)
    }

    #[test]
    fn saved_connections_load_back_sorted_by_name() {
        let (_dir, state) = open_state_dir();
        let (b, a) = (
            build_sample_connection("ito-b"),
            build_sample_connection("ito-a"),
        );
        state.save(&b).unwrap();
        state.save(&a).unwrap();
        assert_eq!(state.load_all().unwrap().connections, [a.clone(), b]);
        assert_eq!(state.load("ito-a").unwrap(), Some(a));
    }

    #[cfg(unix)]
    #[test]
    fn connection_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, state) = open_state_dir();
        state.save(&build_sample_connection("ito-a")).unwrap();
        let path = state.resolve_file_path("ito-a").unwrap();
        let mode = fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn removed_connections_are_gone() {
        let (_dir, state) = open_state_dir();
        state.save(&build_sample_connection("ito-a")).unwrap();
        state.remove("ito-a").unwrap();
        assert_eq!(state.load("ito-a").unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn loose_directories_are_refused_and_left_unchanged() {
        use std::os::unix::fs::PermissionsExt;
        let dir = create_private_dir();
        let loose = dir.path().join("loose");
        fs::create_dir(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(StateDir::open(&loose).is_err());
        let mode = fs::metadata(&loose).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_directories_are_refused() {
        let dir = create_private_dir();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link).unwrap();
        assert!(StateDir::open(&link).is_err());
    }

    #[test]
    fn files_holding_another_connection_are_refused() {
        let (dir, state) = open_state_dir();
        for name in ["ito-b", "../outside"] {
            let text = serde_json::to_vec(&build_sample_connection(name)).unwrap();
            fs::write(dir.path().join("state/ito-a.json"), text).unwrap();
            let refused = state.load("ito-a").unwrap_err();
            assert_eq!(refused.kind(), io::ErrorKind::InvalidData, "{name}");
            assert_eq!(state.load_all().unwrap().errors.len(), 1, "{name}");
        }
    }

    #[test]
    fn files_without_a_connection_name_are_ignored() {
        let (dir, state) = open_state_dir();
        let text = serde_json::to_vec(&build_sample_connection("invalid")).unwrap();
        fs::write(dir.path().join("state/invalid.json"), text).unwrap();
        let loaded = state.load_all().unwrap();
        assert!(loaded.connections.is_empty());
        assert!(loaded.errors.is_empty());
    }

    #[test]
    fn names_stay_inside_the_directory() {
        let (dir, state) = open_state_dir();
        fs::write(dir.path().join("x.json"), "{}").unwrap();
        for name in ["../x", r"..\x", "ito-../../x", "ito-", "/tmp/x", "ito-0a/b"] {
            assert_eq!(state.load(name).unwrap(), None, "{name}");
            assert!(state.remove(name).is_err(), "{name}");
            let connection = build_sample_connection(name);
            assert!(state.save(&connection).is_err(), "{name}");
        }
    }
}
