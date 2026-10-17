//! Windows system integration for WireGuard for Windows: ACLs, DPAPI configuration store,
//! `WireGuardTunnel$<name>` services, and `wg.exe`.
#![allow(unsafe_code, reason = "DPAPI and file security have no safe wrappers")]

use crate::wireguard::WireGuardDriver;
use ito_agent_core::tunnel::TunnelError;
use std::{
    ffi::OsStr,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, BorrowedHandle},
    },
    path::{Path, PathBuf},
    process::Stdio,
    ptr::{null, null_mut},
    time::Duration,
};
use windows_service::{
    service::{ServiceAccess, ServiceState},
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::{
    Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, HANDLE, LocalFree, WIN32_ERROR},
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        },
        Cryptography::{CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData},
        DACL_SECURITY_INFORMATION, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        SetFileSecurityW, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::CreateDirectoryW,
    System::Threading::CREATE_NO_WINDOW,
};

// --- Security descriptors and private directories ---

/// DACL applied to `.conf.dpapi` files in WireGuard's store: full control for `LocalSystem` and
/// delete permission for `Administrators`.
const STORE_FILE_SDDL: &str = "D:PAI(A;;FA;;;SY)(A;;SD;;;BA)";

/// DACL applied to private directories (`WireGuard\Data` and the agent's own `Data` directory):
/// full control for `LocalSystem` and `Administrators` only.
pub const PRIVATE_DIR_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Encodes `s` as a NUL-terminated UTF-16 string.
pub fn encode_wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain([0]).collect()
}

/// Owned Win32 security descriptor parsed from SDDL and freed via `LocalFree` on drop.
pub(crate) struct SecurityDescriptor(pub(crate) PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is an immutable private allocation after creation.
unsafe impl Send for SecurityDescriptor {}

impl SecurityDescriptor {
    pub(crate) fn from_sddl(sddl: &str) -> io::Result<Self> {
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let sddl = encode_wide(sddl);
        // SAFETY: `sddl` is NUL-terminated and outlives the call; the descriptor is freed on drop.
        let parsed = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if parsed == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: the descriptor was allocated by
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
        unsafe { LocalFree(self.0) };
    }
}

/// Creates directory `path` with the DACL in `sddl`, or verifies and updates an existing directory.
pub fn create_private_dir(path: &Path, sddl: &str) -> io::Result<()> {
    let descriptor = SecurityDescriptor::from_sddl(sddl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide_path = encode_wide(path.as_os_str());
    // SAFETY: the path is NUL-terminated, and it and the attributes outlive the call.
    if unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) } != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() != io::ErrorKind::AlreadyExists {
        return Err(error);
    }
    check_private_dir(path)?;
    secure(path, sddl)
}

/// Verifies that `path` is a plain directory (not a symlink or junction) owned by `LocalSystem` or
/// `Administrators`.
pub fn check_private_dir(path: &Path) -> io::Result<()> {
    let refuse = |why: &str| {
        let message = format!(
            "{} {why}; remove it and start the agent again",
            path.display()
        );
        io::Error::new(io::ErrorKind::PermissionDenied, message)
    };
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(refuse("is not a plain directory"));
    }
    if !is_path_owner_trusted(path)? {
        return Err(refuse(
            "belongs to someone other than LocalSystem or the administrators",
        ));
    }
    Ok(())
}

/// Replaces the DACL on `path` with the protected DACL specified by `sddl`.
pub fn secure(path: &Path, sddl: &str) -> io::Result<()> {
    let descriptor = SecurityDescriptor::from_sddl(sddl)?;
    let path = encode_wide(path.as_os_str());
    let what = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: `path` is NUL-terminated and the descriptor is valid for the call.
    if unsafe { SetFileSecurityW(path.as_ptr(), what, descriptor.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Returns `true` if the object referenced by `handle` is owned by `LocalSystem` or
/// `Administrators`.
pub fn is_handle_owner_trusted(handle: BorrowedHandle<'_>) -> io::Result<bool> {
    is_owner_trusted(|owner, descriptor| {
        // SAFETY: the handle is valid, and both outputs outlive the call.
        unsafe {
            GetSecurityInfo(
                handle.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                owner,
                null_mut(),
                null_mut(),
                null_mut(),
                descriptor,
            )
        }
    })
}

/// Returns `true` if the file or directory at `path` is owned by `LocalSystem` or `Administrators`.
pub fn is_path_owner_trusted(path: &Path) -> io::Result<bool> {
    let path = encode_wide(path.as_os_str());
    is_owner_trusted(|owner, descriptor| {
        // SAFETY: `path` is NUL-terminated, and it and both outputs outlive the call.
        unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                owner,
                null_mut(),
                null_mut(),
                null_mut(),
                descriptor,
            )
        }
    })
}

/// Checks whether the owner SID populated by `read_owner` matches `WinLocalSystemSid` or
/// `WinBuiltinAdministratorsSid`.
fn is_owner_trusted(
    read_owner: impl FnOnce(*mut PSID, *mut PSECURITY_DESCRIPTOR) -> WIN32_ERROR,
) -> io::Result<bool> {
    let (mut owner, mut descriptor) = (null_mut(), null_mut());
    let read = read_owner(&mut owner, &mut descriptor);
    if read != 0 {
        return Err(io::Error::from_raw_os_error(read as i32));
    }
    let trusted = [WinLocalSystemSid, WinBuiltinAdministratorsSid]
        .into_iter()
        // SAFETY: the owner points into the descriptor, which is freed only below.
        .any(|sid| unsafe { IsWellKnownSid(owner, sid) } != 0);
    // SAFETY: the call above allocated the descriptor with LocalAlloc.
    unsafe { LocalFree(descriptor) };
    Ok(trusted)
}

// --- DPAPI encryption and service queries ---

/// Encrypts `data` with DPAPI for the current account (`LocalSystem` in the service) using
/// tunnel `name` as the description, matching WireGuard's `.conf.dpapi` store format.
fn protect(data: &[u8], name: &str) -> io::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let description = encode_wide(name);
    // SAFETY: the input and description outlive the call; the output is freed below.
    let protected = unsafe {
        CryptProtectData(
            &input,
            description.as_ptr(),
            null(),
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if protected == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: DPAPI returned `cbData` bytes at `pbData`, which LocalFree releases afterwards.
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let bytes = bytes.to_vec();
    // SAFETY: as above.
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(bytes)
}

/// Queries the current state of `WireGuardTunnel$<name>`, returning `Ok(None)` if the service does
/// not exist.
fn query_state(name: &str) -> Result<Option<ServiceState>, TunnelError> {
    let build_scm_error = |e: windows_service::Error| TunnelError(format!("services: {e}"));
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(build_scm_error)?;
    let service = format!("WireGuardTunnel${name}");
    match manager.open_service(service, ServiceAccess::QUERY_STATUS) {
        Ok(service) => Ok(Some(
            service
                .query_status()
                .map_err(build_scm_error)?
                .current_state,
        )),
        Err(windows_service::Error::Winapi(e))
            if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) =>
        {
            Ok(None)
        }
        Err(e) => Err(build_scm_error(e)),
    }
}

fn build_tunnel_error_with(what: &str) -> impl Fn(io::Error) -> TunnelError + '_ {
    move |e| TunnelError(format!("{what}: {e}"))
}

// --- SystemWireGuard driver ---

/// Production [`WireGuardDriver`] backed by `%ProgramFiles%\WireGuard\wireguard.exe` and `wg.exe`.
pub struct SystemWireGuard {
    dir: PathBuf,
}

impl SystemWireGuard {
    /// Verifies that `wireguard.exe` and `wg.exe` exist in `%ProgramFiles%\WireGuard`.
    pub fn locate() -> Result<Self, String> {
        let programs =
            std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
        let dir = PathBuf::from(programs).join("WireGuard");
        for program in ["wireguard.exe", "wg.exe"] {
            let path = dir.join(program);
            if !path.is_file() {
                return Err(format!(
                    "{} is missing: install WireGuard for Windows",
                    path.display()
                ));
            }
        }
        Ok(Self { dir })
    }

    /// Ensures `WireGuard\Data\Configurations` exists with [`PRIVATE_DIR_SDDL`] permissions.
    fn create_store(&self) -> io::Result<()> {
        let data = self.dir.join("Data");
        if !data.is_dir() {
            std::fs::create_dir(&data)?;
            secure(&data, PRIVATE_DIR_SDDL)?;
        }
        std::fs::create_dir_all(data.join("Configurations"))
    }

    /// Resolves the path to `<name>.conf.dpapi` in WireGuard's configuration store.
    fn resolve_config_path(&self, name: &str) -> PathBuf {
        self.dir
            .join("Data")
            .join("Configurations")
            .join(format!("{name}.conf.dpapi"))
    }

    async fn run(&self, program: &str, args: &[&OsStr]) -> Result<String, TunnelError> {
        let output = tokio::process::Command::new(self.dir.join(program))
            .args(args)
            // Prevent console window flashes when invoked from background tasks.
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(build_tunnel_error_with(program))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TunnelError(format!("{program}: {}", stderr.trim())));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

#[async_trait::async_trait]
impl WireGuardDriver for SystemWireGuard {
    async fn write_config(&self, name: &str, text: &str) -> Result<(), TunnelError> {
        let file = self.resolve_config_path(name);
        let bytes = protect(text.as_bytes(), name).map_err(build_tunnel_error_with("DPAPI"))?;
        // Write to `.dpapi.tmp` first (which WireGuard ignores) and atomically rename into place.
        let temporary = file.with_extension("dpapi.tmp");
        self.create_store()
            .map_err(build_tunnel_error_with("store"))?;
        std::fs::write(&temporary, bytes).map_err(build_tunnel_error_with("store"))?;
        secure(&temporary, STORE_FILE_SDDL).map_err(build_tunnel_error_with("store"))?;
        std::fs::rename(&temporary, &file).map_err(build_tunnel_error_with("store"))
    }

    async fn delete_config(&self, name: &str) -> Result<(), TunnelError> {
        match std::fs::remove_file(self.resolve_config_path(name)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                Err(build_tunnel_error_with("store")(e))
            }
            _ => Ok(()),
        }
    }

    async fn install(&self, name: &str) -> Result<(), TunnelError> {
        let file = self.resolve_config_path(name);
        let args = [OsStr::new("/installtunnelservice"), file.as_os_str()];
        self.run("wireguard.exe", &args).await.map(drop)
    }

    async fn uninstall(&self, name: &str) -> Result<(), TunnelError> {
        let args = [OsStr::new("/uninstalltunnelservice"), OsStr::new(name)];
        self.run("wireguard.exe", &args).await?;
        // Wait until the service is fully stopped or removed before returning so a subsequent
        // install cannot race.
        for _ in 0..100 {
            match query_state(name)? {
                None | Some(ServiceState::Stopped) => return Ok(()),
                Some(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
        Err(TunnelError(format!("the service of {name} did not stop")))
    }

    async fn is_running(&self, name: &str) -> Result<bool, TunnelError> {
        Ok(matches!(
            query_state(name)?,
            Some(ServiceState::Running | ServiceState::StartPending)
        ))
    }

    async fn dump(&self, name: &str) -> Result<String, TunnelError> {
        let args = [OsStr::new("show"), OsStr::new(name), OsStr::new("dump")];
        self.run("wg.exe", &args).await
    }
}
