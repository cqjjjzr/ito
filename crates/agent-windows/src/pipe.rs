//! Named pipe IPC server and client for the Windows agent service.
#![allow(
    unsafe_code,
    reason = "named pipe security attributes and client tokens have no safe wrapper"
)]

use crate::system::{self, SecurityDescriptor};
use ito_agent_core::{
    agent::Agent,
    ipc::{self, IpcResponse},
    tunnel::TunnelDriver,
};
use std::{
    io,
    os::windows::io::{
        AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle, RawHandle,
    },
    ptr::null_mut,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions},
};
use windows_sys::Win32::{
    Foundation::{ERROR_PIPE_BUSY, HANDLE},
    Security::{
        CheckTokenMembership, CreateWellKnownSid, DuplicateToken, GetTokenInformation,
        SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, SecurityIdentification, TOKEN_DUPLICATE,
        TOKEN_LINKED_TOKEN, TOKEN_QUERY, TokenLinkedToken, WELL_KNOWN_SID_TYPE,
        WinBuiltinAdministratorsSid, WinBuiltinNetworkConfigurationOperatorsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::SECURITY_IDENTIFICATION,
    System::{
        Pipes::{GetNamedPipeClientProcessId, WaitNamedPipeW},
        Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};

// --- Named pipe server ---

pub const PIPE: &str = r"\\.\pipe\ProtectedPrefix\Administrators\ito-agent";

/// SDDL for [`PIPE`]:
/// - Owner: Built-in Administrators (`O:BA`), verified by clients in [`verify_pipe_owner`].
/// - Full control (`GA`) for `LocalSystem` (`SY`) and `Administrators` (`BA`).
/// - Read/write access (`0x12019b`, excluding `FILE_CREATE_PIPE_INSTANCE`) for Network
///   Configuration Operators (`NO`) and Interactive Users (`IU`) so they can connect and receive a
///   clear authorization error from [`is_client_authorized`] without being able to create pipe
///   instances.
const PIPE_SDDL: &str = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;NO)(A;;0x12019b;;;IU)";

fn create_pipe_instance(
    descriptor: &SecurityDescriptor,
    first: bool,
) -> io::Result<NamedPipeServer> {
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: the attributes and their descriptor outlive the call, which copies them.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(PIPE, (&raw mut attributes).cast())
    }
}

/// Active named pipe listener holding the security descriptor and next server instance.
pub struct Listener {
    descriptor: SecurityDescriptor,
    server: NamedPipeServer,
}

/// Creates the initial instance of [`PIPE`] with `FILE_FLAG_FIRST_PIPE_INSTANCE`.
pub fn listen() -> io::Result<Listener> {
    let descriptor = SecurityDescriptor::from_sddl(PIPE_SDDL)?;
    let server = create_pipe_instance(&descriptor, true)?;
    Ok(Listener { descriptor, server })
}

/// Accepts client connections on `listener` and serves IPC requests on `agent`.
pub async fn serve<T: TunnelDriver + 'static>(
    listener: Listener,
    agent: Arc<Agent<T>>,
) -> io::Error {
    let Listener {
        descriptor,
        mut server,
    } = listener;
    loop {
        let next = match server.connect().await {
            Ok(()) => create_pipe_instance(&descriptor, false),
            Err(e) => Err(e),
        };
        let connected = match next {
            Ok(next) => std::mem::replace(&mut server, next),
            Err(e) => return e,
        };
        let agent = agent.clone();
        tokio::spawn(async move {
            match is_client_authorized(&connected) {
                Ok(true) => ipc::serve(connected, &agent).await,
                refused => refuse(connected, refused.err()).await,
            }
        });
    }
}

// --- Named pipe client and server verification ---

/// Verifies that the connected pipe handle `client` is owned by `LocalSystem` or `Administrators`.
///
/// Prevents an unprivileged local process from squatting the pipe name when the service is stopped.
pub fn verify_pipe_owner(client: BorrowedHandle<'_>) -> io::Result<()> {
    if system::is_handle_owner_trusted(client)? {
        return Ok(());
    }
    let message = format!("{PIPE} does not belong to the Ito agent service");
    Err(io::Error::new(io::ErrorKind::PermissionDenied, message))
}

/// Opens a blocking client connection to [`PIPE`] (used by the system tray) and verifies its owner.
pub fn open_blocking() -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    let pipe = open_when_available(|| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(PIPE)
    })?;
    verify_pipe_owner(pipe.as_handle())?;
    Ok(pipe)
}

/// Opens an asynchronous client connection to [`PIPE`] (used by the CLI) and verifies its owner.
pub fn open() -> io::Result<NamedPipeClient> {
    let client = open_when_available(|| ClientOptions::new().open(PIPE))?;
    verify_pipe_owner(client.as_handle())?;
    Ok(client)
}

/// Calls `open`, waiting up to 5 seconds when all pipe instances report `ERROR_PIPE_BUSY`.
fn open_when_available<T>(open: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let name = crate::system::encode_wide(PIPE);
    retry_while_busy(open, |left| {
        // SAFETY: the pipe name is NUL-terminated and lives through the bounded wait.
        if unsafe { WaitNamedPipeW(name.as_ptr(), left.as_millis().max(1) as u32) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
}

/// Calls `open` until it stops reporting `ERROR_PIPE_BUSY`, calling `wait` with the time left of 5
/// seconds before each retry.
fn retry_while_busy<T>(
    mut open: impl FnMut() -> io::Result<T>,
    mut wait: impl FnMut(Duration) -> io::Result<()>,
) -> io::Result<T> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match open() {
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(e);
                }
                wait(left)?;
            }
            result => return result,
        }
    }
}

/// Writes an [`IpcResponse::Error`] explaining why the client is unauthorized and closes `pipe`.
async fn refuse(mut pipe: NamedPipeServer, error: Option<io::Error>) -> io::Result<()> {
    let why = match error {
        Some(e) => format!("the Ito agent could not check who you are: {e}"),
        None => {
            "only administrators and network configuration operators may use the Ito agent".into()
        }
    };
    let mut line = serde_json::to_string(&IpcResponse::Error(why)).expect("serializable");
    line.push('\n');
    pipe.write_all(line.as_bytes()).await
}

// --- Client token authorization ---

/// Wraps a newly created Win32 `HANDLE` in an [`OwnedHandle`], or returns `last_os_error()` if
/// `made == 0` or `handle` is null.
fn own_handle(made: i32, handle: HANDLE) -> io::Result<OwnedHandle> {
    if made == 0 || handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call just made the handle, and nothing else owns it.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}

/// Checks whether the client process connected to `pipe` is `LocalSystem`, an Administrator
/// (including unelevated UAC split tokens via `TokenLinkedToken`), or a Network Configuration
/// Operator.
fn is_client_authorized(pipe: &NamedPipeServer) -> io::Result<bool> {
    let mut pid = 0;
    // SAFETY: the pipe handle is valid while `pipe` lives, and `pid` outlives the call.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcess has no preconditions; `own_handle` checks its result.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    let process = own_handle(1, process)?;
    let mut primary = null_mut();
    // SAFETY: the process handle is valid, and `primary` outlives the call.
    let opened = unsafe {
        OpenProcessToken(
            process.as_raw_handle() as HANDLE,
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut primary,
        )
    };
    let primary = own_handle(opened, primary)?;
    for group in [
        WinLocalSystemSid,
        WinBuiltinAdministratorsSid,
        WinBuiltinNetworkConfigurationOperatorsSid,
    ] {
        if is_member(&primary, group)? {
            return Ok(true);
        }
    }
    let mut linked = TOKEN_LINKED_TOKEN {
        LinkedToken: null_mut(),
    };
    let mut length = 0;
    // SAFETY: the primary token is valid, and `linked` is a TOKEN_LINKED_TOKEN of the size given.
    let got = unsafe {
        GetTokenInformation(
            primary.as_raw_handle() as HANDLE,
            TokenLinkedToken,
            (&raw mut linked).cast(),
            size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut length,
        )
    };
    // Non-split tokens do not have a linked token; for split tokens, check the linked elevated
    // token.
    match own_handle(got, linked.LinkedToken) {
        Ok(linked) => Ok(is_member(&linked, WinBuiltinAdministratorsSid)?
            || is_member(&linked, WinBuiltinNetworkConfigurationOperatorsSid)?),
        Err(_) => Ok(false),
    }
}

/// Returns `true` if `token` has the well-known SID `group` enabled.
fn is_member(token: &OwnedHandle, group: WELL_KNOWN_SID_TYPE) -> io::Result<bool> {
    // `CheckTokenMembership` requires an impersonation token, whereas `OpenProcessToken` and
    // `TokenLinkedToken` (when queried by `LocalSystem`) return primary tokens.
    let mut checked_token = null_mut();
    // SAFETY: the token is valid, and `checked_token` outlives the call.
    let duplicated = unsafe {
        DuplicateToken(
            token.as_raw_handle() as HANDLE,
            SecurityIdentification,
            &mut checked_token,
        )
    };
    let token = own_handle(duplicated, checked_token)?;
    let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut size = sid.len() as u32;
    // SAFETY: `sid` holds `size` bytes, the most any SID takes.
    if unsafe { CreateWellKnownSid(group, null_mut(), sid.as_mut_ptr().cast(), &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut member = 0;
    // SAFETY: the token is a valid impersonation token, and the SID and flag outlive the call.
    let checked = unsafe {
        CheckTokenMembership(
            token.as_raw_handle() as HANDLE,
            sid.as_mut_ptr().cast(),
            &mut member,
        )
    };
    if checked == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(member != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_pipes_are_retried_until_one_is_available() {
        let mut busy_answers = 2;
        let opened = retry_while_busy(
            || {
                if busy_answers == 0 {
                    return Ok("pipe");
                }
                busy_answers -= 1;
                Err(io::Error::from_raw_os_error(ERROR_PIPE_BUSY as i32))
            },
            |_| Ok(()),
        );
        assert_eq!(opened.unwrap(), "pipe");
    }
}
