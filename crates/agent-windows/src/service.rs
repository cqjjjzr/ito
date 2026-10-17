//! Windows service wrapper (`ItoAgent`) running as `LocalSystem` to manage DPAPI-encrypted
//! WireGuard configurations and tunnel services.

use std::{
    ffi::{OsStr, OsString},
    io::Write,
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::sync::Notify;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

pub const NAME: &str = "ItoAgent";

/// Returns `INSTALLFOLDER\Data`, the private directory beside the service executable where saved
/// connections and `agent.log` are stored.
pub fn data_dir() -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let directory = executable
        .parent()
        .ok_or("agent executable has no directory")?;
    Ok(directory.join("Data"))
}

/// Appends a timestamped log line to `INSTALLFOLDER\Data\agent.log`.
pub fn log_to_file(line: &str) {
    let Ok(dir) = data_dir() else { return };
    let path = dir.join("agent.log");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path);
    if let Ok(mut file) = file {
        let _ = writeln!(file, "{} {line}", unix_seconds());
    }
}

/// Returns the current Unix timestamp in seconds.
fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

define_windows_service!(ffi_service_main, service_main);

/// Connects the process to the Windows Service Control Manager and dispatches `service_main`.
pub fn dispatch() -> Result<(), String> {
    service_dispatcher::start(NAME, ffi_service_main).map_err(|e| e.to_string())
}

fn service_main(_arguments: Vec<OsString>) {
    let stop = Arc::new(Notify::new());
    let on_stop = stop.clone();
    let status_slot = Arc::new(OnceLock::<service_control_handler::ServiceStatusHandle>::new());
    let on_control_status = status_slot.clone();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(status) = on_control_status.get() {
                let _ = report(
                    status,
                    ServiceState::StopPending,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::Win32(0),
                );
            }
            on_stop.notify_one();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(NAME, handler) else {
        return;
    };
    let _ = status_slot.set(status);
    let (none, ok) = (ServiceControlAccept::empty(), ServiceExitCode::Win32(0));
    let _ = report(&status, ServiceState::StartPending, none, ok);
    // Report `Running` only after the state directory and named pipe listener are initialized.
    let accepted = ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN;
    let running = || drop(report(&status, ServiceState::Running, accepted, ok));
    let ran = tokio::runtime::Runtime::new()
        .map_err(|e| e.to_string())
        .and_then(|runtime| {
            let manager =
                ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                    .map_err(|e| e.to_string())?;
            let service = manager
                // Restart recovery actions also require SERVICE_START on this handle.
                .open_service(NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
                .map_err(|e| e.to_string())?;
            configure_recovery(&service)?;
            runtime.block_on(crate::run_system(stop, log_to_file, running))
        });
    let exit_code = match ran {
        Ok(()) => ok,
        Err(e) => {
            // Only write to `agent.log` if the data directory passed the ownership check.
            if data_dir().is_ok_and(|dir| crate::system::check_private_dir(&dir).is_ok()) {
                log_to_file(&format!("stopped: {e}"));
            }
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    let _ = report(&status, ServiceState::Stopped, none, exit_code);
}

fn report(
    status: &service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    accepted: ServiceControlAccept,
    exit_code: ServiceExitCode,
) -> windows_service::Result<()> {
    status.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code,
        checkpoint: u32::from(state == ServiceState::StopPending),
        wait_hint: Duration::from_secs(30),
        process_id: None,
    })
}

/// Registers this executable as the `ItoAgent` auto-start Windows service and starts it.
pub fn install() -> Result<(), String> {
    let access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager =
        ServiceManager::local_computer(None::<&str>, access).map_err(|e| e.to_string())?;
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let parent = executable
        .parent()
        .ok_or("agent executable has no directory")?;
    crate::system::check_private_dir(parent)
        .map_err(|e| format!("install the agent in an administrator-owned folder: {e}"))?;
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "Ito agent".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: executable,
        launch_arguments: vec!["service".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::START | ServiceAccess::CHANGE_CONFIG)
        .map_err(|e| e.to_string())?;
    let description = "Synchronizes Ito VPN connections and manages WireGuard tunnel services.";
    service
        .set_description(description)
        .map_err(|e| e.to_string())?;
    configure_recovery(&service)?;
    service.start::<&OsStr>(&[]).map_err(|e| e.to_string())
}

/// Stops and deletes the `ItoAgent` Windows service while leaving existing tunnels untouched.
pub fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| e.to_string())?;
    let access = ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = manager
        .open_service(NAME, access)
        .map_err(|e| e.to_string())?;
    let _ = service.stop();
    service.delete().map_err(|e| e.to_string())
}

fn configure_recovery(service: &windows_service::service::Service) -> Result<(), String> {
    service
        .update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
            reboot_msg: None,
            command: None,
            actions: Some(
                [10, 10, 60]
                    .map(|seconds| ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(seconds),
                    })
                    .to_vec(),
            ),
        })
        .map_err(|e| e.to_string())?;
    service
        .set_failure_actions_on_non_crash_failures(true)
        .map_err(|e| e.to_string())?;
    Ok(())
}
