//! Windows tray icon, context menu, named-pipe client, and Win32 UI helpers.
#![allow(
    unsafe_code,
    reason = "the message loop, clipboard, task dialogs, and shell have no safe wrappers"
)]

use crate::model::{self, Action, ConnectionInMenu, Entry, Look};
use ito_agent_core::{
    agent::{ConnectionStatus, ConnectionSummary, LoginOutcome},
    ipc::{IpcRequest, IpcResponse},
    login::LoginTicket,
};
use ito_agent_windows::{pipe, system::encode_wide};
use muda::{
    CheckMenuItem, ContextMenu, IsMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem,
    Submenu,
};
use std::{
    collections::{BTreeMap, HashMap},
    io::{BufRead, BufReader, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    process::ExitCode,
    ptr::{null, null_mut, without_provenance},
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};
use tray_icon::{Icon, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use windows_sys::{
    Win32::{
        Foundation::{
            ERROR_ALREADY_EXISTS, GetLastError, GlobalFree, HANDLE, HWND, LPARAM, S_OK, WPARAM,
        },
        System::{
            DataExchange::{
                CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
            },
            LibraryLoader::GetModuleHandleW,
            Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock},
            Threading::{CreateEventW, CreateMutexW, INFINITE, SetEvent},
        },
        UI::{
            Controls::{
                TASKDIALOG_BUTTON, TASKDIALOGCONFIG, TD_ERROR_ICON, TD_INFORMATION_ICON,
                TD_WARNING_ICON, TDF_ALLOW_DIALOG_CANCELLATION, TDN_CREATED, TaskDialogIndirect,
            },
            HiDpi::{GetDpiForSystem, GetDpiForWindow, GetSystemMetricsForDpi},
            Shell::ShellExecuteW,
            WindowsAndMessaging::{
                DispatchMessageW, FindWindowW, ICON_BIG, ICON_SMALL, LoadIconW, MSG,
                MsgWaitForMultipleObjects, PM_REMOVE, PeekMessageW, QS_ALLINPUT, SM_CXSMICON,
                SW_SHOWNORMAL, SendMessageW, TranslateMessage, WM_SETICON,
            },
        },
    },
    core::{HRESULT, PCWSTR},
};

/// Interval between background polls of the agent service.
const POLL_INTERVAL: Duration = Duration::from_secs(600);
/// Win32 clipboard format ID for UTF-16 text.
const CF_UNICODETEXT: u32 = 13;

// --- Task dialogs ---

/// Icon style for task dialogs.
#[derive(Clone, Copy)]
enum Mood {
    Information,
    Warning,
    Error,
}

/// Assigns the application icon from `ito-tray.rc` to a task dialog window when it is created.
unsafe extern "system" fn set_dialog_icon(
    window: HWND,
    notification: u32,
    _: WPARAM,
    _: LPARAM,
    _: isize,
) -> HRESULT {
    if notification == TDN_CREATED as u32 {
        // SAFETY: icon 1 is embedded in the executable resource table, and `window` is the dialog
        // handle. LoadIconW returns a shared handle that does not need to be freed.
        unsafe {
            let icon = LoadIconW(GetModuleHandleW(null()), without_provenance(1));
            for size in [ICON_SMALL, ICON_BIG] {
                SendMessageW(window, WM_SETICON, size as WPARAM, icon as LPARAM);
            }
        }
    }
    S_OK
}

/// Displays a task dialog and returns the index of the clicked button. Pressing Escape or closing
/// the window returns the last button index.
fn show_dialog(heading: &str, text: &str, mood: Mood, buttons: &[&str]) -> usize {
    let (title, heading, text) = (encode_wide("Ito"), encode_wide(heading), encode_wide(text));
    let labels: Vec<Vec<u16>> = buttons.iter().map(encode_wide).collect();
    let buttons: Vec<TASKDIALOG_BUTTON> = labels
        .iter()
        .enumerate()
        .map(|(i, label)| TASKDIALOG_BUTTON {
            nButtonID: 100 + i as i32,
            pszButtonText: label.as_ptr(),
        })
        .collect();
    let icon: PCWSTR = match mood {
        Mood::Information => TD_INFORMATION_ICON,
        Mood::Warning => TD_WARNING_ICON,
        Mood::Error => TD_ERROR_ICON,
    };
    // SAFETY: an all-zero TASKDIALOGCONFIG is valid.
    let mut config: TASKDIALOGCONFIG = unsafe { std::mem::zeroed() };
    config.cbSize = size_of::<TASKDIALOGCONFIG>() as u32;
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
    config.pszWindowTitle = title.as_ptr();
    config.Anonymous1.pszMainIcon = icon;
    config.pszMainInstruction = heading.as_ptr();
    config.pszContent = text.as_ptr();
    config.cButtons = buttons.len() as u32;
    config.pButtons = buttons.as_ptr();
    config.nDefaultButton = 100;
    config.pfCallback = Some(set_dialog_icon);
    let mut chosen = 0;
    // SAFETY: `config` and all referenced buffers outlive the call.
    let shown = unsafe { TaskDialogIndirect(&config, &mut chosen, null_mut(), null_mut()) };
    let last = buttons.len().saturating_sub(1);
    if shown < 0 {
        return last;
    }
    // Escape and the close button return IDCANCEL.
    usize::try_from(chosen - 100).map_or(last, |i| i.min(last))
}

/// Displays an informational or error dialog with a single OK button.
fn tell(heading: &str, text: &str, mood: Mood) {
    show_dialog(heading, text, mood, &["OK"]);
}

/// Displays a two-button confirmation dialog and returns true if the first button was chosen.
fn ask(heading: &str, text: &str, mood: Mood, yes: &str, no: &str) -> bool {
    show_dialog(heading, text, mood, &[yes, no]) == 0
}

// --- Agent IPC and snapshots ---

/// Sends an IPC request to the agent service over the named pipe.
fn call(request: &IpcRequest) -> Result<serde_json::Value, String> {
    let format_unreachable = ito_agent_windows::format_service_unreachable_error;
    let mut pipe = pipe::open_blocking().map_err(format_unreachable)?;
    let mut line = serde_json::to_string(request).expect("serializable");
    line.push('\n');
    pipe.write_all(line.as_bytes())
        .map_err(format_unreachable)?;
    let mut answer = String::new();
    BufReader::new(pipe)
        .read_line(&mut answer)
        .map_err(format_unreachable)?;
    match serde_json::from_str(&answer).map_err(|e| e.to_string())? {
        IpcResponse::Ok(value) => Ok(value),
        IpcResponse::Error(e) => Err(e),
    }
}

/// Point-in-time snapshot of connections and their status from the agent service.
struct Snapshot {
    connections: Vec<ConnectionSummary>,
    statuses: BTreeMap<String, ConnectionStatus>,
    error: Option<String>,
}

fn read_snapshot() -> Snapshot {
    let listed = call(&IpcRequest::List).and_then(|v| {
        serde_json::from_value::<Vec<ConnectionSummary>>(v).map_err(|e| e.to_string())
    });
    let connections = match listed {
        Ok(connections) => connections,
        Err(e) => {
            return Snapshot {
                connections: vec![],
                statuses: BTreeMap::new(),
                error: Some(e),
            };
        }
    };
    let statuses = connections
        .iter()
        .filter_map(|s| {
            let status = call(&IpcRequest::Status {
                name: s.name.clone(),
            })
            .ok()?;
            Some((s.name.clone(), serde_json::from_value(status).ok()?))
        })
        .collect();
    Snapshot {
        connections,
        statuses,
        error: None,
    }
}

// --- Tray icon and context menu ---

/// Queries the system small-icon size in pixels at the taskbar's DPI.
fn measure_tray_icon() -> u32 {
    let class = encode_wide("Shell_TrayWnd");
    // SAFETY: `class` is NUL-terminated and outlives the call. GetDpiForWindow returns 0 when the
    // window handle is null.
    let size = unsafe {
        let taskbar = FindWindowW(class.as_ptr(), null());
        let dpi = match GetDpiForWindow(taskbar) {
            0 => GetDpiForSystem(),
            dpi => dpi,
        };
        GetSystemMetricsForDpi(SM_CXSMICON, dpi)
    };
    u32::try_from(size).unwrap_or(16).clamp(16, 256)
}

/// Renders the tray icon dot for `look` at the current notification area icon size.
fn build_icon(look: Look) -> Icon {
    let size = measure_tray_icon();
    Icon::from_rgba(model::draw_dot(look, size), size, size).expect("valid icon")
}

/// Converts menu entries into `muda` items and records the action for each selectable item.
fn render(entries: &[Entry], actions: &mut HashMap<MenuId, Action>) -> Vec<Box<dyn IsMenuItem>> {
    entries
        .iter()
        .map(|entry| -> Box<dyn IsMenuItem> {
            match entry {
                Entry::Text(text) => Box::new(MenuItem::new(text, false, None)),
                Entry::Separator => Box::new(PredefinedMenuItem::separator()),
                Entry::Item {
                    label,
                    action,
                    checked: None,
                } => {
                    let item = MenuItem::new(label, true, None);
                    actions.insert(item.id().clone(), action.clone());
                    Box::new(item)
                }
                Entry::Item {
                    label,
                    action,
                    checked: Some(checked),
                } => {
                    let item = CheckMenuItem::new(label, true, *checked, None);
                    actions.insert(item.id().clone(), action.clone());
                    Box::new(item)
                }
                Entry::Submenu { label, entries, .. } => {
                    let children = render(entries, actions);
                    let children: Vec<&dyn IsMenuItem> =
                        children.iter().map(AsRef::as_ref).collect();
                    let submenu = Submenu::with_items(label, true, &children).expect("menu");
                    Box::new(submenu)
                }
            }
        })
        .collect()
}

/// Uses the native menu checkmark gutter, including on entries that open submenus.
fn check_submenus(menu: isize, entries: &[Entry]) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CheckMenuItem, GetSubMenu, MF_BYPOSITION, MF_CHECKED, MF_UNCHECKED,
    };
    for (index, entry) in entries.iter().enumerate() {
        if let Entry::Submenu {
            checked, entries, ..
        } = entry
        {
            // SAFETY: the menu is live and this position was created from the same entries.
            unsafe {
                if let Some(checked) = checked {
                    CheckMenuItem(
                        menu as _,
                        index as u32,
                        MF_BYPOSITION | if *checked { MF_CHECKED } else { MF_UNCHECKED },
                    );
                }
                let child = GetSubMenu(menu as _, index as i32);
                if !child.is_null() {
                    check_submenus(child as _, entries);
                }
            }
        }
    }
}

// --- Clipboard and browser helpers ---

/// Copies `text` to the Windows clipboard.
fn write_clipboard(text: &str) {
    let text = encode_wide(text);
    let size = text.len() * 2;
    // SAFETY: `memory` holds `size` bytes and is filled while locked. If SetClipboardData succeeds,
    // the system owns the handle; otherwise we free it.
    unsafe {
        let memory = GlobalAlloc(GMEM_MOVEABLE, size);
        if memory.is_null() {
            return;
        }
        let p = GlobalLock(memory).cast::<u16>();
        if p.is_null() {
            GlobalFree(memory);
            return;
        }
        std::ptr::copy_nonoverlapping(text.as_ptr(), p, text.len());
        GlobalUnlock(memory);
        if OpenClipboard(null_mut()) == 0 {
            GlobalFree(memory);
            return;
        }
        EmptyClipboard();
        if SetClipboardData(CF_UNICODETEXT, memory).is_null() {
            GlobalFree(memory);
        }
        CloseClipboard();
    }
}

fn read_clipboard() -> Option<String> {
    // SAFETY: the clipboard is opened and closed within this call, and the global memory handle is
    // read only while locked up to its terminating NUL.
    unsafe {
        if OpenClipboard(null_mut()) == 0 {
            return None;
        }
        let handle = GetClipboardData(CF_UNICODETEXT);
        let text = (!handle.is_null())
            .then(|| GlobalLock(handle).cast::<u16>())
            .filter(|p| !p.is_null())
            .and_then(|p| {
                let units = GlobalSize(handle) / size_of::<u16>();
                let text = model::decode_clipboard_text(std::slice::from_raw_parts(p, units));
                GlobalUnlock(handle);
                text
            });
        CloseClipboard();
        text
    }
}

/// Opens `url` in the default browser, or offers to copy it to the clipboard.
fn open_in_browser(url: &str) {
    let (verb, file) = (encode_wide("open"), encode_wide(url));
    // SAFETY: both strings are NUL-terminated and outlive the call.
    let opened = unsafe {
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            null(),
            null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecuteW returns a value greater than 32 on success.
    if opened as isize <= 32
        && ask(
            "No browser opened the portal",
            &format!("Open it in a browser on any device:\n{url}"),
            Mood::Information,
            "Copy link",
            "Close",
        )
    {
        write_clipboard(url);
    }
}

// --- Menu actions and login flow ---

/// Executes a menu `action` and displays an error dialog if it fails.
fn run(action: Action) {
    let describe_action_error = |c: &ConnectionInMenu, what: &str| format!("{} {what}", c.label());
    let (request, failure) = match action {
        Action::Connect(c) => (
            IpcRequest::Connect {
                name: c.name.clone(),
            },
            describe_action_error(&c, "failed to connect"),
        ),
        Action::Disconnect(c) => (
            IpcRequest::Disconnect {
                name: c.name.clone(),
            },
            describe_action_error(&c, "failed to disconnect"),
        ),
        Action::SetProfile {
            connection,
            profile,
            allowed_ips,
        } => (
            IpcRequest::SetProfile {
                name: connection.name.clone(),
                profile,
                allowed_ips,
            },
            describe_action_error(&connection, "could not update routes"),
        ),
        Action::SetDns {
            connection,
            enabled,
        } => (
            IpcRequest::SetDns {
                name: connection.name.clone(),
                enabled,
            },
            describe_action_error(&connection, "could not update DNS setting"),
        ),
        Action::RotateKey(c) => (
            IpcRequest::RotateKey {
                name: c.name.clone(),
            },
            describe_action_error(&c, "could not rotate key"),
        ),
        Action::RotatePsk(c) => (
            IpcRequest::RotatePsk {
                name: c.name.clone(),
            },
            describe_action_error(&c, "could not rotate preshared key"),
        ),
        Action::OpenPortal(url) => return open_in_browser(&url),
        Action::Logout(c) => return log_out(&c),
        Action::Login(portal) => return log_in(portal, None),
        Action::AddFromClipboard => {
            match read_clipboard().as_deref().and_then(model::parse_clipboard) {
                Some((portal, device)) => return log_in(portal, device),
                None => {
                    let help = "Copy the portal URL or the login command from the portal first.";
                    tell("Nothing to add from the clipboard", help, Mood::Information);
                    return;
                }
            }
        }
        Action::Exit => return,
    };
    if let Err(e) = call(&request) {
        tell(&failure, &e, Mood::Error);
    }
}

/// Prompts for confirmation and logs out of `conn`.
fn log_out(conn: &ConnectionInMenu) {
    let label = conn.label();
    let confirmed = ask(
        &format!("Log out of {label}?"),
        "Removes this connection from this computer, and revokes its agent credential on the controller.",
        Mood::Warning,
        "Log out",
        "Cancel",
    );
    if !confirmed {
        return;
    }
    match call(&IpcRequest::Logout {
        name: conn.name.clone(),
    }) {
        Ok(answer) if answer["revoked"] == false => tell(
            &format!("{label} is logged out"),
            "The server could not be reached. Revoke the device in the portal if needed.",
            Mood::Warning,
        ),
        Ok(_) => {}
        Err(e) => tell(&format!("Failed to log out {label}"), &e, Mood::Error),
    }
}

/// Runs the interactive browser login flow for `portal` through the agent service.
fn log_in(portal: String, device: Option<String>) {
    let host_name = ito_agent_windows::read_host_name();
    let start = IpcRequest::LoginStart {
        portal: portal.clone(),
        device,
        host_name,
        no_dns: false,
    };
    let ticket = match call(&start)
        .and_then(|v| serde_json::from_value::<LoginTicket>(v).map_err(|e| e.to_string()))
    {
        Ok(ticket) => ticket,
        Err(e) => return tell("Failed to start login", &e, Mood::Error),
    };
    // Confirm the target portal with the user before opening the browser. `ito-wg://` links can be
    // triggered from arbitrary web pages.
    let confirmed = ask(
        &format!(
            "Log in to {}?",
            model::extract_portal_host(&portal).unwrap_or_else(|| portal.clone())
        ),
        &format!(
            "Your browser opens the portal to approve this computer (confirmation code: {}).",
            ticket.code
        ),
        Mood::Information,
        "Log in",
        "Cancel",
    );
    if !confirmed {
        return;
    }
    open_in_browser(&ticket.url);
    let finish = IpcRequest::LoginFinish {
        request: ticket.request,
        connect: true,
    };
    let outcome = match call(&finish)
        .and_then(|v| serde_json::from_value::<LoginOutcome>(v).map_err(|e| e.to_string()))
    {
        Ok(outcome) => outcome,
        Err(e) => return tell("Failed to complete login", &e, Mood::Error),
    };
    let s = &outcome.summary;
    let new = ConnectionInMenu::from_summary(s);
    let how = if outcome.reauthenticated {
        "is logged in again"
    } else {
        "is added"
    };
    let heading = format!("{} {how}", new.label());
    let format_other_label = |name: &str| {
        outcome
            .others
            .iter()
            .find(|o| o.name == name)
            .map_or(name.to_string(), |o| {
                ConnectionInMenu::from_summary(o).label()
            })
    };
    let mut text = String::new();
    if let Some(other) = &outcome.overlap {
        text += &format!(
            "Not connected: conflicting route prefix already in use by active connection {}.\n\n",
            format_other_label(other)
        );
    }
    if outcome.others.is_empty() {
        return tell(&heading, text.trim_end(), Mood::Information);
    }
    text += &format!("This computer has other connections to {}:\n", s.portal);
    for o in &outcome.others {
        let state = if o.state.wants_connection() {
            "connected"
        } else {
            "disconnected"
        };
        let (conn, interface) = (ConnectionInMenu::from_summary(o), &o.device.interface_id);
        text += &format!("\n{} on {interface}, {state}", conn.label());
    }
    let confirmed = ask(
        &heading,
        &text,
        Mood::Information,
        "Log out others",
        "Keep others",
    );
    if !confirmed {
        return;
    }
    for o in &outcome.others {
        if let Err(e) = call(&IpcRequest::Logout {
            name: o.name.clone(),
        }) {
            tell(
                &format!(
                    "Failed to log out {}",
                    ConnectionInMenu::from_summary(o).label()
                ),
                &e,
                Mood::Error,
            );
        }
    }
    // Connect the new connection if it was previously blocked by the old connections that were just
    // logged out.
    let overlap = outcome.overlap.as_ref();
    if overlap.is_some_and(|x| outcome.others.iter().any(|o| &o.name == x))
        && let Err(e) = call(&IpcRequest::Connect {
            name: s.name.clone(),
        })
    {
        tell(
            &format!("{} failed to connect", new.label()),
            &e,
            Mood::Error,
        );
    }
}

// --- Entry point and event loop ---

/// Converts a CLI setting result into an `ExitCode`, showing an error dialog on failure.
fn report(heading: &str, result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tell(heading, &e, Mood::Error);
            ExitCode::FAILURE
        }
    }
}

pub fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match &args[..] {
        [flag, link] if flag == "--open" => {
            let Some((portal, device)) = model::parse_link(link) else {
                return report("This is not an Ito link", Err(link.clone()));
            };
            log_in(portal, device);
            return ExitCode::SUCCESS;
        }
        [] => {}
        _ => {
            return report(
                "Ito could not start",
                Err("Use ito-tray or ito-tray --open LINK".into()),
            );
        }
    }
    let _instance = match acquire_single_instance() {
        Ok(Some(instance)) => instance,
        Ok(None) => return ExitCode::SUCCESS,
        Err(e) => return report("Ito could not start", Err(e.to_string())),
    };
    // Poll the agent service in the background on `POLL_INTERVAL` or on `refresh`. Signal `woken`
    // after sending each snapshot.
    let woken = match create_event() {
        Ok(event) => Arc::new(event),
        Err(e) => {
            tell("Ito could not start", &e.to_string(), Mood::Error);
            return ExitCode::FAILURE;
        }
    };
    let (snapshots, latest) = mpsc::channel();
    let (refresh, refresh_wanted) = mpsc::channel::<()>();
    let signal = woken.clone();
    thread::spawn(move || {
        while snapshots.send(read_snapshot()).is_ok() {
            // SAFETY: the event handle is valid while `signal` is alive.
            unsafe { SetEvent(signal.as_raw_handle() as HANDLE) };
            let _ = refresh_wanted.recv_timeout(POLL_INTERVAL);
            // Coalesce multiple refresh requests that arrived during a read.
            while refresh_wanted.try_recv().is_ok() {}
        }
    });
    let built = TrayIconBuilder::new()
        .with_tooltip("Ito")
        .with_icon(build_icon(Look::Down))
        .build();
    let tray = match built {
        Ok(tray) => tray,
        Err(e) => {
            tell(
                "Ito could not show its tray icon",
                &e.to_string(),
                Mood::Error,
            );
            return ExitCode::FAILURE;
        }
    };
    let mut actions = HashMap::new();
    let wake = [woken.as_raw_handle() as HANDLE];
    loop {
        // Wait for either a Win32 window message or a snapshot wakeup event.
        // SAFETY: the event handle is valid while `woken` is alive.
        unsafe { MsgWaitForMultipleObjects(1, wake.as_ptr(), 0, INFINITE, QS_ALLINPUT) };
        // SAFETY: MSG is plain data; zero is valid for every field.
        let mut msg: MSG = unsafe { std::mem::zeroed() };
        // SAFETY: `msg` is a valid MSG struct for the current thread's message queue.
        while unsafe { PeekMessageW(&mut msg, null_mut(), 0, 0, PM_REMOVE) } != 0 {
            // SAFETY: `msg` was just retrieved from `PeekMessageW`.
            unsafe {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        // Trigger a background refresh when hovering or clicking the tray icon.
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            let down = MouseButtonState::Down;
            if matches!(event, TrayIconEvent::Enter { .. })
                || matches!(event, TrayIconEvent::Click { button_state, .. } if button_state == down)
            {
                let _ = refresh.send(());
            }
        }
        // Process queued menu clicks before rebuilding the menu and replacing menu IDs.
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            match actions.get(event.id()) {
                Some(Action::Exit) => return ExitCode::SUCCESS,
                Some(action) => {
                    let (action, refresh) = (action.clone(), refresh.clone());
                    thread::spawn(move || {
                        run(action);
                        let _ = refresh.send(());
                    });
                }
                None => {}
            }
        }
        if let Some(snapshot) = latest.try_iter().last() {
            let mut entries = model::build_menu(&snapshot.connections, &snapshot.statuses);
            if let Some(e) = &snapshot.error {
                entries.insert(0, Entry::Text(e.clone()));
            }
            actions.clear();
            let items = render(&entries, &mut actions);
            let items: Vec<&dyn IsMenuItem> = items.iter().map(AsRef::as_ref).collect();
            if let Ok(menu) = Menu::with_items(&items) {
                check_submenus(menu.hpopupmenu(), &entries);
                tray.set_menu(Some(Box::new(menu)));
            }
            let look = if snapshot.error.is_some() {
                Look::Problem
            } else {
                model::determine_look(&snapshot.connections)
            };
            let _ = tray.set_icon(Some(build_icon(look)));
        }
    }
}

/// Creates an auto-reset Win32 event object.
fn create_event() -> std::io::Result<OwnedHandle> {
    // SAFETY: default security attributes and unnamed event. Null return is checked immediately.
    let event = unsafe { CreateEventW(null(), 0, 0, null()) };
    if event.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `event` was just created and is uniquely owned here.
    Ok(unsafe { OwnedHandle::from_raw_handle(event as RawHandle) })
}

/// Acquires the per-session tray mutex, returning `None` if an instance is already running.
fn acquire_single_instance() -> std::io::Result<Option<OwnedHandle>> {
    let name = encode_wide(r"Local\ItoTray");
    // SAFETY: the name is terminated; the returned handle is owned below.
    let handle = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: reads this thread's last-error code immediately after CreateMutexW.
    let exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    // SAFETY: CreateMutexW returned a new reference to a valid handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
    Ok((!exists).then_some(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_submenus_use_native_checked_states() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetMenuState, MF_BYPOSITION, MF_CHECKED,
        };
        let entries = [true, false].map(|checked| Entry::Submenu {
            label: "Laptop".into(),
            checked: Some(checked),
            entries: vec![Entry::Text("State".into())],
        });
        let items = render(&entries, &mut HashMap::new());
        let refs: Vec<&dyn IsMenuItem> = items.iter().map(AsRef::as_ref).collect();
        let menu = Menu::with_items(&refs).unwrap();
        check_submenus(menu.hpopupmenu(), &entries);
        // SAFETY: these are the positions just added to this live native menu.
        unsafe {
            assert_ne!(
                GetMenuState(menu.hpopupmenu() as _, 0, MF_BYPOSITION) & MF_CHECKED,
                0
            );
            assert_eq!(
                GetMenuState(menu.hpopupmenu() as _, 1, MF_BYPOSITION) & MF_CHECKED,
                0
            );
        }
    }
}
