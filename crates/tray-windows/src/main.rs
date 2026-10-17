//! Entry point for `ito-tray`, the Windows notification-area interface for the Ito agent.
//! Supports `--open <ito-wg-url>`.

#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    return ito_tray::app::main();
    #[cfg(not(windows))]
    {
        eprintln!("ito-tray: the tray is for Windows");
        std::process::ExitCode::FAILURE
    }
}
