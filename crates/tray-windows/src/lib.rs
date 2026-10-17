//! Windows system tray application for managing Ito agent connections.
//!
//! [`model`] contains the platform-independent menu layout, icon drawing, and link parsing logic.
//! [`app`] contains the Win32 event loop, dialogs, and named-pipe IPC client.

pub mod model;

#[cfg(windows)]
pub mod app;
