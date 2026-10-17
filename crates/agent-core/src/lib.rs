//! Platform-independent core for Ito host agents: HTTP API client, local connection storage,
//! tunnel synchronization, and IPC protocol.

pub mod agent;
#[cfg(feature = "cli")]
pub mod cli;
pub mod client;
pub mod ipc;
pub mod login;
pub mod naming;
pub mod spec;
pub mod state;
pub mod tunnel;
pub mod wg_quick;
