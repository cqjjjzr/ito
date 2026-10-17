//! The controller through its HTTP API and domain functions, on SQLite and the fake kernel.

#[path = "../common/mod.rs"]
mod common;

mod accounts;
mod devices;
mod dns;
mod endpoints;
mod identity;
mod interfaces;
mod reconcile;
mod requests;
mod sessions;
