//! Periodic synchronization loop shared by the Windows service and foreground console mode.

use ito_agent_core::{agent::Agent, tunnel::TunnelDriver};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::sync::Notify;

/// Synchronizes all saved connections immediately and every 60 seconds until `stop` is notified.
///
/// Logs sync, listing, and per-connection errors to `log` only when they change.
pub async fn run<T: TunnelDriver>(agent: Arc<Agent<T>>, stop: Arc<Notify>, log: fn(&str)) {
    let mut reported: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut sync_error = None;
    let mut list_error = None;
    let syncing = async {
        loop {
            let result = agent.sync_all().await;
            report_failure(
                &mut sync_error,
                result.err().map(|e| e.to_string()),
                "sync",
                log,
            );
            let connections = agent.list().await;
            report_failure(
                &mut list_error,
                connections.as_ref().err().map(ToString::to_string),
                "list",
                log,
            );
            for s in connections.unwrap_or_default() {
                if reported.get(&s.name) != Some(&s.last_error) {
                    match &s.last_error {
                        Some(e) => log(&format!("{}: {e}", s.name)),
                        None => log(&format!("{}: in step", s.name)),
                    }
                    reported.insert(s.name.clone(), s.last_error.clone());
                }
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(60)) => {}
                () = stop.notified() => return,
            }
        }
    };
    tokio::select! {
        () = agent.expire_logins() => {},
        () = syncing => {},
    }
}

fn report_failure(
    previous: &mut Option<String>,
    current: Option<String>,
    operation: &str,
    mut log: impl FnMut(&str),
) {
    if *previous != current {
        if let Some(error) = &current {
            log(&format!("{operation} failed: {error}"));
        }
        *previous = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failures_are_reported_on_change_and_again_after_recovery() {
        let mut previous = None;
        let mut lines = Vec::new();
        for error in [
            None,
            Some("offline"),
            Some("offline"),
            Some("denied"),
            None,
            Some("denied"),
        ] {
            report_failure(&mut previous, error.map(Into::into), "sync", |line| {
                lines.push(line.to_owned());
            });
        }
        assert_eq!(
            lines,
            [
                "sync failed: offline",
                "sync failed: denied",
                "sync failed: denied"
            ]
        );
    }
}
