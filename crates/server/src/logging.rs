use crate::config::{Log, LogFormat};
use std::{
    io::IsTerminal,
    os::{fd::AsFd, unix::fs::MetadataExt},
};
use tracing_subscriber::{EnvFilter, Layer, layer::SubscriberExt, util::SubscriberInitExt};

/// Installs the global `tracing` subscriber. When `format` is `auto` and stderr is connected to
/// the systemd journal, structured fields are emitted with an `ITO_` prefix; otherwise text or
/// JSON logs are written to stderr.
pub fn init(cfg: &Log) {
    let journal = if cfg.format == LogFormat::Auto && is_stderr_journal() {
        tracing_journald::layer()
            .map(|l| {
                l.with_field_prefix(Some("ITO".into()))
                    // Set the syslog identifier explicitly so wrapper scripts do not alter it.
                    .with_syslog_identifier("ito".into())
            })
            .ok()
    } else {
        None
    };
    let output = match (journal, cfg.format) {
        (Some(journal), _) => journal.boxed(),
        (None, LogFormat::Json) => tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_writer(std::io::stderr)
            .boxed(),
        (None, _) => tracing_subscriber::fmt::layer()
            .with_ansi(std::io::stderr().is_terminal())
            .with_writer(std::io::stderr)
            .boxed(),
    };
    tracing_subscriber::registry()
        .with(output.with_filter(EnvFilter::new(&cfg.level)))
        .init();
}

/// Returns true if stderr matches the `JOURNAL_STREAM` device and inode set by systemd.
fn is_stderr_journal() -> bool {
    let Ok(stream) = std::env::var("JOURNAL_STREAM") else {
        return false;
    };
    std::io::stderr()
        .as_fd()
        .try_clone_to_owned()
        .and_then(|fd| std::fs::File::from(fd).metadata())
        .is_ok_and(|m| matches_journal_stream(&stream, &m))
}

/// Returns true if a `JOURNAL_STREAM` value (`DEVICE:INODE`) matches `m`.
fn matches_journal_stream(stream: &str, m: &std::fs::Metadata) -> bool {
    stream
        .split_once(':')
        .is_some_and(|(dev, ino)| dev.parse() == Ok(m.dev()) && ino.parse() == Ok(m.ino()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn journal_stream_must_name_this_file() {
        let file = tempfile::tempfile().unwrap();
        let m = file.metadata().unwrap();
        use std::os::unix::fs::MetadataExt;
        assert!(super::matches_journal_stream(
            &format!("{}:{}", m.dev(), m.ino()),
            &m
        ));
        assert!(!super::matches_journal_stream(
            &format!("{}:{}", m.dev(), m.ino() + 1),
            &m
        ));
        assert!(!super::matches_journal_stream("", &m));
    }
}
