//! Logging setup.
//!
//! Depending on `[logging]` in the config, two file destinations are produced in
//! the state (or configured log) directory:
//!
//! * `rmp.log.<date>` — everything (console + detailed internal events);
//! * `audit.log.<date>` — **only** security-relevant events (target
//!   [`AUDIT_TARGET`]).
//!
//! Log events never contain secret material (passwords, private keys, session
//! keys). They carry non-sensitive identifiers (peer address, username,
//! fingerprint, command…).

use crate::config::Logging;
use anyhow::Result;
use rmp_dirs::Layout;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::{EnvFilter, LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, Layer};

/// Tracing target reserved for audit events.
pub const AUDIT_TARGET: &str = "rmp::audit";

/// Keeps the background log writers alive; dropping it flushes the logs.
pub struct LogGuard {
    _general: Option<WorkerGuard>,
    _audit: Option<WorkerGuard>,
}

/// Initialize logging according to `cfg`, returning a guard to keep alive.
pub fn init(layout: &Layout, cfg: &Logging) -> Result<LogGuard> {
    let console_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| level_filter(&cfg.level));
    let console_layer = fmt::layer()
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_filter(console_filter);

    if !cfg.enabled {
        // Console only: no files, no guard.
        tracing_subscriber::registry().with(console_layer).init();
        return Ok(LogGuard {
            _general: None,
            _audit: None,
        });
    }

    // Where to write: explicit override or the state directory.
    let dir = if cfg.log_dir.is_empty() {
        layout.state_dir.clone()
    } else {
        std::path::PathBuf::from(&cfg.log_dir)
    };
    // Keep log files private even when `log_dir` points outside the state dir.
    rmp_dirs::create_private_dir(&dir)?;

    let general = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix(rmp_dirs::LOG_FILE)
        .max_log_files(14)
        .build(&dir)?;
    let (general_writer, general_guard) = tracing_appender::non_blocking(general);

    // File: verbose for RMP's own crates so nothing we emit is lost.
    let file_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::try_new(format!(
            "warn,rmp={l},rmp_server={l},rmp_client={l},rmp_crypto={l},rmp_proto={l},rmp_dirs={l}",
            l = cfg.level
        ))
        .unwrap_or_else(|_| EnvFilter::new("info"))
    });
    // Audit: only our dedicated target, at INFO and above.
    let (audit_writer, audit_guard) = if cfg.audit {
        let appender = tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix(rmp_dirs::AUDIT_FILE)
            .max_log_files(30)
            .build(&dir)?;
        let (writer, guard) = tracing_appender::non_blocking(appender);
        (Some(writer), Some(guard))
    } else {
        (None, None)
    };
    let audit_filter = Targets::new()
        .with_default(LevelFilter::OFF)
        .with_target(AUDIT_TARGET, LevelFilter::INFO);

    let json = cfg.format.eq_ignore_ascii_case("json");
    if json {
        let file_layer = fmt::layer()
            .json()
            .with_ansi(false)
            .with_target(true)
            .with_writer(general_writer)
            .with_filter(file_filter);
        let audit_layer = audit_writer.map(|writer| {
            fmt::layer()
                .json()
                .with_ansi(false)
                .with_target(false)
                .with_writer(writer)
                .with_filter(audit_filter)
        });
        tracing_subscriber::registry()
            .with(console_layer)
            .with(file_layer)
            .with(audit_layer)
            .init();
    } else {
        let file_layer = fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_writer(general_writer)
            .with_filter(file_filter);
        let audit_layer = audit_writer.map(|writer| {
            fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(writer)
                .with_filter(audit_filter)
        });
        tracing_subscriber::registry()
            .with(console_layer)
            .with(file_layer)
            .with(audit_layer)
            .init();
    }

    Ok(LogGuard {
        _general: Some(general_guard),
        _audit: audit_guard,
    })
}

/// Parse a configured level without panicking on a typo.
fn level_filter(level: &str) -> EnvFilter {
    EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"))
}
