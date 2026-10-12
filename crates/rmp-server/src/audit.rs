//! Audit events.
//!
//! Every security-relevant event is emitted with the dedicated target
//! `rmp::audit`, which the CLI routes to `audit.log` unconditionally.
//!
//! Field convention: a leading `event = "..."` identifies the action; the
//! remaining fields are non-sensitive identifiers. Secrets (passwords, private
//! keys, session keys) must **never** be logged.

/// Emit an audit event.
macro_rules! audit {
    ($($tt:tt)*) => {
        ::tracing::info!(target: "rmp::audit", $($tt)*)
    };
}

pub(crate) use audit;
