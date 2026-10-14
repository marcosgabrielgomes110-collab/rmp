//! Server and client configuration (`config.toml`).
//!
//! The file is split into sections; every option has a safe default so a
//! partially-written file still parses. `rmp init` writes a fully commented
//! template (see [`template`]).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The whole `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub server: Server,
    #[serde(default)]
    pub auth: Auth,
    #[serde(default)]
    pub security: Security,
    #[serde(default)]
    pub logging: Logging,
    #[serde(default)]
    pub client: Client,
}

/// `[server]` — daemon behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    /// Enable the server. `false` makes `rmp serve` refuse to start.
    pub enabled: bool,
    /// Address to listen on.
    pub listen: String,
    /// Account name accepted for password authentication.
    pub username: String,
    /// Login shell ("" = `$SHELL` or the platform default).
    pub shell: String,
    /// Message shown at the start of each session ("" = none).
    pub motd: String,
    /// Maximum number of concurrent sessions.
    pub max_sessions: usize,
}

/// `[auth]` — authentication policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth {
    /// Master switch for password authentication.
    pub password_enabled: bool,
    /// Allow authenticating as `root` (requires the server to run as root).
    pub allow_root: bool,
    /// Allow device-key (public-key) authentication.
    pub allow_key_auth: bool,
    /// Allow enrolling a device key after a successful password login.
    pub allow_key_enrollment: bool,
    /// Failed attempts allowed before a temporary lockout.
    pub max_auth_attempts: u32,
    /// Lockout duration in seconds.
    pub lockout_secs: u64,
}

/// `[security]` — network policy and timeouts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Security {
    /// Addresses allowed to connect (empty = any).
    pub allowed_cidrs: Vec<String>,
    /// Addresses explicitly refused (takes precedence).
    pub denied_cidrs: Vec<String>,
    /// QUIC idle timeout in seconds.
    pub idle_timeout_secs: u64,
    /// QUIC keep-alive interval in seconds.
    pub keep_alive_secs: u64,
}

/// `[logging]` — logging policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Logging {
    /// Write log files in the state directory.
    pub enabled: bool,
    /// Default log level (`trace`/`debug`/`info`/`warn`/`error`).
    pub level: String,
    /// Also maintain `audit.log` with security events.
    pub audit: bool,
    /// Include executed commands in the audit log.
    pub log_commands: bool,
    /// Override the directory for log files ("" = state directory).
    pub log_dir: String,
}

/// `[client]` — behavior of `rmp connect`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    /// Enforce host key pinning (never disable in production).
    pub strict_host_key: bool,
    /// Trust unseen hosts without prompting (trust-on-first-use).
    pub accept_new_hosts: bool,
    /// Try device-key authentication before falling back to a password.
    pub enable_key_auth: bool,
    /// Offer to enroll this device's key after a password login.
    pub offer_enrollment: bool,
    /// Timeout for establishing the connection, in seconds.
    pub connect_timeout_secs: u64,
    /// Default idle timeout for sessions, in seconds.
    pub idle_timeout_secs: u64,
}

macro_rules! defaults {
    ($ty:ident, $($field:ident : $value:expr),+ $(,)?) => {
        impl Default for $ty {
            fn default() -> Self {
                $ty { $($field: $value),+ }
            }
        }
    };
}

defaults!(Server,
    enabled: true,
    listen: "0.0.0.0:2222".to_string(),
    username: "rmp".to_string(),
    shell: String::new(),
    motd: String::new(),
    max_sessions: 8,
);

defaults!(Auth,
    password_enabled: true,
    allow_root: false,
    allow_key_auth: true,
    allow_key_enrollment: true,
    max_auth_attempts: 5,
    lockout_secs: 30,
);

defaults!(Security,
    allowed_cidrs: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
    denied_cidrs: Vec::new(),
    idle_timeout_secs: 600,
    keep_alive_secs: 15,
);

defaults!(Logging,
    enabled: true,
    level: "info".to_string(),
    audit: true,
    log_commands: true,
    log_dir: String::new(),
);

defaults!(Client,
    strict_host_key: true,
    accept_new_hosts: false,
    enable_key_auth: true,
    offer_enrollment: true,
    connect_timeout_secs: 10,
    idle_timeout_secs: 600,
);

impl FileConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    /// Load the file, or return defaults if it does not exist.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self::default())
        }
    }
}

/// The fully commented configuration template written by `rmp init`.
pub fn template(username: &str, listen: &str, allow_root: bool) -> String {
    format!(
        r#"# ─────────────────────────────────────────────────────────────────────────
# RMP — Remote Machine Protocol · configuration
#
# Read by `rmp serve` (server/auth/security/logging) and `rmp connect` (client).
# Every option has a safe default; comment or delete a line to use it.
# ─────────────────────────────────────────────────────────────────────────

[server]
# Enable the daemon. false → `rmp serve` refuses to start.
enabled = true
# Address and UDP port to listen on.
listen = "{listen}"
# Account name accepted for remote access.
username = "{username}"
# Login shell. "" = $SHELL, or /bin/sh (Linux) / cmd.exe (Windows).
shell = ""
# Message shown at the start of every session. "" = none.
motd = ""
# Maximum number of simultaneous sessions.
max_sessions = 8

[auth]
# Master switch for password authentication. false → nobody can log in.
password_enabled = true
# Allow logging in as `root`. Requires the server to run as root (systemd).
# Set the root password with `rmp passwd --root` (or `rmp init --root`).
allow_root = {allow_root}
# Allow device-key (public-key) authentication.
allow_key_auth = true
# Allow enrolling a device key after a successful password login.
allow_key_enrollment = true
# Failed attempts before a temporary lockout (per source IP).
max_auth_attempts = 5
# Lockout duration, in seconds.
lockout_secs = 30

[security]
# Addresses allowed to connect (CIDR). Empty list = any address.
allowed_cidrs = ["0.0.0.0/0", "::/0"]
# Addresses explicitly refused; takes precedence over allowed_cidrs.
denied_cidrs = []
# Drop idle connections after this many seconds.
idle_timeout_secs = 600
# QUIC keep-alive interval, in seconds.
keep_alive_secs = 15

[logging]
# Write rmp.log and audit.log in the state directory.
enabled = true
# Default log level: trace | debug | info | warn | error (RUST_LOG overrides).
level = "info"
# Maintain a dedicated audit.log with security events.
audit = true
# Record executed commands in the audit log.
log_commands = true
# Override the log directory ("" = state directory).
log_dir = ""

[client]
# Enforce host key pinning (never set to false in production).
strict_host_key = true
# Trust unseen hosts without prompting.
accept_new_hosts = false
# Try device-key authentication before falling back to a password.
enable_key_auth = true
# Offer to enroll this device's key after a password login.
offer_enrollment = true
# Timeout for establishing a connection, in seconds.
connect_timeout_secs = 10
# Default session idle timeout, in seconds.
idle_timeout_secs = 600
"#
    )
}
