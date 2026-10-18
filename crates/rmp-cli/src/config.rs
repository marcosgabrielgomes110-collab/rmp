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
#[serde(default)]
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
    /// Maximum number of concurrent QUIC connections.
    pub max_connections: usize,
    /// Allow clients to open local port forwards (`rmp connect -L`).
    pub allow_local_forward: bool,
    /// Allow clients to request remote port forwards (`rmp connect -R`).
    pub allow_remote_forward: bool,
    /// Allow non-root logins to bind ports below 1024 through `-R` in root mode.
    pub allow_privileged_ports: bool,
    /// Allow file transfer (`rmp cp`).
    pub allow_file_transfer: bool,
}

/// `[auth]` — authentication policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
pub struct Logging {
    /// Write log files in the state directory.
    pub enabled: bool,
    /// Default log level (`trace`/`debug`/`info`/`warn`/`error`).
    pub level: String,
    /// File log format: `text` (default) or `json` (one object per line).
    pub format: String,
    /// Also maintain `audit.log` with security events.
    pub audit: bool,
    /// Include executed commands in the audit log.
    pub log_commands: bool,
    /// Override the directory for log files ("" = state directory).
    pub log_dir: String,
}

/// `[client]` — behavior of `rmp connect`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
    max_connections: 128,
    allow_local_forward: true,
    allow_remote_forward: false,
    allow_privileged_ports: false,
    allow_file_transfer: true,
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
    format: "text".to_string(),
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

const SERVER_KEYS: &[&str] = &[
    "enabled",
    "listen",
    "username",
    "shell",
    "motd",
    "max_sessions",
    "max_connections",
    "allow_local_forward",
    "allow_remote_forward",
    "allow_privileged_ports",
    "allow_file_transfer",
];
const AUTH_KEYS: &[&str] = &[
    "password_enabled",
    "allow_root",
    "allow_key_auth",
    "allow_key_enrollment",
    "max_auth_attempts",
    "lockout_secs",
];
const SECURITY_KEYS: &[&str] = &[
    "allowed_cidrs",
    "denied_cidrs",
    "idle_timeout_secs",
    "keep_alive_secs",
];
const LOGGING_KEYS: &[&str] = &[
    "enabled",
    "level",
    "format",
    "audit",
    "log_commands",
    "log_dir",
];
const CLIENT_KEYS: &[&str] = &[
    "strict_host_key",
    "accept_new_hosts",
    "enable_key_auth",
    "offer_enrollment",
    "connect_timeout_secs",
    "idle_timeout_secs",
];

/// Detect unknown sections and keys without rejecting the file.
///
/// The runtime stays permissive so new options do not break older binaries, but
/// `rmp config-check` uses this to catch typos that would silently fall back to
/// defaults.
pub fn unknown_keys(text: &str) -> Result<Vec<String>> {
    let value: toml::Value = toml::from_str(text)?;
    let Some(table) = value.as_table() else {
        return Ok(vec!["<root> must be a table".to_string()]);
    };

    let mut unknown = Vec::new();
    for (section, section_value) in table {
        let known = match section.as_str() {
            "server" => SERVER_KEYS,
            "auth" => AUTH_KEYS,
            "security" => SECURITY_KEYS,
            "logging" => LOGGING_KEYS,
            "client" => CLIENT_KEYS,
            _ => {
                unknown.push(section.clone());
                continue;
            }
        };
        match section_value.as_table() {
            Some(section_table) => {
                for key in section_table.keys() {
                    if !known.contains(&key.as_str()) {
                        unknown.push(format!("{section}.{key}"));
                    }
                }
            }
            None => unknown.push(format!("{section} (expected a table)")),
        }
    }
    Ok(unknown)
}

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
# Maximum number of simultaneous QUIC connections.
max_connections = 128
# Allow clients to open local port forwards (rmp connect -L).
allow_local_forward = true
# Allow clients to request remote port forwards (rmp connect -R; binds on 127.0.0.1).
allow_remote_forward = false
# In root mode, allow non-root logins to request -R on ports below 1024
# (the daemon binds them). Explicit opt-in; off by default.
allow_privileged_ports = false
# Allow file transfer (rmp cp).
allow_file_transfer = true

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
# File log format: "text" or "json" (console output stays text).
format = "text"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_config_is_accepted() {
        // A config missing newer fields must still parse, with defaults filled in.
        let text = r#"
            [server]
            listen = "0.0.0.0:2222"
            username = "dev"
        "#;
        let cfg: FileConfig = toml::from_str(text).unwrap();
        assert_eq!(cfg.server.username, "dev");
        assert!(cfg.server.allow_file_transfer, "defaults applied");
        assert_eq!(cfg.server.max_connections, 128);
        assert_eq!(cfg.auth.max_auth_attempts, 5);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let text = r#"
            [server]
            username = "dev"
            some_future_option = true
        "#;
        assert!(toml::from_str::<FileConfig>(text).is_ok());
    }

    #[test]
    fn unknown_keys_are_reported() {
        let text = r#"
            [server]
            username = "dev"
            some_future_option = true
            [nonsense]
            x = 1
        "#;
        let unknown = unknown_keys(text).unwrap();
        assert!(unknown.contains(&"server.some_future_option".to_string()));
        assert!(unknown.contains(&"nonsense".to_string()));
    }

    #[test]
    fn known_keys_are_not_reported() {
        let unknown = unknown_keys(&template("alice", "0.0.0.0:2222", false)).unwrap();
        assert!(unknown.is_empty(), "template has unknown keys: {unknown:?}");
    }
}
