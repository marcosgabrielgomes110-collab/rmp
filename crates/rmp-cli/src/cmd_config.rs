//! `rmp config-check` — validate `config.toml` without starting the server.

use crate::config::{unknown_keys, FileConfig};
use anyhow::{bail, Context, Result};
use rmp_dirs::Layout;
use std::net::SocketAddr;
use tracing_subscriber::filter::EnvFilter;

/// Validate the configuration and print warnings for suspicious values.
pub fn run(layout: &Layout) -> Result<()> {
    let warnings = validate(layout)?;
    let path = layout.config_file();
    for warning in &warnings {
        eprintln!("[rmp] warning: {warning}");
    }
    if warnings.is_empty() {
        println!("configuration OK: {}", path.display());
    } else {
        println!(
            "configuration OK with {} warning(s): {}",
            warnings.len(),
            path.display()
        );
    }
    Ok(())
}

/// Validate the configuration, returning warnings.
pub fn validate(layout: &Layout) -> Result<Vec<String>> {
    let path = layout.config_file();
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {} (run `rmp init` first)", path.display()))?;

    let config: FileConfig =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

    let mut warnings = Vec::new();
    for key in unknown_keys(&text)? {
        warnings.push(format!("unknown option `{key}` (ignored at runtime)"));
    }

    if config.server.username.trim().is_empty() {
        bail!("server.username must not be empty");
    }
    if config.server.username == "root" {
        bail!("server.username must not be 'root'; use auth.allow_root for root access");
    }
    if !config.server.enabled {
        warnings.push("server.enabled = false; `rmp serve` will refuse to start".to_string());
    }
    if config.server.allow_privileged_ports {
        warnings.push(
            "server.allow_privileged_ports = true; non-root logins can bind ports below 1024 \
             via -R while the server runs as root"
                .to_string(),
        );
    }

    config
        .server
        .listen
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid server.listen {:?}", config.server.listen))?;

    if config.server.max_sessions == 0 {
        bail!("server.max_sessions must be greater than zero");
    }
    if config.server.max_connections == 0 {
        bail!("server.max_connections must be greater than zero");
    }

    rmp_server::net::parse_list(&config.security.allowed_cidrs)
        .map_err(|e| anyhow::anyhow!("security.allowed_cidrs: {e}"))?;
    rmp_server::net::parse_list(&config.security.denied_cidrs)
        .map_err(|e| anyhow::anyhow!("security.denied_cidrs: {e}"))?;

    if config.security.idle_timeout_secs == 0 {
        warnings.push("security.idle_timeout_secs = 0; QUIC idle timeout is disabled".to_string());
    }
    if config.security.keep_alive_secs == 0 {
        warnings.push("security.keep_alive_secs = 0; QUIC keep-alive is disabled".to_string());
    }
    if config.auth.max_auth_attempts == 0 {
        warnings.push("auth.max_auth_attempts = 0; lockout is disabled".to_string());
    }
    if config.client.connect_timeout_secs == 0 {
        warnings.push(
            "client.connect_timeout_secs = 0; connections will time out immediately".to_string(),
        );
    }
    if !matches!(
        config.logging.format.trim().to_ascii_lowercase().as_str(),
        "text" | "json"
    ) {
        warnings.push(format!(
            "logging.format {:?} is not \"text\" or \"json\"; text will be used",
            config.logging.format
        ));
    }
    let level = config.logging.level.trim().to_ascii_lowercase();
    let known_level = matches!(
        level.as_str(),
        "trace" | "debug" | "info" | "warn" | "error" | "off"
    );
    if !known_level && !level.contains('=') {
        warnings.push(format!(
            "logging.level {:?} is not a known level; info will be used",
            config.logging.level
        ));
    } else if EnvFilter::try_new(&config.logging.level).is_err() {
        warnings.push(format!(
            "logging.level {:?} is not a valid filter; info will be used",
            config.logging.level
        ));
    }

    Ok(warnings)
}
