//! `rmp serve` — run the daemon.

use crate::config::FileConfig;
use crate::logging::AUDIT_TARGET;
use anyhow::{bail, Context, Result};
use rmp_crypto::{password, HostKey};
use rmp_dirs::Layout;
use rmp_server::{net, ServerOptions};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Load state and run the server until Ctrl-C.
pub async fn run(layout: &Layout, listen_override: Option<String>) -> Result<()> {
    layout.ensure_all()?;

    let config = FileConfig::load_or_default(&layout.config_file());
    let config = match config {
        Ok(c) => c,
        Err(e) => bail!("invalid config {}: {e}", layout.config_file().display()),
    };

    // Keep the guard alive for the whole server lifetime.
    let _log = crate::logging::init(layout, &config.logging)?;

    if !config.server.enabled {
        bail!(
            "server.enabled = false in {}; refusing to start",
            layout.config_file().display()
        );
    }

    let host_key = HostKey::load(&layout.data_dir).context("loading host key")?;
    let setup_bytes = std::fs::read(layout.opaque_setup_file()).context("reading OPAQUE setup")?;
    let setup = password::setup_from_bytes(&setup_bytes).context("parsing OPAQUE setup")?;
    let password_file =
        password::PasswordFile::load(&layout.password_file()).context("reading password file")?;

    let root_password_file = if layout.root_password_file().exists() {
        Some(
            password::PasswordFile::load(&layout.root_password_file())
                .context("reading root password file")?,
        )
    } else {
        None
    };

    let allowed = net::parse_list(&config.security.allowed_cidrs)
        .map_err(|e| anyhow::anyhow!("security.allowed_cidrs: {e}"))?;
    let denied = net::parse_list(&config.security.denied_cidrs)
        .map_err(|e| anyhow::anyhow!("security.denied_cidrs: {e}"))?;

    let mut opts = ServerOptions::new(
        config.server.username.clone(),
        host_key,
        setup,
        password_file,
    );
    opts.root_password_file = root_password_file;
    opts.allow_root = config.auth.allow_root;
    opts.password_enabled = config.auth.password_enabled;
    opts.allow_key_auth = config.auth.allow_key_auth;
    opts.allow_key_enrollment = config.auth.allow_key_enrollment;
    opts.authorized_keys_path = layout.authorized_keys_file();
    opts.max_auth_attempts = config.auth.max_auth_attempts;
    opts.lockout = Duration::from_secs(config.auth.lockout_secs);
    opts.idle_timeout = Duration::from_secs(config.security.idle_timeout_secs);
    opts.keep_alive = Duration::from_secs(config.security.keep_alive_secs);
    opts.shell = if config.server.shell.is_empty() {
        None
    } else {
        Some(config.server.shell.clone())
    };
    opts.motd = if config.server.motd.is_empty() {
        None
    } else {
        Some(config.server.motd.clone())
    };
    opts.allowed_cidrs = allowed;
    opts.denied_cidrs = denied;
    opts.log_commands = config.logging.log_commands;
    opts.max_sessions = config.server.max_sessions;
    opts.allow_local_forward = config.server.allow_local_forward;
    opts.allow_remote_forward = config.server.allow_remote_forward;

    let listen = listen_override.unwrap_or(config.server.listen.clone());
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid listen address {listen:?}"))?;

    let endpoint = rmp_server::bind(addr, &opts).context("binding QUIC endpoint")?;
    let bound = endpoint.local_addr()?;

    println!("RMP server listening on {bound}");
    println!("  user             : {}", config.server.username);
    println!(
        "  root login       : {}",
        if opts.allow_root {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "  password auth    : {}",
        if opts.password_enabled {
            "enabled"
        } else {
            "DISABLED"
        }
    );
    println!(
        "  key auth         : {}",
        if opts.allow_key_auth {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!(
        "  key enrollment   : {}",
        if opts.allow_key_enrollment {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("  host fingerprint : {}", opts.host_key.fingerprint());
    println!("  config           : {}", layout.config_dir.display());
    println!("  data             : {}", layout.data_dir.display());
    println!(
        "  logs             : {}  (rmp.log + audit.log)",
        layout.state_dir.display()
    );
    println!("Press Ctrl-C to stop.");

    tracing::info!(
        target: AUDIT_TARGET,
        event = "server.start",
        addr = %bound,
        user = %config.server.username,
        allow_root = opts.allow_root,
        password_enabled = opts.password_enabled,
        fingerprint = %opts.host_key.fingerprint()
    );

    let ep = endpoint.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!(target: AUDIT_TARGET, event = "server.stop", reason = "signal");
            ep.close(0u32.into(), b"shutdown");
        }
    });

    rmp_server::serve(endpoint, Arc::new(opts))
        .await
        .context("server error")
}
