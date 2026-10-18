//! `rmp serve` — run the daemon.

use crate::config::FileConfig;
use crate::logging::AUDIT_TARGET;
use anyhow::{bail, Context, Result};
use rmp_crypto::{password, HostKey};
use rmp_dirs::Layout;
use rmp_server::{net, ServerOptions};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Removes the PID file when the server exits (including on early errors).
struct PidGuard {
    path: PathBuf,
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Check whether another `rmp serve` is already using this layout/address.
///
/// The PID file catches servers started by this version. The UDP bind probe
/// also catches older instances (or unrelated processes) holding the port.
pub fn running_server(layout: &Layout, extra_listen: Option<&str>) -> Result<Option<String>> {
    let pid_path = layout.pid_file();
    if let Ok(text) = std::fs::read_to_string(&pid_path) {
        if let Ok(pid) = text.trim().parse::<u32>() {
            if process_alive(pid) {
                return Ok(Some(format!(
                    "`rmp serve` is already running (pid {pid}, pid file {})",
                    pid_path.display()
                )));
            }
        }
        // Stale PID file: the recorded process is gone.
        let _ = std::fs::remove_file(&pid_path);
    }

    let mut listens = Vec::new();
    if let Some(listen) = extra_listen {
        listens.push(listen.to_string());
    }
    // Only probe the configured address if a config exists; otherwise the
    // default (2222) could produce false positives in tests or fresh installs.
    if layout.config_file().exists() {
        if let Ok(config) = FileConfig::load(&layout.config_file()) {
            listens.push(config.server.listen);
        }
    }
    for listen in listens {
        let Ok(addr) = listen.parse::<SocketAddr>() else {
            continue;
        };
        match std::net::UdpSocket::bind(addr) {
            Ok(socket) => drop(socket),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                return Ok(Some(format!(
                    "UDP address {addr} is already in use (another `rmp serve`?)"
                )));
            }
            Err(_) => {}
        }
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
fn process_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    // No portable liveness check; be conservative and require manual cleanup.
    true
}

fn claim_pid_file(layout: &Layout) -> Result<PidGuard> {
    let path = layout.pid_file();
    std::fs::write(&path, format!("{}\n", std::process::id()))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(PidGuard { path })
}

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

    let listen = listen_override.unwrap_or_else(|| config.server.listen.clone());
    if let Some(reason) = running_server(layout, Some(&listen))? {
        bail!(
            "{reason}.\nStop the other instance first (for example `sudo systemctl stop rmp`) \
             or start this one with a different --listen address."
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
    // Re-read password files on every attempt so `rmp passwd` takes effect
    // without restarting the daemon.
    opts.password_file_path = Some(layout.password_file());
    opts.root_password_file_path = layout
        .root_password_file()
        .exists()
        .then(|| layout.root_password_file());
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
    opts.max_connections = config.server.max_connections;
    opts.allow_local_forward = config.server.allow_local_forward;
    opts.allow_remote_forward = config.server.allow_remote_forward;
    opts.allow_privileged_ports = config.server.allow_privileged_ports;
    opts.allow_file_transfer = config.server.allow_file_transfer;

    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid listen address {listen:?}"))?;

    let endpoint = rmp_server::bind(addr, &opts).with_context(|| {
        format!(
            "binding QUIC endpoint on {addr}; another `rmp serve` may already be running \
             (stop it or use --listen with a different address)"
        )
    })?;
    let _pid = claim_pid_file(layout)?;
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
    println!("  max connections  : {}", opts.max_connections);
    println!("  host fingerprint : {}", opts.host_key.fingerprint());
    println!("  config           : {}", layout.config_dir.display());
    println!("  data             : {}", layout.data_dir.display());
    println!(
        "  logs             : {}  (rmp.log + audit.log)",
        layout.state_dir.display()
    );
    println!("Press Ctrl-C (or send SIGTERM via systemd) to stop.");

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
        let reason = shutdown_signal().await;
        tracing::info!(target: AUDIT_TARGET, event = "server.stop", reason = reason);
        ep.close(0u32.into(), b"shutdown");
    });

    rmp_server::serve(endpoint, Arc::new(opts))
        .await
        .context("server error")
}

/// Wait for a graceful shutdown signal.
///
/// SIGINT and SIGTERM stop the server. SIGHUP is ignored on purpose: closing a
/// terminal/SSH session must not take a manually-started daemon down.
#[cfg(unix)]
async fn shutdown_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};

    let mut term = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
            return "signal";
        }
    };
    let mut hup = signal(SignalKind::hangup()).ok();
    let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());

    loop {
        tokio::select! {
            _ = &mut ctrl_c => return "sigint",
            _ = term.recv() => return "sigterm",
            _ = wait_hangup(&mut hup) => {
                tracing::info!("SIGHUP received; ignoring (use `systemctl restart rmp` to restart)");
            }
        }
    }
}

#[cfg(unix)]
async fn wait_hangup(hup: &mut Option<tokio::signal::unix::Signal>) {
    match hup {
        Some(signal) => {
            signal.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "ctrl_c"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_udp_address_in_use() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::single(dir.path());
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();

        assert!(
            running_server(&layout, Some(&addr.to_string()))
                .unwrap()
                .is_some(),
            "a bound UDP address must be detected"
        );
        drop(socket);
        assert!(
            running_server(&layout, Some(&addr.to_string()))
                .unwrap()
                .is_none(),
            "the address is free after the socket is dropped"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stale_pid_file_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::single(dir.path());
        layout.ensure_state().unwrap();
        std::fs::write(layout.pid_file(), "99999999\n").unwrap();

        assert!(running_server(&layout, Some("127.0.0.1:0"))
            .unwrap()
            .is_none());
        assert!(!layout.pid_file().exists());
    }
}
