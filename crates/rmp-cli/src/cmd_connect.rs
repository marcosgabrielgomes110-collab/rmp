//! `rmp connect` — connect, authenticate and open an interactive shell,
//! optionally with port forwards (`-L`/`-R`) and/or `-N` (forward only).

use crate::authflow::{self, DEFAULT_PORT};
use crate::config::FileConfig;
use crate::logging::AUDIT_TARGET;
use anyhow::{bail, Context, Result};
use rmp_client::Client;
use rmp_dirs::Layout;
use std::net::SocketAddr;

/// Connect, verify the host key, authenticate and run a shell.
pub async fn run(
    target: &str,
    layout: &Layout,
    accept_new_flag: bool,
    idle_override: Option<u64>,
    forwards: Vec<String>,
    remote_forwards: Vec<String>,
    no_shell: bool,
) -> Result<i32> {
    let _ = layout.ensure_config();
    let config = FileConfig::load_or_default(&layout.config_file()).unwrap_or_default();
    let _log = crate::logging::init(layout, &config.logging).ok();

    let accept_new = accept_new_flag || config.client.accept_new_hosts;
    let idle_secs = idle_override.unwrap_or(config.client.idle_timeout_secs);

    let target = authflow::parse_target(target, DEFAULT_PORT)?;
    let key = target.key();

    let client = authflow::connect_authenticated(
        layout,
        &config,
        &target,
        accept_new,
        idle_secs,
        config.client.offer_enrollment,
    )
    .await?;

    finish(client, &key, &forwards, &remote_forwards, no_shell).await
}

/// Start forwards and either run a shell or just keep forwarding.
async fn finish(
    mut client: Client,
    key: &str,
    forwards: &[String],
    remote_forwards: &[String],
    no_shell: bool,
) -> Result<i32> {
    if !forwards.is_empty() {
        let conn = client.connection().clone();
        for spec in forwards {
            let (bind, host, port) = parse_forward(spec)?;
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .with_context(|| format!("binding local forward {bind}"))?;
            let actual = listener.local_addr().unwrap_or(bind);
            eprintln!("[rmp] forwarding {actual} -> {host}:{port}");
            let conn = conn.clone();
            tracing::info!(target: AUDIT_TARGET, event = "forward.start", bind = %actual,
                           target = %format!("{host}:{port}"));
            tokio::spawn(async move {
                if let Err(e) = rmp_client::local_forward(conn, listener, host, port).await {
                    eprintln!("[rmp] forward {actual} failed: {e}");
                }
            });
        }
    }

    if !remote_forwards.is_empty() {
        let conn = client.connection().clone();
        tokio::spawn(async move {
            let _ = rmp_client::remote_forward_accept(conn).await;
        });
        for spec in remote_forwards {
            let (bind_port, host, port) = parse_remote_forward(spec)?;
            let bound = client
                .request_remote_forward(bind_port, &host, port)
                .await?;
            eprintln!("[rmp] remote forward 127.0.0.1:{bound} (server) -> {host}:{port}");
            tracing::info!(target: AUDIT_TARGET, event = "remote_forward.start", bind = bound,
                           target = %format!("{host}:{port}"));
        }
    }

    if no_shell {
        eprintln!("[rmp] forwarding only; press Ctrl-C to stop.");
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!(target: AUDIT_TARGET, event = "session.end", host = %key, exit_code = 0);
        return Ok(0);
    }
    session(client, key).await
}

/// Parse `[bind_address:]port:host:hostport` into a bind address and target.
fn parse_forward(spec: &str) -> Result<(SocketAddr, String, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (bind_ip, local_port, host, host_port) = match parts.as_slice() {
        [p, h, hp] => (
            "127.0.0.1".to_string(),
            p.parse::<u16>().context("invalid local port")?,
            h.to_string(),
            hp.parse::<u16>().context("invalid host port")?,
        ),
        [b, p, h, hp] => (
            b.to_string(),
            p.parse::<u16>().context("invalid local port")?,
            h.to_string(),
            hp.parse::<u16>().context("invalid host port")?,
        ),
        _ => bail!("forward spec must be [bind_address:]port:host:hostport"),
    };
    if host.is_empty() {
        bail!("forward spec is missing the target host");
    }
    let bind: SocketAddr = format!("{bind_ip}:{local_port}")
        .parse()
        .context("invalid forward bind address")?;
    Ok((bind, host, host_port))
}

/// Parse `[bind_address:]port:host:hostport` for a remote (`-R`) forward.
fn parse_remote_forward(spec: &str) -> Result<(u16, String, u16)> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (bind_port, host, host_port) = match parts.as_slice() {
        [p, h, hp] => (
            p.parse::<u16>().context("invalid bind port")?,
            h.to_string(),
            hp.parse::<u16>().context("invalid target port")?,
        ),
        [_b, p, h, hp] => (
            p.parse::<u16>().context("invalid bind port")?,
            h.to_string(),
            hp.parse::<u16>().context("invalid target port")?,
        ),
        _ => bail!("remote forward spec must be [bind_address:]port:host:hostport"),
    };
    if host.is_empty() {
        bail!("remote forward spec is missing the target host");
    }
    Ok((bind_port, host, host_port))
}

async fn session(client: Client, key: &str) -> Result<i32> {
    let term_name = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let (cols, rows) = rmp_client::term::terminal_size();
    tracing::info!(target: AUDIT_TARGET, event = "session.start", host = %key, term = %term_name);
    let code = client.interactive(&term_name, cols, rows).await?;
    tracing::info!(target: AUDIT_TARGET, event = "session.end", host = %key, exit_code = code);
    Ok(code as i32)
}
