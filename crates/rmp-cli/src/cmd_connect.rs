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
#[allow(clippy::too_many_arguments)]
pub async fn run(
    target: &str,
    layout: &Layout,
    accept_new_flag: bool,
    update_host_key: bool,
    fingerprint: Option<&str>,
    idle_override: Option<u64>,
    forwards: Vec<String>,
    remote_forwards: Vec<String>,
    no_shell: bool,
) -> Result<i32> {
    let _ = layout.ensure_config();
    let config = FileConfig::load_or_default(&layout.config_file())
        .with_context(|| format!("reading {}", layout.config_file().display()))?;
    let _log = crate::logging::init(layout, &config.logging).ok();

    let accept_new = accept_new_flag || config.client.accept_new_hosts;
    let idle_secs = idle_override.unwrap_or(config.client.idle_timeout_secs);
    let pinned = match fingerprint {
        Some(hex) => Some(rmp_crypto::Fingerprint::from_hex(hex).context("invalid --fingerprint")?),
        None => None,
    };

    let target = authflow::parse_target(target, DEFAULT_PORT)?;
    let key = target.key();

    let client = authflow::connect_authenticated(
        layout,
        &config,
        &target,
        accept_new,
        update_host_key,
        idle_secs,
        config.client.offer_enrollment,
        pinned,
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

/// Split a forward spec on `:` while keeping bracketed IPv6 literals intact.
fn split_colons(spec: &str) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;

    for ch in spec.chars() {
        match ch {
            '[' => {
                depth += 1;
                current.push(ch);
            }
            ']' => {
                depth -= 1;
                if depth < 0 {
                    bail!("unbalanced ']' in forward spec");
                }
                current.push(ch);
            }
            ':' if depth == 0 => parts.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    if depth != 0 {
        bail!("unbalanced '[' in forward spec");
    }
    parts.push(current);
    Ok(parts)
}

/// Remove the brackets around an IPv6 literal (`[::1]` → `::1`).
fn unbracket(value: &str) -> &str {
    value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(value)
}

fn parse_port(value: &str, what: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .with_context(|| format!("invalid {what} port"))
}

fn bind_addr(ip: &str, port: u16) -> Result<SocketAddr> {
    let text = if ip.contains(':') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    };
    text.parse()
        .with_context(|| format!("invalid forward bind address {ip}"))
}

/// Parse `[bind_address:]port:host:hostport` into a bind address and target.
///
/// IPv6 literals must be bracketed (`-L 8080:[::1]:80`).
fn parse_forward(spec: &str) -> Result<(SocketAddr, String, u16)> {
    let parts = split_colons(spec)?;
    let (bind_ip, local_port, host, host_port) = match parts.as_slice() {
        [p, h, hp] => (
            "127.0.0.1".to_string(),
            parse_port(p, "local")?,
            unbracket(h).to_string(),
            parse_port(hp, "host")?,
        ),
        [b, p, h, hp] => (
            unbracket(b).to_string(),
            parse_port(p, "local")?,
            unbracket(h).to_string(),
            parse_port(hp, "host")?,
        ),
        _ => bail!("forward spec must be [bind_address:]port:host:hostport"),
    };
    if host.is_empty() {
        bail!("forward spec is missing the target host");
    }
    let bind = bind_addr(&bind_ip, local_port)?;
    Ok((bind, host, host_port))
}

/// Parse `[bind_address:]port:host:hostport` for a remote (`-R`) forward.
///
/// The bind address is ignored: remote forwards always bind on loopback.
fn parse_remote_forward(spec: &str) -> Result<(u16, String, u16)> {
    let parts = split_colons(spec)?;
    let (bind_port, host, host_port) = match parts.as_slice() {
        [p, h, hp] => (
            parse_port(p, "bind")?,
            unbracket(h).to_string(),
            parse_port(hp, "target")?,
        ),
        [_b, p, h, hp] => (
            parse_port(p, "bind")?,
            unbracket(h).to_string(),
            parse_port(hp, "target")?,
        ),
        _ => bail!("remote forward spec must be [bind_address:]port:host:hostport"),
    };
    if host.is_empty() {
        bail!("remote forward spec is missing the target host");
    }
    Ok((bind_port, host, host_port))
}

async fn session(mut client: Client, key: &str) -> Result<i32> {
    let term_name = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let (cols, rows) = rmp_client::term::terminal_size();
    tracing::info!(target: AUDIT_TARGET, event = "session.start", host = %key, term = %term_name);
    let result = client.interactive(&term_name, cols, rows).await;
    let close_reason = client.connection().close_reason();
    match &result {
        Ok(code) => tracing::info!(
            target: AUDIT_TARGET,
            event = "session.end",
            host = %key,
            exit_code = code,
            close_reason = ?close_reason
        ),
        Err(e) => tracing::warn!(
            target: AUDIT_TARGET,
            event = "session.error",
            host = %key,
            error = %e,
            close_reason = ?close_reason
        ),
    }
    result.map(|code| code as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv6_forward_targets() {
        let (bind, host, port) = parse_forward("8080:[::1]:80").unwrap();
        assert_eq!(bind, "127.0.0.1:8080".parse().unwrap());
        assert_eq!((host.as_str(), port), ("::1", 80));

        let (bind, host, port) = parse_forward("[::1]:8080:[2001:db8::2]:443").unwrap();
        assert_eq!(bind, "[::1]:8080".parse().unwrap());
        assert_eq!((host.as_str(), port), ("2001:db8::2", 443));

        let (port, host, target) = parse_remote_forward("9090:[::1]:5432").unwrap();
        assert_eq!((port, host.as_str(), target), (9090, "::1", 5432));
    }

    #[test]
    fn rejects_malformed_forward_specs() {
        assert!(parse_forward("8080:[::1").is_err());
        assert!(parse_forward("only-one").is_err());
        assert!(parse_remote_forward("x:y:z").is_err());
    }
}
