//! `rmp connect` — connect to a server and open an interactive shell.

use crate::config::FileConfig;
use crate::logging::AUDIT_TARGET;
use anyhow::{bail, Context, Result};
use rmp_client::{transport, Client, ClientOptions, KnownHosts, Trust};
use rmp_dirs::Layout;
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

/// A parsed `user@host[:port]` target.
struct Target {
    user: String,
    host: String,
    port: u16,
}

const DEFAULT_PORT: u16 = 2222;

fn parse_target(raw: &str) -> Result<Target> {
    let (user, rest) = raw
        .split_once('@')
        .context("target must be of the form user@host[:port]")?;
    if user.is_empty() {
        bail!("missing user in target");
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().context("invalid port")?),
        None => (rest.to_string(), DEFAULT_PORT),
    };
    if host.is_empty() {
        bail!("missing host in target");
    }
    Ok(Target {
        user: user.to_string(),
        host,
        port,
    })
}

/// Connect, verify the host key, authenticate and run a shell.
pub async fn run(
    target: &str,
    layout: &Layout,
    accept_new_flag: bool,
    idle_override: Option<u64>,
) -> Result<i32> {
    let _ = layout.ensure_config();
    let config = FileConfig::load_or_default(&layout.config_file()).unwrap_or_default();
    let _log = crate::logging::init(layout, &config.logging).ok();

    let accept_new = accept_new_flag || config.client.accept_new_hosts;
    let strict = config.client.strict_host_key;
    if !strict {
        tracing::warn!("client.strict_host_key = false: host key pinning is DISABLED");
    }
    let idle_secs = idle_override.unwrap_or(config.client.idle_timeout_secs);

    let target = parse_target(target)?;
    let key = format!("{}:{}", target.host, target.port);

    let addr: SocketAddr = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {}:{}", target.host, target.port))?
        .next()
        .context("no address resolved")?;

    let known_path = layout.known_hosts_file();
    let mut known = KnownHosts::load(&known_path).context("reading known_hosts")?;
    // When pinning is disabled we always connect in TOFU mode.
    let expected = if strict { known.get(&key) } else { None };

    let opts = ClientOptions {
        server_addr: addr,
        server_name: target.host.clone(),
        idle_timeout: Duration::from_secs(idle_secs),
        keep_alive: Duration::from_secs(15),
        expected_fingerprint: expected,
    };

    tracing::info!(target: AUDIT_TARGET, event = "client.connect", host = %key, user = %target.user);

    // Establish the transport *before* asking for the password.
    let (endpoint, conn, observed) = tokio::time::timeout(
        Duration::from_secs(config.client.connect_timeout_secs),
        transport(&opts),
    )
    .await
    .context("connection timed out")?
    .context("establishing encrypted connection")?;
    let fingerprint = observed
        .get()
        .context("server did not present a certificate")?;

    match known.check(&key, fingerprint) {
        Trust::Match => {
            tracing::info!(target: AUDIT_TARGET, event = "host.known", host = %key, fingerprint = %fingerprint);
        }
        Trust::Mismatch { expected } if strict => {
            tracing::warn!(target: AUDIT_TARGET, event = "host.mismatch", host = %key,
                expected = %expected, received = %fingerprint);
            bail!(
                "HOST KEY MISMATCH for {key}!\n  expected: {expected}\n  received: {fingerprint}\n\
                 This may indicate a man-in-the-middle attack. Connection aborted."
            );
        }
        Trust::Mismatch { .. } => {
            tracing::warn!(target: AUDIT_TARGET, event = "host.mismatch_ignored", host = %key);
            eprintln!("WARNING: host key changed for {key} and strict_host_key is disabled.");
            known.insert(&key, fingerprint);
            known.save().context("saving known_hosts")?;
        }
        Trust::Unknown => {
            eprintln!("The authenticity of host '{key}' can't be established.");
            eprintln!("Ed25519 fingerprint is {fingerprint}.");
            let accepted = accept_new || confirm("Continue connecting (yes/no)? ")?;
            if !accepted {
                tracing::warn!(target: AUDIT_TARGET, event = "host.rejected", host = %key);
                bail!("connection aborted by user");
            }
            known.insert(&key, fingerprint);
            known.save().context("saving known_hosts")?;
            tracing::info!(target: AUDIT_TARGET, event = "host.trusted", host = %key, fingerprint = %fingerprint);
            eprintln!("Warning: permanently added '{key}' to the list of known hosts.");
        }
    }

    let password =
        rpassword::prompt_password(format!("{}@{}'s password: ", target.user, target.host))
            .context("reading password")?;

    let client = Client::authenticate(endpoint, conn, observed, &target.user, password.as_bytes())
        .await
        .context("authentication failed")?;
    tracing::info!(target: AUDIT_TARGET, event = "auth.success", host = %key, user = %target.user);

    let term_name = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let (cols, rows) = rmp_client::term::terminal_size();
    tracing::info!(target: AUDIT_TARGET, event = "session.start", host = %key, term = %term_name);
    let code = client
        .interactive(&term_name, cols, rows)
        .await
        .context("session error")?;
    tracing::info!(target: AUDIT_TARGET, event = "session.end", host = %key, exit_code = code);
    Ok(code as i32)
}

fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "yes" || answer == "y")
}
