//! `rmp connect` — connect to a server and open an interactive shell.
//!
//! Authentication order:
//!
//! 1. if a device key is stored for this host+user and key auth is enabled, try
//!    it (passwordless);
//! 2. otherwise (or on failure) fall back to the password, offering to enroll
//!    this device's key when the server allows it.

use crate::config::FileConfig;
use crate::logging::AUDIT_TARGET;
use anyhow::{bail, Context, Result};
use rmp_client::{transport, Client, ClientOptions, DeviceKey, KnownHosts, Transport, Trust};
use rmp_dirs::Layout;
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
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

/// Path of the stored device key for a host+user.
fn identity_file(layout: &Layout, host: &str, port: u16, user: &str) -> PathBuf {
    let raw = format!("{host}_{port}__{user}");
    let safe: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    layout.identities_dir().join(format!("{safe}.key"))
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
    let connect_timeout = Duration::from_secs(config.client.connect_timeout_secs);

    let target = parse_target(target)?;
    let key = format!("{}:{}", target.host, target.port);

    let addr: SocketAddr = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {}:{}", target.host, target.port))?
        .next()
        .context("no address resolved")?;

    let known_path = layout.known_hosts_file();
    let mut known = KnownHosts::load(&known_path).context("reading known_hosts")?;

    let opts = ClientOptions {
        server_addr: addr,
        server_name: target.host.clone(),
        idle_timeout: Duration::from_secs(idle_secs),
        keep_alive: Duration::from_secs(15),
        // When pinning is disabled we always connect in TOFU mode.
        expected_fingerprint: if strict { known.get(&key) } else { None },
    };

    let id_path = identity_file(layout, &target.host, target.port, &target.user);
    let device_key = if id_path.exists() {
        match DeviceKey::load(&id_path) {
            Ok(key) => Some(key),
            Err(e) => {
                eprintln!(
                    "[rmp] ignoring unreadable device key {}: {e}",
                    id_path.display()
                );
                None
            }
        }
    } else {
        None
    };

    tracing::info!(target: AUDIT_TARGET, event = "client.connect", host = %key, user = %target.user);

    // --- Attempt 1: device key (passwordless) ---------------------------------
    if let (Some(device_key), true) = (&device_key, config.client.enable_key_auth) {
        let transport =
            establish(&opts, &mut known, &key, strict, accept_new, connect_timeout).await?;
        match transport.authenticate_key(&target.user, device_key).await {
            Ok(client) => {
                tracing::info!(target: AUDIT_TARGET, event = "auth.success", host = %key,
                               user = %target.user, method = "key");
                return session(client, &key).await;
            }
            Err(e) => {
                tracing::warn!(target: AUDIT_TARGET, event = "auth.key_rejected", host = %key, error = %e);
                eprintln!("[rmp] device key rejected ({e}); falling back to password");
            }
        }
    }

    // --- Attempt 2: password, possibly enrolling a new device key -------------
    let mut new_key: Option<DeviceKey> = None;
    let mut enroll_public_key: Option<Vec<u8>> = None;
    if config.client.offer_enrollment
        && device_key.is_none()
        && confirm_default_yes("Enroll this device's key for passwordless login? [Y/n] ")?
    {
        let generated = DeviceKey::generate();
        enroll_public_key = Some(generated.public_key());
        new_key = Some(generated);
    }

    let transport = establish(&opts, &mut known, &key, strict, accept_new, connect_timeout).await?;
    let password =
        rpassword::prompt_password(format!("{}@{}'s password: ", target.user, target.host))
            .context("reading password")?;
    let client = transport
        .authenticate_password(&target.user, password.as_bytes(), enroll_public_key)
        .await
        .context("authentication failed")?;

    if client.key_enrolled() {
        if let Some(generated) = &new_key {
            generated
                .save(&id_path)
                .with_context(|| format!("saving device key {}", id_path.display()))?;
            tracing::info!(target: AUDIT_TARGET, event = "key.enrolled", host = %key,
                           user = %target.user, fingerprint = %generated.fingerprint());
            eprintln!(
                "[rmp] device key enrolled ({}); future logins will not ask for a password.",
                generated.fingerprint()
            );
        }
    } else if new_key.is_some() {
        tracing::warn!(target: AUDIT_TARGET, event = "key.enroll_rejected", host = %key);
        eprintln!("[rmp] the server did not enroll the key (enrollment disabled?).");
    }

    tracing::info!(target: AUDIT_TARGET, event = "auth.success", host = %key,
                   user = %target.user, method = "password");
    session(client, &key).await
}

/// Establish the transport and verify the server fingerprint (TOFU/pinning).
async fn establish(
    opts: &ClientOptions,
    known: &mut KnownHosts,
    key: &str,
    strict: bool,
    accept_new: bool,
    connect_timeout: Duration,
) -> Result<Transport> {
    let tp = tokio::time::timeout(connect_timeout, transport(opts))
        .await
        .context("connection timed out")?
        .context("establishing encrypted connection")?;
    let fingerprint = tp
        .observed_fingerprint()
        .context("server did not present a certificate")?;

    match known.check(key, fingerprint) {
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
            known.insert(key, fingerprint);
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
            known.insert(key, fingerprint);
            known.save().context("saving known_hosts")?;
            tracing::info!(target: AUDIT_TARGET, event = "host.trusted", host = %key, fingerprint = %fingerprint);
            eprintln!("Warning: permanently added '{key}' to the list of known hosts.");
        }
    }
    Ok(tp)
}

async fn session(client: Client, key: &str) -> Result<i32> {
    let term_name = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let (cols, rows) = rmp_client::term::terminal_size();
    tracing::info!(target: AUDIT_TARGET, event = "session.start", host = %key, term = %term_name);
    let code = client.interactive(&term_name, cols, rows).await?;
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

/// Like [`confirm`], but an empty answer means "yes".
fn confirm_default_yes(prompt: &str) -> Result<bool> {
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(!matches!(answer.as_str(), "n" | "no"))
}
