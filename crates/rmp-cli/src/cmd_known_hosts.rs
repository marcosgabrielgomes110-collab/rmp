//! `rmp known-hosts` — inspect and edit the client trust store.
//!
//! The file is normally updated automatically by TOFU/`--update-host-key`;
//! these commands are for auditing, scripting and deliberate recovery.

use crate::authflow::DEFAULT_PORT;
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use rmp_crypto::{Fingerprint, KnownHosts};
use rmp_dirs::Layout;

#[derive(Subcommand)]
pub enum Action {
    /// List recorded hosts and fingerprints.
    List,
    /// Remove a host from the trust store.
    Remove {
        /// Host (and optional port), e.g. host, host:2222, [::1]:2222.
        host: String,
    },
    /// Add or replace the fingerprint recorded for a host.
    Update {
        /// Host (and optional port), e.g. host, host:2222, [::1]:2222.
        host: String,
        /// SHA-256 fingerprint in hex (colons/spaces are ignored).
        fingerprint: String,
    },
}

/// Run a `known-hosts` action.
pub fn run(layout: &Layout, action: Action) -> Result<()> {
    let path = layout.known_hosts_file();
    match action {
        Action::List => list(&path),
        Action::Remove { host } => remove(&path, &host),
        Action::Update { host, fingerprint } => update(&path, &host, &fingerprint),
    }
}

fn list(path: &std::path::Path) -> Result<()> {
    let known = KnownHosts::load(path)?;
    println!("# {}", path.display());
    if known.is_empty() {
        println!("(empty)");
        return Ok(());
    }
    for (host, fingerprint) in known.entries() {
        println!("{host} {}", fingerprint.to_hex());
    }
    Ok(())
}

fn remove(path: &std::path::Path, host: &str) -> Result<()> {
    let key = normalize_host(host)?;
    let mut known = KnownHosts::load(path)?;
    if !known.remove(&key) {
        bail!("host '{key}' not found in {}", path.display());
    }
    known.save()?;
    println!("removed {key}");
    Ok(())
}

fn update(path: &std::path::Path, host: &str, fingerprint: &str) -> Result<()> {
    let key = normalize_host(host)?;
    let fingerprint = parse_fingerprint(fingerprint)?;
    let mut known = KnownHosts::load(path)?;
    let existed = known.get(&key).is_some();
    known.insert(&key, fingerprint);
    known.save()?;
    println!(
        "{} {key} ({fingerprint})",
        if existed { "updated" } else { "added" }
    );
    Ok(())
}

/// Normalize a user-supplied host into the `known_hosts` key format.
///
/// Accepts `host`, `host:port`, `user@host`, bracketed IPv6 and bare IPv6.
/// The default port is 2222, matching `rmp connect`.
fn normalize_host(raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("empty host");
    }
    let host = raw.rsplit_once('@').map(|(_, host)| host).unwrap_or(raw);

    if let Some(after) = host.strip_prefix('[') {
        let end = after
            .find(']')
            .context("invalid IPv6 address (missing ']')")?;
        let address = &after[..end];
        let tail = &after[end + 1..];
        if address.is_empty() {
            bail!("empty IPv6 address");
        }
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse::<u16>().context("invalid port")?,
            None if tail.is_empty() => DEFAULT_PORT,
            None => bail!("unexpected characters after IPv6 address"),
        };
        return Ok(format!("[{address}]:{port}"));
    }

    match host.matches(':').count() {
        0 => Ok(format!("{host}:{DEFAULT_PORT}")),
        1 => {
            let (address, port) = host.rsplit_once(':').expect("one colon");
            let port = port.parse::<u16>().context("invalid port")?;
            if address.is_empty() {
                bail!("empty host");
            }
            Ok(format!("{address}:{port}"))
        }
        // Bare IPv6 (multiple colons) cannot carry an unambiguous port.
        _ => Ok(format!("[{host}]:{DEFAULT_PORT}")),
    }
}

fn parse_fingerprint(raw: &str) -> Result<Fingerprint> {
    let hex: String = raw
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '-')
        .collect();
    Fingerprint::from_hex(&hex).map_err(|e| anyhow::anyhow!("invalid fingerprint {raw:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_hosts_and_ports() {
        assert_eq!(normalize_host("example.com").unwrap(), "example.com:2222");
        assert_eq!(
            normalize_host("example.com:3333").unwrap(),
            "example.com:3333"
        );
        assert_eq!(
            normalize_host("user@example.com").unwrap(),
            "example.com:2222"
        );
        assert_eq!(normalize_host("[::1]").unwrap(), "[::1]:2222");
        assert_eq!(normalize_host("[::1]:3333").unwrap(), "[::1]:3333");
        assert_eq!(normalize_host("::1").unwrap(), "[::1]:2222");
        assert!(normalize_host("host:not-a-port").is_err());
        assert!(normalize_host("[::1").is_err());
    }

    #[test]
    fn parses_colon_separated_fingerprints() {
        let hex = "38ddfc5a0ee38ef5575908919005b8fb592f87692472b546dc35d08b16143e3f";
        let pretty = "38:dd:fc:5a:0e:e3:8e:f5:57:59:08:91:90:05:b8:fb:\
                      59:2f:87:69:24:72:b5:46:dc:35:d0:8b:16:14:3e:3f";
        assert_eq!(
            parse_fingerprint(hex).unwrap(),
            parse_fingerprint(pretty).unwrap()
        );
        assert!(parse_fingerprint("not-a-fingerprint").is_err());
    }
}
