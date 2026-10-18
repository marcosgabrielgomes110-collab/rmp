//! `rmp known-hosts` — inspect or edit the TOFU trust store.

use anyhow::{bail, Context, Result};
use rmp_client::KnownHosts;
use rmp_dirs::Layout;

/// Print every known host and its SHA-256 fingerprint.
pub fn list(layout: &Layout) -> Result<()> {
    let path = layout.known_hosts_file();
    let known = KnownHosts::load(&path).with_context(|| format!("reading {}", path.display()))?;

    let mut count = 0usize;
    for (host, fingerprint) in known.entries() {
        println!("{host} {}", fingerprint.to_hex());
        count += 1;
    }
    if count == 0 {
        println!("(no known hosts)");
    }
    Ok(())
}

/// Remove `host` from the trust store.
pub fn remove(layout: &Layout, host: &str) -> Result<()> {
    let path = layout.known_hosts_file();
    let mut known =
        KnownHosts::load(&path).with_context(|| format!("reading {}", path.display()))?;
    if known.remove(host)? {
        println!("removed {host}");
        Ok(())
    } else {
        bail!("host '{host}' is not in {}", path.display())
    }
}
