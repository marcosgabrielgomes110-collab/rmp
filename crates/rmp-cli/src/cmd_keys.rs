//! `rmp keys` — inspect or revoke device keys enrolled on this server.

use anyhow::{Context, Result};
use rmp_crypto::Fingerprint;
use rmp_dirs::Layout;
use rmp_server::AuthorizedKeys;

/// Print the fingerprint and comment of every authorized device key.
pub fn list(layout: &Layout) -> Result<()> {
    let path = layout.authorized_keys_file();
    let keys =
        AuthorizedKeys::load(&path).with_context(|| format!("reading {}", path.display()))?;

    if keys.entries().is_empty() {
        println!("(no authorized device keys)");
        return Ok(());
    }
    for key in keys.entries() {
        println!(
            "{} {}",
            Fingerprint::of_bytes(&key.public_key).to_hex(),
            key.comment
        );
    }
    Ok(())
}

/// Revoke the key whose SHA-256 fingerprint matches `fingerprint`.
pub fn revoke(layout: &Layout, fingerprint: &str) -> Result<()> {
    let wanted = Fingerprint::from_hex(fingerprint).context("invalid fingerprint")?;
    let path = layout.authorized_keys_file();
    let mut keys =
        AuthorizedKeys::load(&path).with_context(|| format!("reading {}", path.display()))?;

    let key = keys
        .entries()
        .iter()
        .find(|key| Fingerprint::of_bytes(&key.public_key) == wanted)
        .cloned()
        .with_context(|| format!("no authorized key with fingerprint {fingerprint}"))?;

    keys.remove(&key.public_key)?;
    println!(
        "revoked {} {}",
        wanted.to_hex(),
        if key.comment.is_empty() {
            "(no comment)"
        } else {
            &key.comment
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_removes_only_the_requested_key() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::single(dir.path());
        let path = layout.authorized_keys_file();
        let mut keys = AuthorizedKeys::load(&path).unwrap();
        keys.add(&[1u8; 32], "laptop").unwrap();
        keys.add(&[2u8; 32], "desktop").unwrap();

        let fp = Fingerprint::of_bytes(&[1u8; 32]).to_hex();
        revoke(&layout, &fp).unwrap();

        let keys = AuthorizedKeys::load(&path).unwrap();
        assert_eq!(keys.entries().len(), 1);
        assert_eq!(keys.entries()[0].public_key, vec![2u8; 32]);
    }

    #[test]
    fn unknown_fingerprint_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::single(dir.path());
        let fp = Fingerprint::of_bytes(&[9u8; 32]).to_hex();
        assert!(revoke(&layout, &fp).is_err());
    }
}
