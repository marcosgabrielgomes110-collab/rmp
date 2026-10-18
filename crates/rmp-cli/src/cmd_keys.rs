//! `rmp keys` — inspect and revoke server-side device keys.
//!
//! `authorized_keys` is global to the single configured account. The running
//! server reloads it on every login, so a revocation takes effect immediately.

use crate::config::FileConfig;
use anyhow::{bail, Result};
use clap::Subcommand;
use rmp_crypto::Fingerprint;
use rmp_dirs::Layout;
use rmp_server::AuthorizedKeys;

#[derive(Subcommand)]
pub enum Action {
    /// List authorized device keys (fingerprint, comment, public key).
    List,
    /// Revoke a key by fingerprint or public-key hex.
    Revoke {
        /// SHA-256 fingerprint or the 32-byte public key in hex.
        key: String,
    },
}

/// Run a `keys` action.
pub fn run(layout: &Layout, action: Action) -> Result<()> {
    let path = layout.authorized_keys_file();
    let config = FileConfig::load_or_default(&layout.config_file()).unwrap_or_default();
    let keys = AuthorizedKeys::load(&path)?;

    match action {
        Action::List => list(&path, &config, &keys),
        Action::Revoke { key } => revoke(&path, &config, keys, &key),
    }
}

fn list(path: &std::path::Path, config: &FileConfig, keys: &AuthorizedKeys) -> Result<()> {
    println!("# {} (account: {})", path.display(), config.server.username);
    if keys.entries().is_empty() {
        println!("(no authorized keys)");
        return Ok(());
    }
    for (index, key) in keys.entries().iter().enumerate() {
        let fingerprint = Fingerprint::of_bytes(&key.public_key);
        println!(
            "{index}\t{fingerprint}\t{}\t{}",
            if key.comment.is_empty() {
                "-"
            } else {
                &key.comment
            },
            hex::encode(&key.public_key)
        );
    }
    Ok(())
}

fn revoke(
    path: &std::path::Path,
    config: &FileConfig,
    mut keys: AuthorizedKeys,
    selector: &str,
) -> Result<()> {
    let compact = compact_hex(selector)?;
    let fingerprint = Fingerprint::from_hex(&compact).ok();

    let target = fingerprint
        .and_then(|wanted| {
            keys.entries()
                .iter()
                .find(|key| Fingerprint::of_bytes(&key.public_key) == wanted)
                .map(|key| key.public_key.clone())
        })
        .or_else(|| {
            // A 64-hex selector may also be the public key itself. Try that
            // only when no fingerprint matched.
            hex::decode(&compact).ok().filter(|public_key| {
                keys.entries()
                    .iter()
                    .any(|key| key.public_key == *public_key)
            })
        });

    let Some(public_key) = target else {
        bail!(
            "no authorized key matches '{selector}' in {} (run `rmp keys list`)",
            path.display()
        );
    };

    if keys.entries().len() == 1 && !config.auth.password_enabled {
        bail!(
            "refusing to revoke the last key: password authentication is disabled \
             and this would lock out every client"
        );
    }

    let comment = keys
        .entries()
        .iter()
        .find(|key| key.public_key == public_key)
        .map(|key| key.comment.clone())
        .unwrap_or_default();
    let fingerprint = Fingerprint::of_bytes(&public_key);
    if !keys.remove(&public_key)? {
        bail!("key vanished while revoking {fingerprint}");
    }

    println!(
        "revoked {fingerprint}{}",
        if comment.is_empty() {
            String::new()
        } else {
            format!(" ({comment})")
        }
    );
    println!("The running server picks this up on the next login.");
    Ok(())
}

/// Normalize a 64-hex fingerprint/public key, accepting colon separators.
fn compact_hex(raw: &str) -> Result<String> {
    let mut out = String::with_capacity(64);
    for character in raw.chars() {
        if character.is_ascii_hexdigit() {
            out.push(character.to_ascii_lowercase());
        } else if character == ':' || character == '-' || character.is_ascii_whitespace() {
            continue;
        } else {
            bail!("invalid key/fingerprint {raw:?}");
        }
    }
    if out.len() != 64 {
        bail!(
            "expected a 64-hex fingerprint or public key, got {} hex digits",
            out.len()
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_and_colon_separated_hex() {
        let hex = "38ddfc5a0ee38ef5575908919005b8fb592f87692472b546dc35d08b16143e3f";
        let pretty = "38:dd:fc:5a:0e:e3:8e:f5:57:59:08:91:90:05:b8:fb:\
                      59:2f:87:69:24:72:b5:46:dc:35:d0:8b:16:14:3e:3f";
        assert_eq!(compact_hex(hex).unwrap(), hex);
        assert_eq!(compact_hex(pretty).unwrap(), hex);
        assert!(compact_hex("zz").is_err());
        assert!(compact_hex("00:11").is_err());
    }

    #[test]
    fn revoke_rejects_unknown_key() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::single(dir.path());
        layout.ensure_data().unwrap();
        let path = layout.authorized_keys_file();
        let key = [7u8; 32];
        let mut keys = AuthorizedKeys::load(&path).unwrap();
        keys.add(&key, "test@host").unwrap();

        let config = FileConfig::default();
        let err = revoke(
            &path,
            &config,
            AuthorizedKeys::load(&path).unwrap(),
            &"00".repeat(32),
        )
        .unwrap_err();
        assert!(err.to_string().contains("no authorized key matches"));

        revoke(
            &path,
            &config,
            AuthorizedKeys::load(&path).unwrap(),
            &hex::encode(key),
        )
        .unwrap();
        assert!(AuthorizedKeys::load(&path).unwrap().entries().is_empty());
    }
}
