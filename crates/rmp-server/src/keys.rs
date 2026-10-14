//! Server-side store of authorized device keys (public-key authentication).
//!
//! One Ed25519 public key per line:
//!
//! ```text
//! # comments are ignored
//! <hex-public-key> <comment>
//! ```
//!
//! The file is written with mode `0600`.

use anyhow::{bail, Context, Result};
use rmp_crypto::hostkey::write_private;
use std::path::{Path, PathBuf};

/// A single authorized public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedKey {
    pub public_key: Vec<u8>,
    pub comment: String,
}

/// An in-memory view of the `authorized_keys` file.
#[derive(Debug, Default)]
pub struct AuthorizedKeys {
    path: PathBuf,
    keys: Vec<AuthorizedKey>,
}

impl AuthorizedKeys {
    /// Load the store from `path` (a missing file is an empty store).
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let mut keys = Vec::new();
        if path.exists() {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            for (i, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.splitn(2, char::is_whitespace);
                let hex_key = parts.next().unwrap_or("");
                let comment = parts.next().unwrap_or("").trim().to_string();
                match hex::decode(hex_key) {
                    Ok(pk) if pk.len() == 32 => keys.push(AuthorizedKey {
                        public_key: pk,
                        comment,
                    }),
                    _ => bail!("malformed authorized_keys entry at line {}", i + 1),
                }
            }
        }
        Ok(AuthorizedKeys { path, keys })
    }

    /// Whether `public_key` is authorized.
    pub fn contains(&self, public_key: &[u8]) -> bool {
        self.keys.iter().any(|k| k.public_key == public_key)
    }

    /// Add a key (deduplicating). Returns `true` if it was newly added.
    pub fn add(&mut self, public_key: &[u8], comment: &str) -> Result<bool> {
        if public_key.len() != 32 {
            bail!("public key must be 32 bytes");
        }
        if self.contains(public_key) {
            return Ok(false);
        }
        self.keys.push(AuthorizedKey {
            public_key: public_key.to_vec(),
            comment: comment.to_string(),
        });
        self.save()?;
        Ok(true)
    }

    /// Remove a key. Returns `true` if it existed.
    pub fn remove(&mut self, public_key: &[u8]) -> Result<bool> {
        let before = self.keys.len();
        self.keys.retain(|k| k.public_key != public_key);
        let removed = self.keys.len() != before;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    pub fn entries(&self) -> &[AuthorizedKey] {
        &self.keys
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn save(&self) -> Result<()> {
        let mut out =
            String::from("# RMP authorized_keys — one Ed25519 key per line: <hex> <comment>\n");
        for key in &self.keys {
            out.push_str(&hex::encode(&key.public_key));
            if !key.comment.is_empty() {
                out.push(' ');
                out.push_str(&key.comment);
            }
            out.push('\n');
        }
        write_private(&self.path, out.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_contains_remove_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authorized_keys");
        let pk = vec![7u8; 32];

        let mut keys = AuthorizedKeys::load(&path).unwrap();
        assert!(!keys.contains(&pk));
        assert!(keys.add(&pk, "laptop").unwrap());
        assert!(!keys.add(&pk, "again").unwrap(), "deduplicated");
        assert!(keys.contains(&pk));

        let reloaded = AuthorizedKeys::load(&path).unwrap();
        assert!(reloaded.contains(&pk));
        assert_eq!(reloaded.entries()[0].comment, "laptop");

        let mut keys = AuthorizedKeys::load(&path).unwrap();
        assert!(keys.remove(&pk).unwrap());
        assert!(!AuthorizedKeys::load(&path).unwrap().contains(&pk));
    }

    #[test]
    fn rejects_bad_length_and_malformed_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authorized_keys");
        let mut keys = AuthorizedKeys::load(&path).unwrap();
        assert!(keys.add(&[1, 2, 3], "short").is_err());

        std::fs::write(&path, "not-hex comment\n").unwrap();
        assert!(AuthorizedKeys::load(&path).is_err());
    }
}
