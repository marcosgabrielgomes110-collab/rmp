//! Trust-on-first-use storage of server fingerprints.
//!
//! The file format is a line per host:
//!
//! ```text
//! # comments are ignored
//! host:port <hex-sha256>
//! ```

use crate::error::CryptoError;
use crate::hostkey::Fingerprint;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Outcome of comparing a presented fingerprint with the known-hosts store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// The host is known and the fingerprint matches.
    Match,
    /// The host is known and the fingerprint **differs** — possible MITM.
    Mismatch { expected: Fingerprint },
    /// The host was not seen before (trust-on-first-use).
    Unknown,
}

/// A parsed `known_hosts` file.
#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    entries: BTreeMap<String, Fingerprint>,
    path: Option<PathBuf>,
}

impl KnownHosts {
    /// Load the store from `path`. A missing file is treated as empty.
    pub fn load(path: &Path) -> Result<Self, CryptoError> {
        let mut entries = BTreeMap::new();
        if path.exists() {
            let contents = std::fs::read_to_string(path)?;
            for (lineno, line) in contents.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let (Some(host), Some(hex)) = (parts.next(), parts.next()) else {
                    return Err(CryptoError::Rcgen(format!(
                        "malformed known_hosts entry at line {}",
                        lineno + 1
                    )));
                };
                let fp = Fingerprint::from_hex(hex)?;
                entries.insert(host.to_string(), fp);
            }
        }
        Ok(KnownHosts {
            entries,
            path: Some(path.to_path_buf()),
        })
    }

    /// An in-memory store (useful for tests).
    pub fn in_memory() -> Self {
        KnownHosts::default()
    }

    /// The fingerprint recorded for `host`, if any.
    pub fn get(&self, host: &str) -> Option<Fingerprint> {
        self.entries.get(host).copied()
    }

    /// The file backing this store, when loaded from disk.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Compare a presented fingerprint against the store.
    pub fn check(&self, host: &str, presented: Fingerprint) -> Trust {
        match self.entries.get(host) {
            Some(existing) if *existing == presented => Trust::Match,
            Some(existing) => Trust::Mismatch {
                expected: *existing,
            },
            None => Trust::Unknown,
        }
    }

    /// Record (or update) a fingerprint for `host`.
    pub fn insert(&mut self, host: &str, fingerprint: Fingerprint) {
        self.entries.insert(host.to_string(), fingerprint);
    }

    /// Persist the store back to disk.
    pub fn save(&self) -> Result<(), CryptoError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = String::from("# RMP known hosts — do not edit while the client runs\n");
        for (host, fp) in &self.entries {
            out.push_str(host);
            out.push(' ');
            out.push_str(&fp.to_hex());
            out.push('\n');
        }
        std::fs::write(path, out.as_bytes())?;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostkey::HostKey;

    #[test]
    fn trust_decisions() {
        let fp_a = HostKey::generate().unwrap().fingerprint();
        let fp_b = HostKey::generate().unwrap().fingerprint();
        let mut kh = KnownHosts::in_memory();

        assert_eq!(kh.check("h", fp_a), Trust::Unknown);
        kh.insert("h", fp_a);
        assert_eq!(kh.check("h", fp_a), Trust::Match);
        assert_eq!(kh.check("h", fp_b), Trust::Mismatch { expected: fp_a });
        assert_eq!(kh.check("other", fp_a), Trust::Unknown);
    }

    #[test]
    fn file_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let fp = HostKey::generate().unwrap().fingerprint();

        let mut kh = KnownHosts::load(&path).unwrap();
        assert!(kh.is_empty());
        kh.insert("example:2222", fp);
        kh.save().unwrap();

        let reloaded = KnownHosts::load(&path).unwrap();
        assert_eq!(reloaded.check("example:2222", fp), Trust::Match);
    }
}
