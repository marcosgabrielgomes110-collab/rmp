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

    /// All `(host, fingerprint)` entries, sorted by host.
    pub fn entries(&self) -> impl Iterator<Item = (&str, Fingerprint)> + '_ {
        self.entries.iter().map(|(host, fp)| (host.as_str(), *fp))
    }

    /// Remove `host` and persist the file. Returns whether it existed.
    pub fn remove(&mut self, host: &str) -> Result<bool, CryptoError> {
        let removed = self.entries.remove(host).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
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
        write_atomic(path, out.as_bytes())?;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Write `contents` to `path` via a private temporary file and a rename.
///
/// This avoids leaving a truncated `known_hosts` behind if the process dies
/// mid-write, and never follows a symlink at the final path.
fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), CryptoError> {
    use std::io::Write;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("known_hosts");
    let tmp = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));

    let result = (|| -> Result<(), CryptoError> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);

        #[cfg(windows)]
        {
            let _ = std::fs::remove_file(path);
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
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

        let mut reloaded = KnownHosts::load(&path).unwrap();
        assert_eq!(reloaded.check("example:2222", fp), Trust::Match);
        assert_eq!(reloaded.entries().count(), 1);
        assert!(reloaded.remove("example:2222").unwrap());
        assert!(!reloaded.remove("example:2222").unwrap());
        assert!(!path.exists() || KnownHosts::load(&path).unwrap().is_empty());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "known_hosts must be private");
        }
    }
}
