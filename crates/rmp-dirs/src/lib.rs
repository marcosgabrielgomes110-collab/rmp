//! # rmp-dirs
//!
//! Filesystem layout for RMP, following the XDG Base Directory specification for
//! user installs and the traditional FHS locations for system services.
//!
//! | Kind | User (XDG) | System (service) |
//! |---|---|---|
//! | Config (settings, known_hosts) | `~/.config/rmp` | `/etc/rmp` |
//! | Data (**secrets**: keys, hashes) | `~/.local/share/rmp` | `/var/lib/rmp` |
//! | State (logs) | `~/.local/state/rmp` | `/var/log/rmp` |
//!
//! Secrets (host key, OPAQUE setup, password file) live in the **data** directory,
//! which is created with mode `0700` and files with `0600`.

#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::path::{Path, PathBuf};

pub const CONFIG_FILE: &str = "config.toml";
pub const KNOWN_HOSTS_FILE: &str = "known_hosts";
pub const HOST_CERT_FILE: &str = "host_cert.pem";
pub const HOST_KEY_FILE: &str = "host_key.pem";
pub const OPAQUE_SETUP_FILE: &str = "opaque_setup.bin";
pub const PASSWORD_FILE: &str = "password_file.bin";
pub const PASSWORD_FILE_ROOT: &str = "password_file.root.bin";
/// Public keys authorized to log in (server side).
pub const AUTHORIZED_KEYS_FILE: &str = "authorized_keys";
/// Local device identities (client side).
pub const IDENTITIES_DIR: &str = "identities";
pub const LOG_FILE: &str = "rmp.log";
pub const AUDIT_FILE: &str = "audit.log";

/// The three directories RMP uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// Settings and client trust (`config.toml`, `known_hosts`).
    pub config_dir: PathBuf,
    /// Persistent, security-sensitive data (host key, OPAQUE setup, hashes).
    pub data_dir: PathBuf,
    /// Logs and runtime state.
    pub state_dir: PathBuf,
}

impl Layout {
    /// Per-user XDG layout (`~/.config`, `~/.local/share`, `~/.local/state`).
    pub fn user() -> Result<Self> {
        let dirs =
            ProjectDirs::from("", "", "rmp").context("could not determine XDG base directories")?;
        let data = dirs.data_dir().to_path_buf();
        Ok(Layout {
            config_dir: dirs.config_dir().to_path_buf(),
            data_dir: data.clone(),
            state_dir: dirs.state_dir().map(Path::to_path_buf).unwrap_or(data),
        })
    }

    /// System-service layout (`/etc/rmp`, `/var/lib/rmp`, `/var/log/rmp`).
    pub fn system() -> Self {
        Layout {
            config_dir: PathBuf::from("/etc/rmp"),
            data_dir: PathBuf::from("/var/lib/rmp"),
            state_dir: PathBuf::from("/var/log/rmp"),
        }
    }

    /// Put everything under a single directory (handy for tests/portable use).
    pub fn single(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        Layout {
            config_dir: dir.clone(),
            data_dir: dir.clone(),
            state_dir: dir,
        }
    }

    /// Apply individual directory overrides.
    pub fn with_overrides(
        mut self,
        config_dir: Option<PathBuf>,
        data_dir: Option<PathBuf>,
        state_dir: Option<PathBuf>,
    ) -> Self {
        if let Some(d) = config_dir {
            self.config_dir = d;
        }
        if let Some(d) = data_dir {
            self.data_dir = d;
        }
        if let Some(d) = state_dir {
            self.state_dir = d;
        }
        self
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join(CONFIG_FILE)
    }
    pub fn known_hosts_file(&self) -> PathBuf {
        self.config_dir.join(KNOWN_HOSTS_FILE)
    }
    pub fn host_cert_file(&self) -> PathBuf {
        self.data_dir.join(HOST_CERT_FILE)
    }
    pub fn host_key_file(&self) -> PathBuf {
        self.data_dir.join(HOST_KEY_FILE)
    }
    pub fn opaque_setup_file(&self) -> PathBuf {
        self.data_dir.join(OPAQUE_SETUP_FILE)
    }
    pub fn password_file(&self) -> PathBuf {
        self.data_dir.join(PASSWORD_FILE)
    }
    /// Registration record for the optional `root` account.
    pub fn root_password_file(&self) -> PathBuf {
        self.data_dir.join(PASSWORD_FILE_ROOT)
    }
    /// The `authorized_keys` file (server side).
    pub fn authorized_keys_file(&self) -> PathBuf {
        self.data_dir.join(AUTHORIZED_KEYS_FILE)
    }
    /// Directory holding this client's device identities.
    pub fn identities_dir(&self) -> PathBuf {
        self.data_dir.join(IDENTITIES_DIR)
    }
    pub fn log_file(&self) -> PathBuf {
        self.state_dir.join(LOG_FILE)
    }
    pub fn audit_file(&self) -> PathBuf {
        self.state_dir.join(AUDIT_FILE)
    }

    /// Create the configuration directory (mode `0700` on Unix).
    pub fn ensure_config(&self) -> Result<()> {
        create_private_dir(&self.config_dir)
    }

    /// Create the data directory holding secrets (mode `0700` on Unix).
    pub fn ensure_data(&self) -> Result<()> {
        create_private_dir(&self.data_dir)
    }

    /// Create the state/log directory (mode `0700` on Unix).
    pub fn ensure_state(&self) -> Result<()> {
        create_private_dir(&self.state_dir)
    }

    /// Create all three directories.
    pub fn ensure_all(&self) -> Result<()> {
        self.ensure_config()?;
        self.ensure_data()?;
        self.ensure_state()?;
        Ok(())
    }
}

/// Create a directory, restricting its permissions to the owner on Unix.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating directory {}", dir.display()))?;
    restrict_to_owner(dir)?;
    Ok(())
}

/// Set `0700` on `path` (no-op on non-Unix platforms).
#[cfg(unix)]
pub fn restrict_to_owner(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("setting 0700 on {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn restrict_to_owner(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_layout_paths_are_consistent() {
        let l = Layout::single("/tmp/rmp-x");
        assert_eq!(l.config_file(), PathBuf::from("/tmp/rmp-x/config.toml"));
        assert_eq!(l.host_key_file(), PathBuf::from("/tmp/rmp-x/host_key.pem"));
        assert_eq!(
            l.password_file(),
            PathBuf::from("/tmp/rmp-x/password_file.bin")
        );
        assert_eq!(l.audit_file(), PathBuf::from("/tmp/rmp-x/audit.log"));
    }

    #[test]
    fn system_layout_uses_fhs() {
        let l = Layout::system();
        assert_eq!(l.config_dir, PathBuf::from("/etc/rmp"));
        assert_eq!(l.data_dir, PathBuf::from("/var/lib/rmp"));
        assert_eq!(l.state_dir, PathBuf::from("/var/log/rmp"));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_creates_private_dirs() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = std::env::temp_dir().join(format!("rmp-dirs-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let l = Layout::single(&tmp);
        l.ensure_all().unwrap();
        let mode = std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "directory must be 0700");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
