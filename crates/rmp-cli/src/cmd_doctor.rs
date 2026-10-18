//! `rmp doctor` — check config and on-disk state for common problems.

use crate::config::FileConfig;
use anyhow::{bail, Context, Result};
use rmp_dirs::Layout;
use std::path::Path;

/// Validate the configuration and the files/directories the server relies on.
pub fn run(layout: &Layout) -> Result<()> {
    let mut warnings = crate::cmd_config::validate(layout)?;
    let mut errors = Vec::new();

    check_dir("config", &layout.config_dir, &mut warnings, &mut errors);
    check_dir("data", &layout.data_dir, &mut warnings, &mut errors);
    check_dir("state", &layout.state_dir, &mut warnings, &mut errors);

    check_private_file(
        "host key",
        &layout.host_key_file(),
        true,
        &mut warnings,
        &mut errors,
    );
    check_private_file(
        "OPAQUE setup",
        &layout.opaque_setup_file(),
        true,
        &mut warnings,
        &mut errors,
    );
    check_private_file(
        "password file",
        &layout.password_file(),
        true,
        &mut warnings,
        &mut errors,
    );
    check_private_file(
        "authorized_keys",
        &layout.authorized_keys_file(),
        false,
        &mut warnings,
        &mut errors,
    );
    check_private_file(
        "known_hosts",
        &layout.known_hosts_file(),
        false,
        &mut warnings,
        &mut errors,
    );

    let config = FileConfig::load_or_default(&layout.config_file())
        .with_context(|| format!("reading {}", layout.config_file().display()))?;
    if config.auth.allow_root && !command_available("runuser") {
        errors.push(
            "auth.allow_root = true but `runuser` is not available; \
             the server will refuse to start"
                .to_string(),
        );
    }
    if config.auth.allow_root && !is_root() {
        warnings.push(
            "auth.allow_root = true but this process is not root; \
             `rmp serve` will refuse to start"
                .to_string(),
        );
    }

    for warning in &warnings {
        eprintln!("[rmp] warning: {warning}");
    }
    for error in &errors {
        eprintln!("[rmp] error: {error}");
    }
    if errors.is_empty() {
        println!(
            "doctor: OK ({} warning(s)): {}",
            warnings.len(),
            layout.data_dir.display()
        );
        Ok(())
    } else {
        bail!("doctor found {} error(s)", errors.len());
    }
}

fn check_dir(label: &str, path: &Path, warnings: &mut Vec<String>, errors: &mut Vec<String>) {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o700 {
                    warnings.push(format!(
                        "{label} directory {} has mode {mode:o}, expected 700",
                        path.display()
                    ));
                }
            }
        }
        Ok(_) => errors.push(format!(
            "{label} path {} is not a directory",
            path.display()
        )),
        Err(_) => errors.push(format!("{label} directory {} is missing", path.display())),
    }
}

fn check_private_file(
    label: &str,
    path: &Path,
    required: bool,
    warnings: &mut Vec<String>,
    errors: &mut Vec<String>,
) {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    warnings.push(format!(
                        "{label} {} has mode {mode:o}; it should be 0600",
                        path.display()
                    ));
                }
            }
        }
        Ok(_) => errors.push(format!("{label} {} is not a regular file", path.display())),
        Err(_) if !required => {}
        Err(_) => errors.push(format!("{label} {} is missing", path.display())),
    }
}

fn command_available(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2).map(|v| v == "0"))
        })
        .unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn is_root() -> bool {
    false
}
