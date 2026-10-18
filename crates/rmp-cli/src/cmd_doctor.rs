//! `rmp doctor` (alias: `rmp status`) — local diagnostics.
//!
//! The command is read-only apart from cleaning a stale PID file (through the
//! server-running probe). It reports problems that commonly break a connection:
//! missing/invalid host key, password file, config, trust store, permissions,
//! a stopped server or a held UDP port.

use crate::config::FileConfig;
use anyhow::Result;
use rmp_crypto::{password, HostKey, KnownHosts};
use rmp_dirs::Layout;
use rmp_server::AuthorizedKeys;
use std::path::Path;

#[derive(Default)]
struct Report {
    errors: usize,
    warnings: usize,
}

impl Report {
    fn ok(&self, message: impl AsRef<str>) {
        println!("[ok]    {}", message.as_ref());
    }

    fn info(&self, message: impl AsRef<str>) {
        println!("[info]  {}", message.as_ref());
    }

    fn warn(&mut self, message: impl AsRef<str>) {
        self.warnings += 1;
        println!("[warn]  {}", message.as_ref());
    }

    fn error(&mut self, message: impl AsRef<str>) {
        self.errors += 1;
        println!("[error] {}", message.as_ref());
    }
}

/// Run the diagnostics. Returns the process exit code (0 = no errors).
pub fn run(layout: &Layout) -> Result<i32> {
    let mut report = Report::default();

    println!(
        "RMP doctor — {} ({}, {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!();

    let config_path = layout.config_file();
    let config = if config_path.exists() {
        match FileConfig::load(&config_path) {
            Ok(config) => {
                report.ok(format!("config: {}", config_path.display()));
                config
            }
            Err(e) => {
                report.error(format!("config {}: {e}", config_path.display()));
                FileConfig::default()
            }
        }
    } else {
        report.warn(format!(
            "config not found at {} (defaults will be used)",
            config_path.display()
        ));
        FileConfig::default()
    };

    report.ok(format!("server account: {}", config.server.username));
    if let Some(os_user) = os_user() {
        if os_user != config.server.username {
            report.info(format!(
                "OS user is '{os_user}', but RMP authenticates as '{}' (connect as {}@host)",
                config.server.username, config.server.username
            ));
        }
    }
    report.ok(format!("listen: {}", config.server.listen));
    report.info(format!(
        "server.enabled={}, password_enabled={}, allow_root={}, key_auth={}, key_enrollment={}",
        config.server.enabled,
        config.auth.password_enabled,
        config.auth.allow_root,
        config.auth.allow_key_auth,
        config.auth.allow_key_enrollment
    ));

    check_dir(&mut report, &layout.config_dir, "config dir");
    check_dir(&mut report, &layout.data_dir, "data dir");
    check_dir(&mut report, &layout.state_dir, "state dir");

    check_host_key(&mut report, layout);
    check_opaque_setup(&mut report, layout);
    check_password_file(&mut report, layout);
    check_root(&mut report, layout, &config);
    check_authorized_keys(&mut report, layout);
    check_known_hosts(&mut report, layout);
    check_server(&mut report, layout, &config);

    println!();
    if report.errors > 0 {
        println!("{} error(s), {} warning(s)", report.errors, report.warnings);
        Ok(1)
    } else {
        println!("0 errors, {} warning(s)", report.warnings);
        Ok(0)
    }
}

fn os_user() -> Option<String> {
    for variable in ["USER", "LOGNAME"] {
        if let Ok(value) = std::env::var(variable) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn check_dir(report: &mut Report, path: &Path, label: &str) {
    if !path.exists() {
        report.warn(format!("{label} missing: {}", path.display()));
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    report.warn(format!(
                        "{label} {} is {mode:03o}; expected 0700",
                        path.display()
                    ));
                } else {
                    report.ok(format!("{label}: {} ({mode:03o})", path.display()));
                }
            }
            Err(e) => report.warn(format!("{label} {}: {e}", path.display())),
        }
    }
    #[cfg(not(unix))]
    {
        report.ok(format!("{label}: {}", path.display()));
    }
}

fn check_private_file(report: &mut Report, path: &Path, label: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                report.warn(format!(
                    "{label} {} is {mode:03o}; expected 0600",
                    path.display()
                ));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (report, path, label);
    }
}

fn check_host_key(report: &mut Report, layout: &Layout) {
    let path = layout.host_key_file();
    if !path.exists() {
        report.error(format!(
            "host key missing: {} (run `rmp init`)",
            path.display()
        ));
        return;
    }
    match HostKey::load(&layout.data_dir) {
        Ok(key) => {
            report.ok(format!(
                "host key: {} (fingerprint {})",
                path.display(),
                key.fingerprint()
            ));
            check_private_file(report, &path, "host key");
        }
        Err(e) => report.error(format!("host key {}: {e}", path.display())),
    }
}

fn check_opaque_setup(report: &mut Report, layout: &Layout) {
    let path = layout.opaque_setup_file();
    match std::fs::read(&path) {
        Ok(bytes) => match password::setup_from_bytes(&bytes) {
            Ok(_) => {
                report.ok(format!("OPAQUE setup: {}", path.display()));
                check_private_file(report, &path, "OPAQUE setup");
            }
            Err(e) => report.error(format!("OPAQUE setup {}: {e}", path.display())),
        },
        Err(e) => report.error(format!("OPAQUE setup {}: {e}", path.display())),
    }
}

fn check_password_file(report: &mut Report, layout: &Layout) {
    let path = layout.password_file();
    match password::PasswordFile::load(&path) {
        Ok(_) => {
            report.ok(format!("password file: {}", path.display()));
            check_private_file(report, &path, "password file");
        }
        Err(e) => report.error(format!(
            "password file {}: {e} (run `rmp passwd`)",
            path.display()
        )),
    }
}

fn check_root(report: &mut Report, layout: &Layout, config: &FileConfig) {
    if !config.auth.allow_root {
        report.info("root login: disabled");
        return;
    }
    let path = layout.root_password_file();
    match password::PasswordFile::load(&path) {
        Ok(_) => {
            report.ok(format!("root password file: {}", path.display()));
            check_private_file(report, &path, "root password file");
        }
        Err(e) => report.error(format!(
            "root login enabled but {} is unusable: {e}",
            path.display()
        )),
    }
}

fn check_authorized_keys(report: &mut Report, layout: &Layout) {
    let path = layout.authorized_keys_file();
    if !path.exists() {
        report.info(format!("authorized_keys: none ({})", path.display()));
        return;
    }
    match AuthorizedKeys::load(&path) {
        Ok(keys) => {
            report.ok(format!(
                "authorized_keys: {} key(s) ({})",
                keys.entries().len(),
                path.display()
            ));
            check_private_file(report, &path, "authorized_keys");
        }
        Err(e) => report.error(format!("authorized_keys {}: {e}", path.display())),
    }
}

fn check_known_hosts(report: &mut Report, layout: &Layout) {
    let path = layout.known_hosts_file();
    if !path.exists() {
        report.info(format!("known_hosts: none ({})", path.display()));
        return;
    }
    match KnownHosts::load(&path) {
        Ok(hosts) => report.ok(format!(
            "known_hosts: {} host(s) ({})",
            hosts.len(),
            path.display()
        )),
        Err(e) => report.error(format!("known_hosts {}: {e}", path.display())),
    }
}

fn check_server(report: &mut Report, layout: &Layout, config: &FileConfig) {
    match crate::cmd_serve::running_server(layout, Some(&config.server.listen)) {
        Ok(Some(reason)) => report.ok(format!("server: {reason}")),
        Ok(None) => report.warn(format!(
            "server: not running on {} (start `rmp serve` or the systemd service)",
            config.server.listen
        )),
        Err(e) => report.error(format!("server status: {e}")),
    }

    #[cfg(target_os = "linux")]
    if Path::new("/run/systemd/system").exists() {
        match std::process::Command::new("systemctl")
            .args(["is-active", "rmp"])
            .output()
        {
            Ok(output) => {
                let state = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if state == "active" {
                    report.ok("systemd: rmp.service active");
                } else {
                    report.warn(format!("systemd: rmp.service {state}"));
                }
            }
            Err(e) => report.warn(format!("systemd: cannot run systemctl: {e}")),
        }
    }
}
