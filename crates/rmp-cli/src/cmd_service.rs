//! `rmp install-service` / `rmp uninstall-service`.
//!
//! On Linux this installs a systemd **system** unit so `rmp serve` starts at
//! boot. It must run as root (use `sudo rmp install-service`).

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

const UNIT_PATH: &str = "/etc/systemd/system/rmp.service";

/// Install the service. `user` defaults to the invoking user (`SUDO_USER`),
/// `bin` to the running binary.
pub fn install(
    user: Option<String>,
    bin: Option<PathBuf>,
    no_start: bool,
    dry_run: bool,
) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    bail!("install-service currently supports Linux (systemd) only");

    #[cfg(target_os = "linux")]
    {
        let user = user
            .or_else(current_user)
            .context("could not determine the service user (pass --user)")?;
        let home = home_for(&user)
            .with_context(|| format!("could not find the home directory of '{user}'"))?;
        let bin = match bin {
            Some(b) => b,
            None => std::env::current_exe().context("resolving the current binary")?,
        };
        let bin = bin.canonicalize().unwrap_or(bin);

        let unit = render_unit(&bin, &user, &home);

        if dry_run {
            println!("{unit}");
            return Ok(());
        }

        if !is_root() {
            bail!("installing a system service requires root; run: sudo rmp install-service");
        }
        if !Path::new("/run/systemd/system").exists() {
            bail!("systemd does not appear to be running");
        }

        std::fs::write(UNIT_PATH, unit.as_bytes())
            .with_context(|| format!("writing {UNIT_PATH}"))?;
        println!("installed {UNIT_PATH}  (User={user}, ExecStart={bin:?})");

        systemctl(&["daemon-reload"])?;
        if no_start {
            systemctl(&["enable", "rmp"])?;
            println!("enabled rmp.service (not started; run: systemctl start rmp)");
        } else {
            systemctl(&["enable", "--now", "rmp"])?;
            println!("enabled and started rmp.service");
        }
        println!("check with: systemctl status rmp");
        Ok(())
    }
}

/// Stop, disable and remove the service.
pub fn uninstall() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    bail!("uninstall-service currently supports Linux (systemd) only");

    #[cfg(target_os = "linux")]
    {
        if !is_root() {
            bail!("removing a system service requires root; run: sudo rmp uninstall-service");
        }
        let _ = systemctl(&["disable", "--now", "rmp"]);
        if Path::new(UNIT_PATH).exists() {
            std::fs::remove_file(UNIT_PATH).with_context(|| format!("removing {UNIT_PATH}"))?;
            println!("removed {UNIT_PATH}");
        }
        let _ = systemctl(&["daemon-reload"]);
        Ok(())
    }
}

fn render_unit(bin: &Path, user: &str, home: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=RMP server (Remote Machine Protocol)\n\
         Documentation=https://github.com/marcosgabrielgomes110-collab/rmp\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         Environment=HOME={home}\n\
         Environment=RUST_LOG=info\n\
         ExecStart={bin} serve\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        user = user,
        home = home.display(),
        bin = bin.display(),
    )
}

/// The user that invoked us (prefers `SUDO_USER` so `sudo rmp ...` targets you).
fn current_user() -> Option<String> {
    for var in ["SUDO_USER", "USER", "LOGNAME"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() && v != "root" {
                return Some(v);
            }
        }
    }
    None
}

/// Look up a user's home directory in `/etc/passwd`.
fn home_for(user: &str) -> Option<PathBuf> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 6 && fields[0] == user {
            return Some(PathBuf::from(fields[5]));
        }
    }
    None
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

fn systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("running systemctl {}", args.join(" ")))?;
    if !status.success() {
        bail!("systemctl {} failed ({status})", args.join(" "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_has_expected_fields() {
        let unit = render_unit(
            Path::new("/usr/local/bin/rmp"),
            "dev",
            Path::new("/home/dev"),
        );
        assert!(unit.contains("User=dev"));
        assert!(unit.contains("Environment=HOME=/home/dev"));
        assert!(unit.contains("ExecStart=/usr/local/bin/rmp serve"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }
}
