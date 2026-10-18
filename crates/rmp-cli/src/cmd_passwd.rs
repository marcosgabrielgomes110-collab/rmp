//! `rmp passwd` — set or replace the access password (user or root).

use crate::config::Logging;
use crate::logging::AUDIT_TARGET;
use anyhow::{bail, Context, Result};
use rmp_crypto::{password, HostKey};
use rmp_dirs::Layout;

/// Set the password for `account` (the configured user, or `root`).
pub fn run(layout: &Layout, user: Option<String>, root: bool, password_stdin: bool) -> Result<()> {
    let _log = crate::logging::init(layout, &Logging::default()).ok();

    // Host key must exist (i.e. the server was initialized).
    let _ = HostKey::load(&layout.data_dir).context("host key not found — run `rmp init` first")?;
    let setup_bytes = std::fs::read(layout.opaque_setup_file()).context("reading OPAQUE setup")?;
    let setup = password::setup_from_bytes(&setup_bytes).context("parsing OPAQUE setup")?;

    let account = if root {
        "root".to_string()
    } else {
        match user {
            Some(u) => u,
            None => {
                crate::config::FileConfig::load_or_default(&layout.config_file())?
                    .server
                    .username
            }
        }
    };
    if !root && account == "root" {
        bail!("use `rmp passwd --root` to set the root password");
    }

    let pw = if password_stdin {
        crate::cmd_init::read_stdin_password("password")?
    } else {
        prompt_new_password(&format!("New password for '{account}': "))?
    };
    let file = password::enroll(pw.as_bytes(), &account, &setup).context("deriving file")?;

    let path = if root {
        layout.root_password_file()
    } else {
        layout.password_file()
    };
    file.save(&path).context("saving password file")?;

    tracing::info!(target: AUDIT_TARGET, event = "password.changed", account = %account);

    println!("Password updated for '{account}'.");
    if root {
        println!("Ensure `[auth] allow_root = true` in the config to allow root logins.");
    }
    Ok(())
}

fn prompt_new_password(prompt: &str) -> Result<zeroize::Zeroizing<String>> {
    let pw =
        zeroize::Zeroizing::new(rpassword::prompt_password(prompt).context("reading password")?);
    if pw.is_empty() {
        bail!("password must not be empty");
    }
    let confirm = zeroize::Zeroizing::new(
        rpassword::prompt_password("Confirm password: ").context("reading password")?,
    );
    if *pw != *confirm {
        bail!("passwords do not match");
    }
    Ok(pw)
}
