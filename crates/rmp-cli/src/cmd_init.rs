//! `rmp init` — server setup: generate identity and set the access password.

use crate::config::{self, Logging};
use crate::logging::AUDIT_TARGET;
use anyhow::{bail, Context, Result};
use rmp_crypto::{hostkey::write_private, password, HostKey};
use rmp_dirs::Layout;

/// Initialize server state for the given layout.
pub fn run(
    layout: &Layout,
    username: &str,
    listen: &str,
    force: bool,
    with_root: bool,
    password_stdin: bool,
    reset_keys: bool,
) -> Result<()> {
    layout.ensure_all()?;
    let _log = crate::logging::init(layout, &Logging::default()).ok();

    if username.trim().is_empty() {
        bail!("the server username must not be empty");
    }
    if username == "root" {
        bail!(
            "the server username must not be 'root'; use `rmp init --root` \
             for root login (separate root password)"
        );
    }

    let key_path = layout.host_key_file();
    if key_path.exists() && !force {
        bail!(
            "RMP server state already exists in {} (use --force to overwrite)",
            layout.data_dir.display()
        );
    }
    if reset_keys {
        match std::fs::remove_file(layout.authorized_keys_file()) {
            Ok(()) => println!(
                "removed device keys: {}",
                layout.authorized_keys_file().display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("removing {}", layout.authorized_keys_file().display())
                })
            }
        }
    } else if force && layout.authorized_keys_file().exists() {
        eprintln!(
            "[rmp] warning: --force keeps existing device keys in {}; \
             use --reset-keys to revoke passwordless logins",
            layout.authorized_keys_file().display()
        );
    }

    let password = if password_stdin {
        read_stdin_password("remote access password")?
    } else {
        prompt_new_password("New password for remote access: ")?
    };

    // Identity (secret) → data directory.
    let host_key = HostKey::generate().context("generating host key")?;
    host_key.save(&layout.data_dir).context("saving host key")?;

    // OPAQUE setup and password file (secrets/hashes) → data directory.
    let setup = password::new_setup();
    write_private(
        &layout.opaque_setup_file(),
        &password::setup_to_bytes(&setup),
    )
    .context("saving OPAQUE setup")?;
    let file = password::enroll(password.as_bytes(), username, &setup)
        .context("deriving password file")?;
    file.save(&layout.password_file())
        .context("saving password file")?;

    // Optional root password.
    if with_root {
        let root_pw = if password_stdin {
            read_stdin_password("root password")?
        } else {
            prompt_new_password("New password for root access: ")?
        };
        let root_file =
            password::enroll(root_pw.as_bytes(), "root", &setup).context("deriving root file")?;
        root_file
            .save(&layout.root_password_file())
            .context("saving root password file")?;
    }

    // Configuration (commented template) → config directory.
    std::fs::write(
        layout.config_file(),
        config::template(username, listen, with_root),
    )
    .context("writing config.toml")?;

    tracing::info!(
        target: AUDIT_TARGET,
        event = "server.init",
        user = %username,
        listen = %listen,
        allow_root = with_root,
        fingerprint = %host_key.fingerprint()
    );

    println!();
    println!("RMP server initialized.");
    println!("  user             : {username}");
    if with_root {
        println!("  root login       : enabled (allow_root = true)");
    }
    println!("  listen           : {listen}");
    println!("  host fingerprint : {}", host_key.fingerprint());
    println!();
    println!("Directories:");
    println!("  config : {}", layout.config_dir.display());
    println!("  data   : {}  (secrets, 0700)", layout.data_dir.display());
    println!("  state  : {}  (logs)", layout.state_dir.display());
    println!();
    println!(
        "Edit {} to change behavior, then:",
        layout.config_file().display()
    );
    println!("  rmp serve{}", dir_hint(layout));
    println!();
    println!("From another machine:");
    println!("  rmp connect {username}@<this-host>:{}", port_of(listen));

    Ok(())
}

/// Build a `--system`/`--dir`/`--*-dir` hint matching the layout used.
pub fn dir_hint(layout: &Layout) -> String {
    if layout == &Layout::system() {
        " --system".to_string()
    } else if layout.config_dir == layout.data_dir && layout.data_dir == layout.state_dir {
        format!(" --dir {}", layout.config_dir.display())
    } else {
        format!(
            " --config-dir {} --data-dir {} --state-dir {}",
            layout.config_dir.display(),
            layout.data_dir.display(),
            layout.state_dir.display()
        )
    }
}

fn port_of(listen: &str) -> u16 {
    listen
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .unwrap_or(2222)
}

/// Read one password line from stdin (for `--password-stdin`).
pub(crate) fn read_stdin_password(label: &str) -> Result<zeroize::Zeroizing<String>> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .with_context(|| format!("reading {label} from stdin"))?;
    let line = line.trim_end_matches(['\n', '\r']);
    if line.is_empty() {
        bail!("{label} from stdin is empty");
    }
    Ok(zeroize::Zeroizing::new(line.to_string()))
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
