//! `rmp init` — server setup: generate identity and set the access password.

use crate::config::{self, FileConfig, Logging};
use crate::logging::AUDIT_TARGET;
use anyhow::{bail, Context, Result};
use rmp_crypto::{hostkey::write_private, password, HostKey};
use rmp_dirs::Layout;

/// Initialize server state for the given layout.
///
/// Re-running with `--force` keeps the existing host key unless
/// `--new-host-key` is given, refuses to overwrite state while a server is
/// running, and moves old device keys aside if the account name changes.
#[allow(clippy::too_many_arguments)]
pub fn run(
    layout: &Layout,
    username: &str,
    listen: &str,
    force: bool,
    with_root: bool,
    new_host_key: bool,
) -> Result<()> {
    layout.ensure_all()?;
    let _log = crate::logging::init(layout, &Logging::default()).ok();

    let key_path = layout.host_key_file();
    let had_state = key_path.exists();
    if had_state && !force {
        bail!(
            "RMP server state already exists in {} (use --force to update it; \
             the host key is preserved unless --new-host-key is also given)",
            layout.data_dir.display()
        );
    }

    // Never rewrite state underneath a running daemon: the live process keeps
    // the old host key/password in memory while clients see the new files.
    if let Some(reason) = crate::cmd_serve::running_server(layout, Some(listen))? {
        bail!(
            "{reason}.\nStop `rmp serve` first (for example `sudo systemctl stop rmp`) \
             before running `rmp init`."
        );
    }

    let old_config = if layout.config_file().exists() {
        FileConfig::load(&layout.config_file()).ok()
    } else {
        None
    };
    let old_user = old_config.as_ref().map(|c| c.server.username.clone());
    let old_fingerprint = if had_state {
        HostKey::load(&layout.data_dir)
            .ok()
            .map(|key| key.fingerprint())
    } else {
        None
    };

    // Prepare the config before touching any state: an invalid existing config
    // must abort here, not after the host key/password files were replaced.
    let new_config = prepare_config(layout, username, listen, with_root)?;

    let password = prompt_new_password("New password for remote access: ")?;

    // Identity (secret) → data directory. A re-init preserves the host key by
    // default so existing `known_hosts` entries keep working.
    let host_key = select_host_key(layout, new_host_key)?;
    let fingerprint = host_key.fingerprint();

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

    // Optional root password. A new OPAQUE setup invalidates a previous root
    // registration, so remove it when root is not being configured again.
    if with_root {
        let root_pw = prompt_new_password("New password for root access: ")?;
        let root_file =
            password::enroll(root_pw.as_bytes(), "root", &setup).context("deriving root file")?;
        root_file
            .save(&layout.root_password_file())
            .context("saving root password file")?;
    } else if layout.root_password_file().exists() {
        let _ = std::fs::remove_file(layout.root_password_file());
    }

    // Device keys are global to the single server account. If the account
    // changes, old credentials must not silently authenticate as the new one.
    migrate_device_keys(layout, old_user.as_deref(), username)?;

    // Configuration → config directory. An existing file keeps its comments
    // and custom settings; only the fields controlled by `init` are updated.
    std::fs::write(layout.config_file(), new_config).context("writing config.toml")?;

    let key_status = if had_state && !new_host_key {
        "preserved"
    } else if old_fingerprint.is_some() {
        "rotated"
    } else {
        "generated"
    };

    tracing::info!(
        target: AUDIT_TARGET,
        event = "server.init",
        user = %username,
        listen = %listen,
        allow_root = with_root,
        fingerprint = %fingerprint,
        host_key = key_status
    );

    println!();
    println!("RMP server initialized.");
    println!("  user             : {username}");
    if with_root {
        println!("  root login       : enabled (allow_root = true)");
    }
    println!("  listen           : {listen}");
    println!("  host key         : {key_status}");
    println!("  host fingerprint : {fingerprint}");
    if let Some(old) = old_fingerprint {
        if old != fingerprint {
            println!("  previous key     : {old}");
            println!();
            println!("WARNING: the host key changed. Clients that pinned the previous");
            println!("fingerprint must update `known_hosts` after verifying the new one:");
            println!("  rmp connect ... --update-host-key");
        }
    }
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

/// Build the config text written by `init`.
///
/// Fresh installs get the fully commented template. On re-init, the existing
/// file is edited in place (preserving comments and all settings not controlled
/// by `init`) and only `server.username`, `server.listen` and `auth.allow_root`
/// are updated.
fn prepare_config(
    layout: &Layout,
    username: &str,
    listen: &str,
    with_root: bool,
) -> Result<String> {
    let path = layout.config_file();
    if !path.exists() {
        return Ok(config::template(username, listen, with_root));
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    if text.trim().is_empty() {
        return Ok(config::template(username, listen, with_root));
    }

    let mut document: toml_edit::DocumentMut = text.parse().with_context(|| {
        format!(
            "parsing {}; fix or move it aside before running `rmp init`",
            path.display()
        )
    })?;

    let server = config_table(&mut document, "server");
    server["username"] = toml_edit::value(username);
    server["listen"] = toml_edit::value(listen);

    let auth = config_table(&mut document, "auth");
    auth["allow_root"] = toml_edit::value(with_root);

    Ok(document.to_string())
}

fn config_table<'a>(
    document: &'a mut toml_edit::DocumentMut,
    name: &str,
) -> &'a mut toml_edit::Table {
    if !document.contains_key(name) || !document[name].is_table() {
        document[name] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    document[name]
        .as_table_mut()
        .expect("table was just ensured")
}

/// Load the existing host key or create one.
///
/// `new_host_key` is the explicit opt-in to rotation; without it a re-init
/// reuses the current identity, keeping clients' `known_hosts` entries valid.
fn select_host_key(layout: &Layout, new_host_key: bool) -> Result<HostKey> {
    let path = layout.host_key_file();
    if path.exists() && !new_host_key {
        return HostKey::load(&layout.data_dir).context("loading existing host key");
    }
    let key = HostKey::generate().context("generating host key")?;
    key.save(&layout.data_dir).context("saving host key")?;
    Ok(key)
}

/// Move old device keys out of the way when the account name changes.
///
/// `authorized_keys` is global to the single configured account, so leaving the
/// old file in place would let keys enrolled for the previous account
/// authenticate as the new one.
fn migrate_device_keys(layout: &Layout, old_user: Option<&str>, username: &str) -> Result<()> {
    if old_user == Some(username) {
        return Ok(());
    }
    let keys = layout.authorized_keys_file();
    if !keys.exists() {
        return Ok(());
    }
    let backup = keys.with_file_name("authorized_keys.bak");
    let _ = std::fs::remove_file(&backup);
    match std::fs::rename(&keys, &backup) {
        Ok(()) => eprintln!(
            "[rmp] account changed ({} -> {}); previous device keys moved to {}",
            old_user.unwrap_or("<none>"),
            username,
            backup.display()
        ),
        Err(e) => {
            eprintln!(
                "[rmp] warning: could not move {} to {}: {e}; clearing it instead",
                keys.display(),
                backup.display()
            );
            write_private(
                &keys,
                b"# RMP authorized_keys - one Ed25519 key per line: <hex> <comment>\n",
            )
            .context("clearing authorized_keys")?;
        }
    }
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

fn prompt_new_password(prompt: &str) -> Result<String> {
    let pw = rpassword::prompt_password(prompt).context("reading password")?;
    if pw.is_empty() {
        bail!("password must not be empty");
    }
    let confirm = rpassword::prompt_password("Confirm password: ").context("reading password")?;
    if pw != confirm {
        bail!("passwords do not match");
    }
    Ok(pw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reinit_preserves_host_key_unless_rotation_is_requested() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::single(dir.path());
        layout.ensure_data().unwrap();

        let first = select_host_key(&layout, false).unwrap();
        let reused = select_host_key(&layout, false).unwrap();
        assert_eq!(first.fingerprint(), reused.fingerprint());

        let rotated = select_host_key(&layout, true).unwrap();
        assert_ne!(first.fingerprint(), rotated.fingerprint());

        let reloaded = HostKey::load(&layout.data_dir).unwrap();
        assert_eq!(rotated.fingerprint(), reloaded.fingerprint());
    }

    #[test]
    fn reinit_preserves_custom_config_settings_and_comments() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::single(dir.path());
        layout.ensure_config().unwrap();
        let original = r#"
[server]
# keep this comment
username = "old"
listen = "0.0.0.0:2222"
max_sessions = 42

[logging]
level = "debug"
"#;
        std::fs::write(layout.config_file(), original).unwrap();

        let merged = prepare_config(&layout, "new", "127.0.0.1:3333", true).unwrap();
        let parsed: FileConfig = toml::from_str(&merged).unwrap();
        assert_eq!(parsed.server.username, "new");
        assert_eq!(parsed.server.listen, "127.0.0.1:3333");
        assert_eq!(parsed.server.max_sessions, 42);
        assert_eq!(parsed.logging.level, "debug");
        assert!(parsed.auth.allow_root);
        assert!(merged.contains("# keep this comment"));
    }

    #[test]
    fn reinit_rejects_invalid_config_before_touching_state() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::single(dir.path());
        layout.ensure_config().unwrap();
        std::fs::write(layout.config_file(), "this is not = valid = toml").unwrap();

        let error = prepare_config(&layout, "user", "0.0.0.0:2222", false).unwrap_err();
        assert!(error.to_string().contains("parsing"));
    }

    #[test]
    fn fresh_init_uses_commented_template() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::single(dir.path());
        let text = prepare_config(&layout, "alice", "0.0.0.0:2222", false).unwrap();
        assert!(text.contains("# RMP — Remote Machine Protocol · configuration"));
        assert!(text.contains("username = \"alice\""));
    }

    #[test]
    fn account_change_moves_old_device_keys_aside() {
        let dir = tempfile::tempdir().unwrap();
        let layout = Layout::single(dir.path());
        layout.ensure_data().unwrap();
        let keys = layout.authorized_keys_file();
        std::fs::write(
            &keys,
            "0e5026f34b7f0e749f32f1645a668a25814627707b01777319637d719e6683d4 rmp@host\n",
        )
        .unwrap();

        migrate_device_keys(&layout, Some("rmp"), "arch").unwrap();
        assert!(!keys.exists(), "old keys must not stay active");
        let backup = keys.with_file_name("authorized_keys.bak");
        assert!(backup.exists(), "old keys should be preserved for audit");

        std::fs::write(&keys, "deadbeef\n").unwrap();
        migrate_device_keys(&layout, Some("arch"), "arch").unwrap();
        assert!(keys.exists(), "same account keeps its keys");
    }
}
