//! `rmp exec` — run a command remotely and return its exit status.

use crate::authflow::{self, DEFAULT_PORT};
use crate::config::FileConfig;
use crate::logging::AUDIT_TARGET;
use anyhow::{bail, Context, Result};
use rmp_crypto::Fingerprint;
use rmp_dirs::Layout;
use std::io::Write;

/// Connect, authenticate and run `command` through the remote shell.
pub async fn run(
    target: &str,
    command: &[String],
    layout: &Layout,
    accept_new_flag: bool,
    fingerprint: Option<&str>,
) -> Result<i32> {
    if command.is_empty() {
        bail!("rmp exec requires a command");
    }

    let _ = layout.ensure_config();
    let config = FileConfig::load_or_default(&layout.config_file())
        .with_context(|| format!("reading {}", layout.config_file().display()))?;
    let _ = crate::logging::init(layout, &config.logging).ok();

    let accept_new = accept_new_flag || config.client.accept_new_hosts;
    let pinned = match fingerprint {
        Some(hex) => Some(Fingerprint::from_hex(hex).context("invalid --fingerprint")?),
        None => None,
    };

    let target = authflow::parse_target(target, DEFAULT_PORT)?;
    let key = target.key();

    let client = authflow::connect_authenticated(
        layout,
        &config,
        &target,
        accept_new,
        config.client.idle_timeout_secs,
        false,
        pinned,
    )
    .await?;

    tracing::info!(target: AUDIT_TARGET, event = "session.start", host = %key, kind = "exec");
    let output = client.exec(&shell_join(command)).await?;

    let mut stdout = std::io::stdout();
    stdout.write_all(&output.data)?;
    stdout.flush()?;

    tracing::info!(target: AUDIT_TARGET, event = "session.end", host = %key,
                   exit_code = output.exit_code);
    Ok(output.exit_code as i32)
}

/// Join arguments into a POSIX shell command, quoting what needs it.
fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|arg| quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c));
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_only_when_needed() {
        assert_eq!(quote("uname"), "uname");
        assert_eq!(quote("-a"), "-a");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn joins_arguments() {
        let args = vec!["printf".to_string(), "%s\n".to_string(), "a b".to_string()];
        assert_eq!(shell_join(&args), "printf '%s\n' 'a b'");
    }
}
