//! # rmp — Remote Machine Protocol CLI
//!
//! Subcommands:
//!
//! * `rmp init`    — server setup (generates identity, prompts for a password)
//! * `rmp serve`   — run the daemon
//! * `rmp connect` — connect and open an interactive shell
//!
//! Directories follow the XDG Base Directory spec for user installs and the
//! FHS locations (`/etc`, `/var/lib`, `/var/log`) in `--system` mode.

#![forbid(unsafe_code)]

mod authflow;
mod cmd_config;
mod cmd_connect;
mod cmd_cp;
mod cmd_doctor;
mod cmd_exec;
mod cmd_init;
mod cmd_keys;
mod cmd_known_hosts;
mod cmd_passwd;
mod cmd_serve;
mod cmd_service;
mod config;
mod helper;
mod logging;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use rmp_dirs::Layout;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "rmp",
    version,
    about = "RMP — Remote Machine Protocol (secure remote shell)"
)]
struct Cli {
    #[command(flatten)]
    dirs: DirArgs,
    #[command(subcommand)]
    command: Command,
}

/// Where RMP keeps its files.
#[derive(Args, Debug, Clone)]
struct DirArgs {
    /// Use system-wide locations: /etc/rmp, /var/lib/rmp, /var/log/rmp.
    #[arg(long, global = true)]
    system: bool,
    /// Put configuration, data and state under a single directory.
    #[arg(long, global = true, value_name = "DIR")]
    dir: Option<PathBuf>,
    /// Override the configuration directory.
    #[arg(long, global = true, value_name = "DIR")]
    config_dir: Option<PathBuf>,
    /// Override the data directory (secrets/hashes).
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,
    /// Override the state/log directory.
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,
}

impl DirArgs {
    fn resolve(&self) -> Result<Layout> {
        let base = if self.system {
            Layout::system()
        } else {
            Layout::user()?
        };
        let layout = match &self.dir {
            Some(dir) => Layout::single(dir),
            None => base,
        };
        Ok(layout.with_overrides(
            self.config_dir.clone(),
            self.data_dir.clone(),
            self.state_dir.clone(),
        ))
    }
}

#[derive(Subcommand)]
enum Command {
    /// Initialize this machine as a server: generate identity and set a password.
    Init {
        /// Account name used for remote access.
        #[arg(long, default_value = "rmp")]
        user: String,
        /// Address the server will listen on.
        #[arg(long, default_value = "0.0.0.0:2222")]
        listen: String,
        /// Also set a password for root and enable `auth.allow_root`.
        #[arg(long)]
        root: bool,
        /// Read the password(s) from stdin instead of prompting (normal
        /// account first, then root when `--root` is used).
        #[arg(long)]
        password_stdin: bool,
        /// Remove enrolled device keys (revoke passwordless logins).
        #[arg(long)]
        reset_keys: bool,
        /// Overwrite existing state.
        #[arg(long)]
        force: bool,
    },
    /// Run the RMP server (daemon).
    Serve {
        /// Override the listen address.
        #[arg(long)]
        listen: Option<String>,
    },
    /// Connect to a remote machine and open an interactive shell.
    Connect {
        /// Target in the form user@host[:port].
        target: String,
        /// Accept an unknown host key without prompting.
        #[arg(long)]
        accept_new: bool,
        /// Pin the server to this SHA-256 fingerprint (hex) instead of using known_hosts.
        #[arg(long, value_name = "HEX")]
        fingerprint: Option<String>,
        /// Local forward: `[bind_address:]port:host:hostport` (repeatable).
        #[arg(short = 'L', long = "local-forward", value_name = "SPEC")]
        local_forward: Vec<String>,
        /// Remote forward: `[bind_address:]port:host:hostport` bound on the server (repeatable).
        #[arg(short = 'R', long = "remote-forward", value_name = "SPEC")]
        remote_forward: Vec<String>,
        /// Do not open a shell; only keep forwards running.
        #[arg(short = 'N', long = "no-shell")]
        no_shell: bool,
        /// QUIC idle timeout in seconds (overrides the config).
        #[arg(long)]
        idle_timeout: Option<u64>,
    },
    /// Copy a file to/from a remote machine (`user@host:path`).
    Cp {
        /// Source: a local path or `user@host:path`.
        src: String,
        /// Destination: a local path or `user@host:path`.
        dst: String,
        /// Remote port.
        #[arg(long, default_value_t = 2222)]
        port: u16,
        /// Accept an unknown host key without prompting.
        #[arg(long)]
        accept_new: bool,
        /// Pin the server to this SHA-256 fingerprint (hex) instead of using known_hosts.
        #[arg(long, value_name = "HEX")]
        fingerprint: Option<String>,
        /// Show transfer progress on stderr.
        #[arg(long)]
        progress: bool,
        /// Copy directories recursively.
        #[arg(short = 'r', long)]
        recursive: bool,
    },
    /// Run a command on a remote machine and return its exit status.
    Exec {
        /// Target in the form user@host[:port].
        target: String,
        /// Command and arguments to run remotely.
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
        /// Accept an unknown host key without prompting.
        #[arg(long)]
        accept_new: bool,
        /// Pin the server to this SHA-256 fingerprint (hex) instead of using known_hosts.
        #[arg(long, value_name = "HEX")]
        fingerprint: Option<String>,
    },
    /// Inspect or edit the client's known_hosts file.
    KnownHosts {
        #[command(subcommand)]
        command: KnownHostsCommand,
    },
    /// Inspect or revoke device keys enrolled on this server.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Validate config.toml, CIDRs and limits without starting the server.
    ConfigCheck,
    /// Check config and on-disk permissions for common problems.
    Doctor,
    /// Set or replace the access password.
    Passwd {
        /// Account name (defaults to the one in the config).
        #[arg(long)]
        user: Option<String>,
        /// Set the root password instead.
        #[arg(long)]
        root: bool,
        /// Read the password from stdin instead of prompting.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Install a systemd service so `rmp serve` runs at boot (Linux; needs root).
    InstallService {
        /// User the service runs as (default: the invoking user).
        #[arg(long)]
        user: Option<String>,
        /// Path to the rmp binary (default: the running one).
        #[arg(long)]
        bin: Option<PathBuf>,
        /// Install but do not start it.
        #[arg(long)]
        no_start: bool,
        /// Print the unit file instead of installing it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the systemd service (Linux; needs root).
    UninstallService,
    /// Internal helper used by the server to run file/forward operations as a
    /// non-root user in root mode. Not a public command.
    #[command(hide = true, name = "__helper")]
    Helper,
}

#[derive(Subcommand)]
enum KnownHostsCommand {
    /// List host fingerprints.
    List,
    /// Remove a host from known_hosts.
    Remove {
        /// Host key as stored, e.g. `example.com:2222` or `[::1]:2222`.
        host: String,
    },
}

#[derive(Subcommand)]
enum KeysCommand {
    /// List authorized device keys.
    List,
    /// Revoke a device key by its SHA-256 fingerprint (hex).
    Revoke {
        /// Fingerprint shown by `rmp keys list`.
        fingerprint: String,
    },
}

fn main() -> Result<()> {
    let Cli { dirs, command } = Cli::parse();

    match command {
        Command::Init {
            user,
            listen,
            root,
            password_stdin,
            reset_keys,
            force,
        } => {
            let layout = dirs.resolve()?;
            cmd_init::run(
                &layout,
                &user,
                &listen,
                force,
                root,
                password_stdin,
                reset_keys,
            )
        }
        Command::Serve { listen } => {
            let layout = dirs.resolve()?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(cmd_serve::run(&layout, listen))
        }
        Command::Connect {
            target,
            accept_new,
            fingerprint,
            local_forward,
            remote_forward,
            no_shell,
            idle_timeout,
        } => {
            let layout = dirs.resolve()?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let code = rt.block_on(cmd_connect::run(
                &target,
                &layout,
                accept_new,
                fingerprint.as_deref(),
                idle_timeout,
                local_forward,
                remote_forward,
                no_shell,
            ))?;
            std::process::exit(code);
        }
        Command::Cp {
            src,
            dst,
            port,
            accept_new,
            fingerprint,
            progress,
            recursive,
        } => {
            let layout = dirs.resolve()?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let code = rt.block_on(cmd_cp::run(
                &src,
                &dst,
                &layout,
                port,
                accept_new,
                fingerprint.as_deref(),
                progress,
                recursive,
            ))?;
            std::process::exit(code);
        }
        Command::Exec {
            target,
            command,
            accept_new,
            fingerprint,
        } => {
            let layout = dirs.resolve()?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let code = rt.block_on(cmd_exec::run(
                &target,
                &command,
                &layout,
                accept_new,
                fingerprint.as_deref(),
            ))?;
            std::process::exit(code);
        }
        Command::KnownHosts { command } => {
            let layout = dirs.resolve()?;
            match command {
                KnownHostsCommand::List => cmd_known_hosts::list(&layout),
                KnownHostsCommand::Remove { host } => cmd_known_hosts::remove(&layout, &host),
            }
        }
        Command::Keys { command } => {
            let layout = dirs.resolve()?;
            match command {
                KeysCommand::List => cmd_keys::list(&layout),
                KeysCommand::Revoke { fingerprint } => cmd_keys::revoke(&layout, &fingerprint),
            }
        }
        Command::ConfigCheck => {
            let layout = dirs.resolve()?;
            cmd_config::run(&layout)
        }
        Command::Doctor => {
            let layout = dirs.resolve()?;
            cmd_doctor::run(&layout)
        }
        Command::Passwd {
            user,
            root,
            password_stdin,
        } => {
            let layout = dirs.resolve()?;
            cmd_passwd::run(&layout, user, root, password_stdin)
        }
        Command::InstallService {
            user,
            bin,
            no_start,
            dry_run,
        } => cmd_service::install(user, bin, no_start, dry_run),
        Command::UninstallService => cmd_service::uninstall(),
        Command::Helper => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(helper::run())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_overrides_are_global() {
        let cli = Cli::try_parse_from(["rmp", "keys", "list", "--dir", "/tmp/rmp"]).unwrap();
        assert_eq!(cli.dirs.dir, Some(PathBuf::from("/tmp/rmp")));
        assert!(matches!(cli.command, Command::Keys { .. }));
    }

    #[test]
    fn exec_captures_arguments_after_dashdash() {
        let cli = Cli::try_parse_from(["rmp", "exec", "alice@host", "--", "echo", "hi"]).unwrap();
        match cli.command {
            Command::Exec { command, .. } => {
                assert_eq!(command, vec!["echo".to_string(), "hi".to_string()]);
            }
            _ => panic!("expected exec"),
        }
    }
}
