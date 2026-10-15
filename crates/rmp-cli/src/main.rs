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
mod cmd_connect;
mod cmd_cp;
mod cmd_init;
mod cmd_passwd;
mod cmd_serve;
mod config;
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
    #[command(subcommand)]
    command: Command,
}

/// Where RMP keeps its files.
#[derive(Args, Debug, Clone)]
struct DirArgs {
    /// Use system-wide locations: /etc/rmp, /var/lib/rmp, /var/log/rmp.
    #[arg(long)]
    system: bool,
    /// Put configuration, data and state under a single directory.
    #[arg(long, value_name = "DIR")]
    dir: Option<PathBuf>,
    /// Override the configuration directory.
    #[arg(long, value_name = "DIR")]
    config_dir: Option<PathBuf>,
    /// Override the data directory (secrets/hashes).
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
    /// Override the state/log directory.
    #[arg(long, value_name = "DIR")]
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
        #[command(flatten)]
        dirs: DirArgs,
        /// Account name used for remote access.
        #[arg(long, default_value = "rmp")]
        user: String,
        /// Address the server will listen on.
        #[arg(long, default_value = "0.0.0.0:2222")]
        listen: String,
        /// Also set a password for root and enable `auth.allow_root`.
        #[arg(long)]
        root: bool,
        /// Overwrite existing state.
        #[arg(long)]
        force: bool,
    },
    /// Run the RMP server (daemon).
    Serve {
        #[command(flatten)]
        dirs: DirArgs,
        /// Override the listen address.
        #[arg(long)]
        listen: Option<String>,
    },
    /// Connect to a remote machine and open an interactive shell.
    Connect {
        /// Target in the form user@host[:port].
        target: String,
        #[command(flatten)]
        dirs: DirArgs,
        /// Accept an unknown host key without prompting.
        #[arg(long)]
        accept_new: bool,
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
        #[command(flatten)]
        dirs: DirArgs,
        /// Remote port.
        #[arg(long, default_value_t = 2222)]
        port: u16,
        /// Accept an unknown host key without prompting.
        #[arg(long)]
        accept_new: bool,
    },
    /// Set or replace the access password.
    Passwd {
        #[command(flatten)]
        dirs: DirArgs,
        /// Account name (defaults to the one in the config).
        #[arg(long)]
        user: Option<String>,
        /// Set the root password instead.
        #[arg(long)]
        root: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init {
            dirs,
            user,
            listen,
            root,
            force,
        } => {
            let layout = dirs.resolve()?;
            cmd_init::run(&layout, &user, &listen, force, root)
        }
        Command::Serve { dirs, listen } => {
            let layout = dirs.resolve()?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(cmd_serve::run(&layout, listen))
        }
        Command::Connect {
            target,
            dirs,
            accept_new,
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
            dirs,
            port,
            accept_new,
        } => {
            let layout = dirs.resolve()?;
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            let code = rt.block_on(cmd_cp::run(&src, &dst, &layout, port, accept_new))?;
            std::process::exit(code);
        }
        Command::Passwd { dirs, user, root } => {
            let layout = dirs.resolve()?;
            cmd_passwd::run(&layout, user, root)
        }
    }
}
