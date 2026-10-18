//! Server configuration and QUIC listener.

use crate::audit::audit;
use crate::auth::{self, AuthLimiter, Authed, Principal};
use crate::net::Cidr;
use crate::session;
use anyhow::{Context, Result};
use rmp_crypto::{self as crypto, HostKey};
use rmp_proto::{Disconnect, DisconnectReason, Message};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

/// How long a freshly connected peer has to open the control stream.
const CONTROL_STREAM_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound for the whole authentication exchange.
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum number of concurrent bidirectional streams per connection.
const MAX_BIDI_STREAMS: u32 = 256;

/// Everything the server needs to run.
pub struct ServerOptions {
    /// Account name accepted for password authentication.
    pub username: String,
    /// Server host identity.
    pub host_key: HostKey,
    /// OPAQUE server setup (long-term OPRF secret).
    pub opaque_setup: crypto::OpaqueSetup,
    /// Registration record for `username`.
    pub password_file: crypto::PasswordFile,
    /// When set, re-read the user's registration record on every attempt, so
    /// `rmp passwd` takes effect without restarting the daemon.
    pub password_file_path: Option<PathBuf>,
    /// Optional registration record for the `root` account.
    pub root_password_file: Option<crypto::PasswordFile>,
    /// Optional path to re-read the root registration record on every attempt.
    pub root_password_file_path: Option<PathBuf>,
    /// Allow authenticating as `root` (requires the server to run as root).
    pub allow_root: bool,
    /// Master switch for password authentication.
    pub password_enabled: bool,
    /// Allow device-key (public-key) authentication.
    pub allow_key_auth: bool,
    /// Allow enrolling a device key after a successful password login.
    pub allow_key_enrollment: bool,
    /// Path to the `authorized_keys` file.
    pub authorized_keys_path: PathBuf,
    /// Failed attempts allowed before a temporary lockout.
    pub max_auth_attempts: u32,
    /// Lockout duration after too many failures.
    pub lockout: Duration,
    /// QUIC idle timeout.
    pub idle_timeout: Duration,
    /// QUIC keep-alive interval.
    pub keep_alive: Duration,
    /// Shell used for interactive sessions (defaults to `$SHELL` or `/bin/sh`).
    pub shell: Option<String>,
    /// Message of the day shown at the start of each session.
    pub motd: Option<String>,
    /// Addresses allowed to connect (empty = any).
    pub allowed_cidrs: Vec<Cidr>,
    /// Addresses explicitly refused.
    pub denied_cidrs: Vec<Cidr>,
    /// Whether executed commands are written to the audit log.
    pub log_commands: bool,
    /// Allow clients to open local port forwards (`rmp connect -L`).
    pub allow_local_forward: bool,
    /// Allow clients to request remote port forwards (`rmp connect -R`).
    pub allow_remote_forward: bool,
    /// Allow non-root logins to request remote forwards on ports below 1024
    /// while the daemon runs as root (the daemon binds them).
    pub allow_privileged_ports: bool,
    /// Allow file transfer (`rmp cp`).
    pub allow_file_transfer: bool,
    /// Maximum number of concurrent sessions.
    pub max_sessions: usize,
    /// Maximum number of concurrent QUIC connections.
    pub max_connections: usize,
    /// Live session counter.
    sessions: AtomicUsize,
}

/// Everything needed to spawn a shell or a command for an authenticated user.
///
/// Keeping this in one place makes the privilege and environment decisions
/// (for example `runuser` in root mode) explicit and testable.
#[derive(Debug, Clone)]
pub(crate) struct SpawnSpec {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
}

impl std::fmt::Debug for ServerOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerOptions")
            .field("username", &self.username)
            .field("host_key", &self.host_key)
            .field("allow_root", &self.allow_root)
            .field("password_enabled", &self.password_enabled)
            .field("max_auth_attempts", &self.max_auth_attempts)
            .finish_non_exhaustive()
    }
}

impl ServerOptions {
    /// Build options with sensible defaults for the fields not set by callers.
    pub fn new(
        username: String,
        host_key: HostKey,
        opaque_setup: crypto::OpaqueSetup,
        password_file: crypto::PasswordFile,
    ) -> Self {
        ServerOptions {
            username,
            host_key,
            opaque_setup,
            password_file,
            password_file_path: None,
            root_password_file: None,
            root_password_file_path: None,
            allow_root: false,
            password_enabled: true,
            allow_key_auth: true,
            allow_key_enrollment: true,
            authorized_keys_path: PathBuf::new(),
            max_auth_attempts: 5,
            lockout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
            keep_alive: Duration::from_secs(15),
            shell: None,
            motd: None,
            allowed_cidrs: Vec::new(),
            denied_cidrs: Vec::new(),
            log_commands: true,
            allow_local_forward: true,
            allow_remote_forward: false,
            allow_privileged_ports: false,
            allow_file_transfer: true,
            max_sessions: 8,
            max_connections: 128,
            sessions: AtomicUsize::new(0),
        }
    }

    /// The shell to spawn, resolving the platform default.
    pub fn shell(&self) -> String {
        if let Some(shell) = &self.shell {
            if !shell.is_empty() {
                return shell.clone();
            }
        }
        if let Ok(shell) = std::env::var("SHELL") {
            if !shell.is_empty() {
                return shell;
            }
        }
        default_shell()
    }

    /// Load the current password registration for the configured user.
    ///
    /// Reading from disk on each attempt makes `rmp passwd` effective
    /// immediately. Tests and library users can keep using the in-memory file
    /// by leaving [`Self::password_file_path`] as `None`.
    pub fn current_password_file(&self) -> Option<crypto::PasswordFile> {
        self.load_password_file(self.password_file_path.as_deref())
    }

    /// Load the current root password registration, if configured.
    pub fn current_root_password_file(&self) -> Option<crypto::PasswordFile> {
        match &self.root_password_file_path {
            Some(path) => match crypto::PasswordFile::load(path) {
                Ok(file) => Some(file),
                Err(e) => {
                    warn!(path = %path.display(), error = %e,
                          "could not reload the root password file; failing closed");
                    None
                }
            },
            None => self.root_password_file.clone(),
        }
    }

    fn load_password_file(&self, path: Option<&std::path::Path>) -> Option<crypto::PasswordFile> {
        match path {
            Some(path) => match crypto::PasswordFile::load(path) {
                Ok(file) => Some(file),
                Err(e) => {
                    warn!(path = %path.display(), error = %e,
                          "could not reload the password file; failing closed");
                    None
                }
            },
            None => Some(self.password_file.clone()),
        }
    }

    /// Fail fast on insecure or impossible configurations.
    pub fn check_startup(&self) -> Result<()> {
        if self.username.trim().is_empty() {
            anyhow::bail!("server.username must not be empty");
        }
        // `root` has its own password file and its own switch. Allowing it as
        // the normal account would silently bypass both.
        if self.username == "root" {
            anyhow::bail!(
                "server.username must not be 'root'; use `rmp init --root` \
                 (auth.allow_root) for root access"
            );
        }
        if self.allow_root {
            if !is_root() {
                anyhow::bail!(
                    "auth.allow_root = true requires the server to run as root \
                     (start it via systemd as root, or with sudo)"
                );
            }
            if self.root_password_file.is_none() {
                anyhow::bail!(
                    "auth.allow_root = true but no root password is set \
                     (run `rmp init --root` or `rmp passwd --root`)"
                );
            }
            // Non-root logins are dropped with runuser; refuse to start if the
            // helper is missing instead of failing only at login time.
            if !command_available("runuser") {
                anyhow::bail!(
                    "auth.allow_root requires `runuser` (util-linux) in PATH \
                     to drop privileges for non-root logins"
                );
            }
            if !runuser_works(&self.username) {
                anyhow::bail!(
                    "server.username '{}' cannot be used with runuser \
                     (unknown user, missing home or PAM failure)",
                    self.username
                );
            }
        }
        if self.max_sessions == 0 {
            anyhow::bail!("server.max_sessions must be greater than zero");
        }
        if self.max_connections == 0 {
            anyhow::bail!("server.max_connections must be greater than zero");
        }
        Ok(())
    }

    /// Program, arguments, environment and working directory for `principal`.
    ///
    /// When the server runs as root, non-root logins are dropped to the
    /// configured user via `runuser -l`, so a normal login never yields a root
    /// shell and starts in that user's home with a login environment.
    fn spawn_for(&self, principal: Principal) -> SpawnSpec {
        self.spawn_spec_as(principal, is_root())
    }

    /// Testable core of [`Self::spawn_for`].
    fn spawn_spec_as(&self, principal: Principal, running_as_root: bool) -> SpawnSpec {
        let shell = self.shell();

        if running_as_root {
            match principal {
                Principal::Root => {
                    let home = home_dir();
                    SpawnSpec {
                        program: shell.clone(),
                        args: Vec::new(),
                        env: user_env("root", &shell, home.as_deref()),
                        cwd: home,
                    }
                }
                Principal::User => SpawnSpec {
                    // `-l` gives the target user its own home, login
                    // environment (HOME/USER/LOGNAME/SHELL/PATH) and shell
                    // defaults. For `exec`, `run_exec` appends `-c <command>`
                    // after the shell argument.
                    program: "runuser".to_string(),
                    args: vec![
                        "-l".to_string(),
                        self.username.clone(),
                        "--".to_string(),
                        shell,
                    ],
                    env: Vec::new(),
                    cwd: None,
                },
            }
        } else {
            let name = current_user_name().unwrap_or_else(|| self.username.clone());
            let home = home_dir();
            SpawnSpec {
                program: shell.clone(),
                args: Vec::new(),
                env: user_env(&name, &shell, home.as_deref()),
                cwd: home,
            }
        }
    }

    /// Whether `principal` needs a privilege-dropped helper for operations
    /// that would otherwise run with the daemon's own credentials.
    ///
    /// File transfer (`rmp cp`) and local forwarding (`-L`) are proxied through
    /// `runuser -l`. Remote forwarding (`-R`) binds high ports in the daemon
    /// (harmless on loopback) but refuses ports below 1024.
    fn privileged_stream_denied(&self, principal: Principal) -> bool {
        self.privileged_stream_denied_as(principal, is_root())
    }

    fn privileged_stream_denied_as(&self, principal: Principal, running_as_root: bool) -> bool {
        running_as_root && principal == Principal::User
    }
}

/// Whether `name` is a supported application protocol version.
fn proto_version_supported(version: u16) -> bool {
    version == rmp_proto::PROTO_VERSION
}

fn command_available(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn runuser_works(user: &str) -> bool {
    std::process::Command::new("runuser")
        .args(["-l", user, "--", "/bin/sh", "-c", "true"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

fn current_user_name() -> Option<String> {
    for var in ["USER", "LOGNAME", "USERNAME"] {
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn user_env(name: &str, shell: &str, home: Option<&std::path::Path>) -> Vec<(String, String)> {
    let mut env = vec![
        ("USER".to_string(), name.to_string()),
        ("LOGNAME".to_string(), name.to_string()),
        ("SHELL".to_string(), shell.to_string()),
    ];
    if let Some(home) = home {
        env.push(("HOME".to_string(), home.to_string_lossy().into_owned()));
    }
    env
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    // Effective UID is the second field of the `Uid:` line in /proc/self/status.
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

#[cfg(unix)]
fn default_shell() -> String {
    "/bin/sh".to_string()
}

#[cfg(windows)]
fn default_shell() -> String {
    "cmd.exe".to_string()
}

/// Build the QUIC server configuration from the options.
pub fn quic_server_config(opts: &ServerOptions) -> Result<quinn::ServerConfig> {
    let tls = crypto::server_config(&opts.host_key).context("building TLS config")?;
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .context("converting TLS config to QUIC")?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(opts.idle_timeout).context("idle timeout")?,
    ));
    transport.keep_alive_interval(Some(opts.keep_alive));
    transport.max_concurrent_bidi_streams(MAX_BIDI_STREAMS.into());
    transport.max_concurrent_uni_streams(0u32.into());
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// Bind a QUIC endpoint for the given options on `addr`.
pub fn bind(addr: SocketAddr, opts: &ServerOptions) -> Result<quinn::Endpoint> {
    opts.check_startup()?;
    let config = quic_server_config(opts)?;
    let endpoint = quinn::Endpoint::server(config, addr)?;
    Ok(endpoint)
}

/// Decrements the live-session counter on drop.
struct SessionGuard<'a>(&'a AtomicUsize);

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Accept connections until the endpoint is closed.
pub async fn serve(endpoint: quinn::Endpoint, opts: Arc<ServerOptions>) -> Result<()> {
    let limiter = Arc::new(AuthLimiter::new(opts.max_auth_attempts, opts.lockout));
    let connections = Arc::new(tokio::sync::Semaphore::new(opts.max_connections));

    info!(addr = ?endpoint.local_addr()?, fingerprint = %opts.host_key.fingerprint(),
          "RMP server listening");

    while let Some(incoming) = endpoint.accept().await {
        // Bound the number of live connections so unauthenticated peers cannot
        // pin an unbounded number of tasks.
        let permit = match connections.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                audit!(event = "connection.refused", reason = "max_connections");
                incoming.refuse();
                continue;
            }
        };
        let opts = opts.clone();
        let limiter = limiter.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let conn = match incoming.accept() {
                Ok(connecting) => match connecting.await {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!(error = %e, "failed to establish connection");
                        return;
                    }
                },
                Err(e) => {
                    warn!(error = %e, "failed to accept connection");
                    return;
                }
            };
            let peer = conn.remote_address();

            // Access control (allow/deny lists) before anything else.
            if !crate::net::is_allowed(peer.ip(), &opts.allowed_cidrs, &opts.denied_cidrs) {
                audit!(event = "connection.denied", peer = %peer);
                conn.close(0u32.into(), b"not allowed");
                return;
            }

            if let Err(e) = handle_connection(conn, opts, limiter, peer).await {
                warn!(%peer, error = %e, "connection ended with error");
            }
        });
    }
    Ok(())
}

async fn handle_connection(
    conn: quinn::Connection,
    opts: Arc<ServerOptions>,
    limiter: Arc<AuthLimiter>,
    peer: SocketAddr,
) -> Result<()> {
    let (mut send, mut recv) = tokio::time::timeout(CONTROL_STREAM_TIMEOUT, conn.accept_bi())
        .await
        .context("timed out waiting for the control stream")?
        .context("accepting control stream")?;

    // Application handshake.
    let hello = tokio::time::timeout(CONTROL_STREAM_TIMEOUT, rmp_proto::read_message(&mut recv))
        .await
        .context("timed out reading Hello")?
        .context("reading Hello")?;
    let Message::Hello(hello) = hello else {
        anyhow::bail!("expected Hello, got {:?}", hello.frame_type());
    };

    if !proto_version_supported(hello.proto_version) {
        audit!(
            event = "handshake.refused",
            peer = %peer,
            proto_version = hello.proto_version,
            server_version = rmp_proto::PROTO_VERSION
        );
        let _ = rmp_proto::write_message(
            &mut send,
            &Message::Disconnect(Disconnect {
                reason: DisconnectReason::ProtocolError,
                message: format!(
                    "unsupported protocol version {} (server supports {})",
                    hello.proto_version,
                    rmp_proto::PROTO_VERSION
                ),
            }),
        )
        .await;
        conn.close(0u32.into(), b"protocol version mismatch");
        return Ok(());
    }

    info!(%peer, client = %hello.client_name, "client connected");
    audit!(
        event = "handshake.ok",
        peer = %peer,
        client = %hello.client_name,
        client_version = %hello.client_version,
        proto_version = hello.proto_version
    );

    let ack = Message::HelloAck(rmp_proto::HelloAck {
        proto_version: rmp_proto::PROTO_VERSION,
        server_name: "rmp".to_string(),
        server_version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![0, 1, 2],
    });
    rmp_proto::write_message(&mut send, &ack).await?;

    // Authentication. A failed attempt must not keep the connection (and its
    // task) alive until the QUIC idle timeout.
    let authed = tokio::time::timeout(
        AUTH_TIMEOUT,
        auth::authenticate(&mut send, &mut recv, &opts, &limiter, peer),
    )
    .await
    .context("authentication timed out")??;
    let Some(authed) = authed else {
        conn.close(0u32.into(), b"authentication failed");
        return Ok(());
    };

    // Serve streams (sessions and forwards) until the connection closes.
    // Control requests (e.g. remote-forward binds) are handled concurrently.
    let ctrl_opts = opts.clone();
    let ctrl_conn = conn.clone();
    let ctrl_principal = authed.principal;
    tokio::spawn(async move {
        if let Err(e) = control_loop(send, recv, ctrl_opts, ctrl_conn, peer, ctrl_principal).await {
            tracing::debug!(%peer, error = %e, "control loop ended");
        }
    });

    let mut tasks = tokio::task::JoinSet::new();
    while let Ok((send, recv)) = conn.accept_bi().await {
        let opts = opts.clone();
        let authed = authed.clone();
        tasks.spawn(async move {
            if let Err(e) = handle_stream(send, recv, opts, authed, peer).await {
                warn!(%peer, error = %e, "stream ended with error");
            }
        });
    }
    while tasks.join_next().await.is_some() {}

    if let Some(reason) = conn.close_reason() {
        tracing::info!(%peer, reason = %reason, "connection closed");
    }
    audit!(event = "connection.close", peer = %peer);
    Ok(())
}

async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    opts: Arc<ServerOptions>,
    authed: Authed,
    peer: SocketAddr,
) -> Result<()> {
    let first = rmp_proto::read_message(&mut recv)
        .await
        .context("reading stream request")?;

    match first {
        Message::PtyRequest(req) => {
            let Some(_guard) = acquire_session(&opts) else {
                audit!(event = "session.refused", peer = %peer, reason = "max_sessions");
                return Ok(());
            };
            let spec = opts.spawn_for(authed.principal);
            audit!(event = "session.open", peer = %peer, kind = "pty",
                   as_root = matches!(authed.principal, Principal::Root),
                   term = %req.term, cols = req.cols, rows = req.rows);
            let code =
                session::run_pty(&mut send, &mut recv, req, &spec, opts.motd.as_deref()).await?;
            audit!(event = "session.close", peer = %peer, kind = "pty", exit_code = code);
        }
        Message::Exec(exec) => {
            let Some(_guard) = acquire_session(&opts) else {
                audit!(event = "session.refused", peer = %peer, reason = "max_sessions");
                return Ok(());
            };
            let spec = opts.spawn_for(authed.principal);
            let logged = if opts.log_commands {
                exec.command.clone()
            } else {
                "<redacted>".to_string()
            };
            audit!(event = "session.open", peer = %peer, kind = "exec",
                   as_root = matches!(authed.principal, Principal::Root), command = %logged);
            let code = session::run_exec(&mut send, &mut recv, &exec.command, &spec).await?;
            audit!(event = "session.close", peer = %peer, kind = "exec", exit_code = code);
        }
        Message::ForwardRequest(req) => {
            if !opts.allow_local_forward {
                audit!(event = "forward.refused", peer = %peer, reason = "disabled");
                let _ = rmp_proto::write_message(
                    &mut send,
                    &Message::ForwardResponse(rmp_proto::ForwardResponse {
                        ok: false,
                        reason: Some("forwarding is disabled".into()),
                    }),
                )
                .await;
                return Ok(());
            }
            // Forwarding dials from the server process. In root mode, run it
            // through a helper as the target user instead of handing a normal
            // login the daemon's network privileges.
            if opts.privileged_stream_denied(authed.principal) {
                audit!(event = "forward.proxy", peer = %peer,
                       target = %format!("{}:{}", req.host, req.port));
                return run_as_user_helper(send, recv, &opts, Message::ForwardRequest(req), peer)
                    .await;
            }
            crate::forward::serve(send, recv, req, peer).await?;
        }
        Message::FileRequest(req) => {
            if !opts.allow_file_transfer {
                audit!(event = "file.refused", peer = %peer, reason = "disabled");
                let _ = rmp_proto::write_message(
                    &mut send,
                    &Message::FileResponse(rmp_proto::FileResponse {
                        ok: false,
                        size: 0,
                        reason: Some("file transfer is disabled".into()),
                        mode: 0,
                    }),
                )
                .await;
                return Ok(());
            }
            // File I/O runs with the daemon's credentials. In root mode, run it
            // through a helper as the target user so a normal login cannot
            // read/write root files.
            if opts.privileged_stream_denied(authed.principal) {
                audit!(event = "file.proxy", peer = %peer, path = %req.path);
                return run_as_user_helper(send, recv, &opts, Message::FileRequest(req), peer)
                    .await;
            }
            crate::files::serve(send, recv, req, peer).await?;
        }
        other => {
            anyhow::bail!("unexpected stream request: {:?}", other.frame_type());
        }
    }
    Ok(())
}

/// Relay a file/forward stream to a helper process running as the target user.
///
/// The server has already read the first request. The helper (the same `rmp`
/// binary, launched through `runuser -l`) reads it from stdin and serves it,
/// writing framed responses to stdout. Raw byte relays avoid duplicating the
/// file/forward logic in the daemon.
async fn run_as_user_helper(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    opts: &ServerOptions,
    first: Message,
    peer: SocketAddr,
) -> Result<()> {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            send_helper_error(&mut send, &first, &format!("helper path: {e}")).await;
            return Ok(());
        }
    };

    let mut cmd = tokio::process::Command::new("runuser");
    cmd.arg("-l")
        .arg(&opts.username)
        .arg("--")
        .arg(&exe)
        .arg("__helper")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            send_helper_error(&mut send, &first, &format!("cannot start helper: {e}")).await;
            return Ok(());
        }
    };

    let Some(mut helper_in) = child.stdin.take() else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        send_helper_error(&mut send, &first, "helper has no stdin").await;
        return Ok(());
    };
    let Some(mut helper_out) = child.stdout.take() else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        send_helper_error(&mut send, &first, "helper has no stdout").await;
        return Ok(());
    };

    if let Err(e) = rmp_proto::write_message(&mut helper_in, &first).await {
        let _ = child.kill().await;
        let _ = child.wait().await;
        send_helper_error(&mut send, &first, &format!("helper handshake failed: {e}")).await;
        return Ok(());
    }

    let to_helper = async {
        tokio::io::copy(&mut recv, &mut helper_in).await?;
        let _ = helper_in.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };
    let to_client = async {
        tokio::io::copy(&mut helper_out, &mut send).await?;
        let _ = send.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };
    let mut to_helper = Box::pin(to_helper);
    let mut to_client = Box::pin(to_client);

    let outcome = tokio::select! {
        result = &mut to_client => result,
        result = &mut to_helper => match result {
            // The client half-closed; keep relaying the helper's remaining
            // output (Get responses, EOF, final status).
            Ok(()) => (&mut to_client).await,
            Err(e) => Err(e),
        },
    };

    // Dropping the unfinished relay closes the helper's pipes, so `wait` cannot
    // block on a child still holding stdin open.
    drop(to_helper);
    drop(to_client);

    match child.wait().await {
        Ok(status) if status.success() => {}
        Ok(status) => {
            warn!(%peer, ?status, "user helper exited with an error");
            audit!(event = "helper.failed", peer = %peer);
        }
        Err(e) => warn!(%peer, error = %e, "waiting for user helper"),
    }

    outcome
}

/// Send a protocol-level refusal when the helper cannot be started.
async fn send_helper_error(send: &mut quinn::SendStream, first: &Message, reason: &str) {
    let response = match first {
        Message::FileRequest(_) => Message::FileResponse(rmp_proto::FileResponse {
            ok: false,
            size: 0,
            reason: Some(reason.to_string()),
            mode: 0,
        }),
        Message::ForwardRequest(_) => Message::ForwardResponse(rmp_proto::ForwardResponse {
            ok: false,
            reason: Some(reason.to_string()),
        }),
        _ => return,
    };
    let _ = rmp_proto::write_message(send, &response).await;
}

/// Reserve a session slot, or return `None` if the limit is reached.
fn acquire_session(opts: &ServerOptions) -> Option<SessionGuard<'_>> {
    let already = opts.sessions.fetch_add(1, Ordering::SeqCst);
    if already >= opts.max_sessions {
        opts.sessions.fetch_sub(1, Ordering::SeqCst);
        None
    } else {
        Some(SessionGuard(&opts.sessions))
    }
}

/// Handle post-authentication control-stream requests.
async fn control_loop(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    opts: Arc<ServerOptions>,
    conn: quinn::Connection,
    peer: SocketAddr,
    principal: Principal,
) -> Result<()> {
    while let Ok(msg) = rmp_proto::read_message(&mut recv).await {
        match msg {
            Message::Ping(ping) => {
                rmp_proto::write_message(
                    &mut send,
                    &Message::Pong(rmp_proto::Pong { nonce: ping.nonce }),
                )
                .await?;
            }
            Message::RemoteForwardBind(req) => {
                handle_remote_bind(&mut send, &opts, &conn, peer, req, principal).await?;
            }
            Message::Disconnect(_) => break,
            _ => {}
        }
    }
    Ok(())
}

/// Bind a server-side listener for a `-R` request and forward connections back
/// to the client.
async fn handle_remote_bind(
    send: &mut quinn::SendStream,
    opts: &ServerOptions,
    conn: &quinn::Connection,
    peer: SocketAddr,
    req: rmp_proto::RemoteForwardBind,
    principal: Principal,
) -> Result<()> {
    use tokio::net::TcpListener;

    if !opts.allow_remote_forward {
        audit!(event = "remote_forward.refused", peer = %peer, reason = "disabled");
        rmp_proto::write_message(
            send,
            &Message::RemoteForwardBindResult(rmp_proto::RemoteForwardBindResult {
                ok: false,
                bound_port: 0,
                reason: Some("remote forwarding is disabled".into()),
            }),
        )
        .await?;
        return Ok(());
    }

    // A normal login must not make the root daemon bind privileged ports.
    // High ports on loopback are harmless: the same user could bind them
    // directly, and no root file/network capability is involved.
    if opts.privileged_stream_denied(principal)
        && req.bind_port != 0
        && req.bind_port < 1024
        && !opts.allow_privileged_ports
    {
        audit!(event = "remote_forward.refused", peer = %peer, reason = "privileged_port");
        rmp_proto::write_message(
            send,
            &Message::RemoteForwardBindResult(rmp_proto::RemoteForwardBindResult {
                ok: false,
                bound_port: 0,
                reason: Some(
                    "ports below 1024 are unavailable for non-root logins while the server runs as root (set [server] allow_privileged_ports = true to opt in)"
                        .into(),
                ),
            }),
        )
        .await?;
        return Ok(());
    }

    // Bind on loopback only, so a client cannot expose the machine on the LAN.
    let addr = SocketAddr::from(([127, 0, 0, 1], req.bind_port));
    match TcpListener::bind(addr).await {
        Ok(listener) => {
            let bound = listener
                .local_addr()
                .map(|a| a.port())
                .unwrap_or(req.bind_port);
            rmp_proto::write_message(
                send,
                &Message::RemoteForwardBindResult(rmp_proto::RemoteForwardBindResult {
                    ok: true,
                    bound_port: bound,
                    reason: None,
                }),
            )
            .await?;
            audit!(event = "remote_forward.open", peer = %peer, bound_port = bound,
                   target = %format!("{}:{}", req.target_host, req.target_port));

            let conn = conn.clone();
            let host = req.target_host.clone();
            let port = req.target_port;
            tokio::spawn(async move {
                let closed = conn.closed();
                tokio::pin!(closed);
                loop {
                    tokio::select! {
                        _ = &mut closed => break,
                        accepted = listener.accept() => {
                            let Ok((tcp, _)) = accepted else { break };
                            let conn = conn.clone();
                            let host = host.clone();
                            tokio::spawn(async move {
                                if let Err(e) = serve_remote_conn(conn, tcp, host, port).await {
                                    tracing::debug!("remote forward connection ended: {e}");
                                }
                            });
                        }
                    }
                }
                // Drop the listener, releasing the port when the connection ends.
                audit!(event = "remote_forward.close", peer = %peer, bound_port = bound);
            });
            Ok(())
        }
        Err(e) => {
            audit!(event = "remote_forward.refused", peer = %peer, reason = %e);
            rmp_proto::write_message(
                send,
                &Message::RemoteForwardBindResult(rmp_proto::RemoteForwardBindResult {
                    ok: false,
                    bound_port: 0,
                    reason: Some(e.to_string()),
                }),
            )
            .await?;
            Ok(())
        }
    }
}

/// Offer a server-side TCP connection to the client, which dials the target.
async fn serve_remote_conn(
    conn: quinn::Connection,
    tcp: tokio::net::TcpStream,
    host: String,
    port: u16,
) -> Result<()> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("opening remote forward stream")?;
    rmp_proto::write_message(
        &mut send,
        &Message::ForwardRequest(rmp_proto::ForwardRequest { host, port }),
    )
    .await?;
    match rmp_proto::read_message(&mut recv).await? {
        Message::ForwardResponse(rmp_proto::ForwardResponse { ok: true, .. }) => {}
        Message::ForwardResponse(rmp_proto::ForwardResponse { ok: false, reason }) => {
            anyhow::bail!("client refused forward: {}", reason.unwrap_or_default());
        }
        other => anyhow::bail!("unexpected forward response: {:?}", other.frame_type()),
    }
    crate::forward::pipe(tcp, send, recv).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmp_crypto::password;

    fn options() -> ServerOptions {
        let setup = password::new_setup();
        let file = password::enroll(b"pw", "alice", &setup).unwrap();
        ServerOptions::new(
            "alice".to_string(),
            HostKey::generate().unwrap(),
            setup,
            file,
        )
    }

    #[test]
    fn non_root_spawn_uses_process_environment_and_home() {
        let opts = options();
        let spec = opts.spawn_spec_as(Principal::User, false);

        assert!(!spec.program.is_empty());
        assert!(spec.args.is_empty());
        assert!(spec
            .env
            .iter()
            .any(|(key, value)| key == "SHELL" && value == &spec.program));
        assert!(spec.env.iter().any(|(key, _)| key == "USER"));
        if let Some(home) = home_dir() {
            assert_eq!(spec.cwd.as_deref(), Some(home.as_path()));
            assert!(spec
                .env
                .iter()
                .any(|(key, value)| key == "HOME"
                    && value.as_str() == home.to_string_lossy().as_ref()));
        }
    }

    #[test]
    fn root_mode_drops_non_root_logins_with_runuser() {
        let opts = options();
        let spec = opts.spawn_spec_as(Principal::User, true);
        let shell = opts.shell();

        assert_eq!(spec.program, "runuser");
        assert_eq!(&spec.args[..3], ["-l", "alice", "--"]);
        assert_eq!(spec.args.last().map(String::as_str), Some(shell.as_str()));
        assert!(spec.env.is_empty(), "runuser -l sets the login environment");
        assert!(spec.cwd.is_none(), "runuser -l changes to the user's home");
    }

    #[test]
    fn root_login_keeps_root_environment() {
        let opts = options();
        let spec = opts.spawn_spec_as(Principal::Root, true);

        assert_ne!(spec.program, "runuser");
        assert!(spec
            .env
            .iter()
            .any(|(key, value)| key == "USER" && value == "root"));
        assert!(spec
            .env
            .iter()
            .any(|(key, value)| key == "LOGNAME" && value == "root"));
    }

    #[test]
    fn non_root_principals_cannot_use_privileged_streams_in_root_mode() {
        let opts = options();
        assert!(opts.privileged_stream_denied_as(Principal::User, true));
        assert!(!opts.privileged_stream_denied_as(Principal::Root, true));
        assert!(!opts.privileged_stream_denied_as(Principal::User, false));
    }

    #[test]
    fn protocol_version_must_match() {
        assert!(proto_version_supported(rmp_proto::PROTO_VERSION));
        assert!(!proto_version_supported(rmp_proto::PROTO_VERSION + 1));
        assert!(!proto_version_supported(0));
    }

    #[test]
    fn startup_rejects_root_as_the_normal_account() {
        let mut opts = options();
        opts.username = "root".to_string();
        assert!(opts.check_startup().is_err());
    }

    #[test]
    fn startup_rejects_zero_connection_limit() {
        let mut opts = options();
        opts.max_connections = 0;
        assert!(opts.check_startup().is_err());
    }

    #[test]
    fn valid_options_pass_startup_checks() {
        assert!(options().check_startup().is_ok());
    }
}
