//! Server configuration and QUIC listener.

use crate::audit::audit;
use crate::auth::{self, AuthLimiter, Authed, Principal};
use crate::net::Cidr;
use crate::session;
use anyhow::{Context, Result};
use rmp_crypto::{self as crypto, HostKey};
use rmp_proto::Message;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

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
    /// Optional registration record for the `root` account.
    pub root_password_file: Option<crypto::PasswordFile>,
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
    /// Allow file transfer (`rmp cp`).
    pub allow_file_transfer: bool,
    /// Maximum number of concurrent sessions.
    pub max_sessions: usize,
    /// Live session counter.
    sessions: AtomicUsize,
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
            root_password_file: None,
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
            allow_file_transfer: true,
            max_sessions: 8,
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

    /// Fail fast on insecure or impossible configurations.
    pub fn check_startup(&self) -> Result<()> {
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
        }
        if self.max_sessions == 0 {
            anyhow::bail!("server.max_sessions must be greater than zero");
        }
        Ok(())
    }

    /// Program and base arguments used to spawn a shell for `principal`.
    ///
    /// When the server runs as root, non-root logins are dropped to the
    /// configured user via `runuser`, so a normal login never yields a root
    /// shell.
    fn spawn_for(&self, principal: Principal) -> (String, Vec<String>) {
        let shell = self.shell();
        if is_root() {
            match principal {
                Principal::Root => (shell, Vec::new()),
                Principal::User => (
                    "runuser".to_string(),
                    vec![
                        "-u".to_string(),
                        self.username.clone(),
                        "--".to_string(),
                        shell,
                    ],
                ),
            }
        } else {
            (shell, Vec::new())
        }
    }
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

    info!(addr = ?endpoint.local_addr()?, fingerprint = %opts.host_key.fingerprint(),
          "RMP server listening");

    while let Some(incoming) = endpoint.accept().await {
        let opts = opts.clone();
        let limiter = limiter.clone();
        tokio::spawn(async move {
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
    let (mut send, mut recv) = conn.accept_bi().await.context("accepting control stream")?;

    // Application handshake.
    let hello = rmp_proto::read_message(&mut recv)
        .await
        .context("reading Hello")?;
    let Message::Hello(hello) = hello else {
        anyhow::bail!("expected Hello, got {:?}", hello.frame_type());
    };
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

    // Authentication.
    let authed = auth::authenticate(&mut send, &mut recv, &opts, &limiter, peer).await?;
    let Some(authed) = authed else {
        let _ = conn.closed().await;
        return Ok(());
    };

    // Serve streams (sessions and forwards) until the connection closes.
    // Control requests (e.g. remote-forward binds) are handled concurrently.
    let ctrl_opts = opts.clone();
    let ctrl_conn = conn.clone();
    tokio::spawn(async move {
        if let Err(e) = control_loop(send, recv, ctrl_opts, ctrl_conn, peer).await {
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
            let (program, args) = opts.spawn_for(authed.principal);
            audit!(event = "session.open", peer = %peer, kind = "pty",
                   as_root = matches!(authed.principal, Principal::Root),
                   term = %req.term, cols = req.cols, rows = req.rows);
            let code = session::run_pty(
                &mut send,
                &mut recv,
                req,
                &program,
                &args,
                opts.motd.as_deref(),
            )
            .await?;
            audit!(event = "session.close", peer = %peer, kind = "pty", exit_code = code);
        }
        Message::Exec(exec) => {
            let Some(_guard) = acquire_session(&opts) else {
                audit!(event = "session.refused", peer = %peer, reason = "max_sessions");
                return Ok(());
            };
            let (program, args) = opts.spawn_for(authed.principal);
            let logged = if opts.log_commands {
                exec.command.clone()
            } else {
                "<redacted>".to_string()
            };
            audit!(event = "session.open", peer = %peer, kind = "exec",
                   as_root = matches!(authed.principal, Principal::Root), command = %logged);
            let code =
                session::run_exec(&mut send, &mut recv, &exec.command, &program, &args).await?;
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
                    }),
                )
                .await;
                return Ok(());
            }
            crate::files::serve(send, recv, req, peer).await?;
        }
        other => {
            anyhow::bail!("unexpected stream request: {:?}", other.frame_type());
        }
    }
    Ok(())
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
) -> Result<()> {
    while let Ok(msg) = rmp_proto::read_message(&mut recv).await {
        match msg {
            Message::RemoteForwardBind(req) => {
                handle_remote_bind(&mut send, &opts, &conn, peer, req).await?;
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
                while let Ok((tcp, _)) = listener.accept().await {
                    let conn = conn.clone();
                    let host = host.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_remote_conn(conn, tcp, host, port).await {
                            tracing::debug!("remote forward connection ended: {e}");
                        }
                    });
                }
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
