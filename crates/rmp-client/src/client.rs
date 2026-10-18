//! RMP client: connect, authenticate and drive sessions.

use crate::term;
use anyhow::{bail, Context, Result};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rmp_crypto::{self as crypto, DeviceKey, Fingerprint, ObservedFingerprint};
use rmp_proto::{
    key_auth_context, AuthFinish, AuthResponse, AuthResult, AuthStart, Data, Exec, ExitStatus,
    FileEntry, FileOp, FileRequest, Hello, HelloAck, KeyAuthChallenge, KeyAuthProof,
    KeyAuthRequest, Message, Ping, Pong, PtyRequest, RemoteForwardBind, WindowChange,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;

/// Parameters for establishing a client connection.
pub struct ClientOptions {
    pub server_addr: SocketAddr,
    /// Name used for SNI and as the `known_hosts` key.
    pub server_name: String,
    pub idle_timeout: Duration,
    pub keep_alive: Duration,
    /// When `Some`, only this certificate fingerprint is accepted.
    pub expected_fingerprint: Option<Fingerprint>,
}

/// Build the QUIC client configuration.
pub fn quic_client_config(
    idle_timeout: Duration,
    keep_alive: Duration,
) -> Result<(quinn::ClientConfig, ObservedFingerprint)> {
    let (tls, observed) = crypto::client_config()?;
    let quic_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).context("QUIC client TLS")?;
    let mut config = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(idle_timeout).context("idle timeout")?,
    ));
    transport.keep_alive_interval(Some(keep_alive));
    config.transport_config(Arc::new(transport));
    Ok((config, observed))
}

/// Establish the encrypted transport (TLS handshake only, no authentication).
pub async fn transport(opts: &ClientOptions) -> Result<Transport> {
    let bind: SocketAddr = if opts.server_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = Endpoint::client(bind).context("creating client endpoint")?;
    let (config, observed) = quic_client_config(opts.idle_timeout, opts.keep_alive)?;
    endpoint.set_default_client_config(config);

    let conn = endpoint
        .connect(opts.server_addr, &opts.server_name)
        .context("initiating QUIC connection")?
        .await
        .context("QUIC/TLS handshake")?;

    // Pin the certificate *after* the handshake and *before* returning the
    // transport. No credential is sent before this check, so a changed host key
    // is still a hard failure — but now with an actionable message.
    if let Some(expected) = opts.expected_fingerprint {
        let actual = observed
            .get()
            .context("server did not present a certificate")?;
        if actual != expected {
            bail!(
                "HOST KEY MISMATCH for {}!\n  expected: {expected}\n  received: {actual}\n\
                 This may indicate a man-in-the-middle attack. Connection aborted.\n\
                 If the server host key was changed intentionally, update the \
                 `known_hosts` entry (or use --update-host-key).",
                opts.server_name
            );
        }
    }

    info!(addr = %conn.remote_address(), "transport established");
    Ok(Transport {
        endpoint,
        conn,
        observed,
    })
}

/// An established, unauthenticated transport.
pub struct Transport {
    endpoint: Endpoint,
    conn: Connection,
    observed: ObservedFingerprint,
}

impl Transport {
    /// The fingerprint the server presented, if the handshake completed.
    pub fn observed_fingerprint(&self) -> Option<Fingerprint> {
        self.observed.get()
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// Authenticate with a password, optionally enrolling `enroll_public_key`.
    pub async fn authenticate_password(
        self,
        username: &str,
        password: &[u8],
        enroll_public_key: Option<Vec<u8>>,
    ) -> Result<Client> {
        let Transport {
            endpoint,
            conn,
            observed,
        } = self;
        let (mut send, mut recv) = Client::open_control(&conn).await?;

        let (initial, state) =
            crypto::password::client_start(password).context("OPAQUE client_start")?;
        rmp_proto::write_message(
            &mut send,
            &Message::AuthStart(AuthStart {
                username: username.to_string(),
                initial,
            }),
        )
        .await?;

        let response = rmp_proto::read_message(&mut recv).await?;
        let Message::AuthResponse(AuthResponse { payload }) = response else {
            bail!("expected AuthResponse, got {:?}", response.frame_type());
        };

        let (finalization, _session_key) =
            crypto::password::client_finish(state, &payload, password)?;

        rmp_proto::write_message(
            &mut send,
            &Message::AuthFinish(AuthFinish {
                payload: finalization,
                device_pubkey: enroll_public_key,
            }),
        )
        .await?;

        let result = rmp_proto::read_message(&mut recv).await?;
        let Message::AuthResult(AuthResult {
            ok,
            reason,
            key_enrolled,
            ..
        }) = result
        else {
            bail!("expected AuthResult, got {:?}", result.frame_type());
        };
        if !ok {
            bail!("authentication rejected: {reason:?}");
        }
        Client::finish(endpoint, conn, send, recv, observed, key_enrolled, username).await
    }

    /// Authenticate with a device key (passwordless).
    pub async fn authenticate_key(self, username: &str, device_key: &DeviceKey) -> Result<Client> {
        let Transport {
            endpoint,
            conn,
            observed,
        } = self;
        let (mut send, mut recv) = Client::open_control(&conn).await?;
        let public_key = device_key.public_key();

        rmp_proto::write_message(
            &mut send,
            &Message::KeyAuthRequest(KeyAuthRequest {
                username: username.to_string(),
                public_key: public_key.clone(),
            }),
        )
        .await?;

        let challenge = rmp_proto::read_message(&mut recv).await?;
        let Message::KeyAuthChallenge(KeyAuthChallenge { nonce }) = challenge else {
            bail!(
                "expected KeyAuthChallenge, got {:?}",
                challenge.frame_type()
            );
        };

        let context = key_auth_context(username, &public_key, &nonce);
        let signature = device_key.sign(&context);
        rmp_proto::write_message(
            &mut send,
            &Message::KeyAuthProof(KeyAuthProof { signature }),
        )
        .await?;

        let result = rmp_proto::read_message(&mut recv).await?;
        let Message::AuthResult(AuthResult { ok, reason, .. }) = result else {
            bail!("expected AuthResult, got {:?}", result.frame_type());
        };
        if !ok {
            bail!("device key rejected: {reason:?}");
        }
        Client::finish(endpoint, conn, send, recv, observed, false, username).await
    }
}

/// An authenticated client, holding the control stream open.
pub struct Client {
    _endpoint: Endpoint,
    conn: Connection,
    ctrl_send: SendStream,
    ctrl_recv: RecvStream,
    observed: Option<Fingerprint>,
    key_enrolled: bool,
}

/// Output of a non-interactive command.
pub struct ExecOutput {
    pub data: Vec<u8>,
    pub exit_code: u32,
}

impl Client {
    /// Open the control stream and perform the application handshake.
    async fn open_control(conn: &Connection) -> Result<(SendStream, RecvStream)> {
        let (mut send, mut recv) = conn.open_bi().await.context("opening control stream")?;
        rmp_proto::write_message(
            &mut send,
            &Message::Hello(Hello {
                proto_version: rmp_proto::PROTO_VERSION,
                client_name: "rmp".to_string(),
                client_version: env!("CARGO_PKG_VERSION").to_string(),
            }),
        )
        .await
        .context("sending Hello")?;

        let ack = rmp_proto::read_message(&mut recv)
            .await
            .context("reading HelloAck")?;
        let Message::HelloAck(HelloAck { proto_version, .. }) = ack else {
            bail!("expected HelloAck, got {:?}", ack.frame_type());
        };
        if proto_version != rmp_proto::PROTO_VERSION {
            bail!(
                "protocol version mismatch: server={proto_version}, client={}",
                rmp_proto::PROTO_VERSION
            );
        }
        Ok((send, recv))
    }

    async fn finish(
        endpoint: Endpoint,
        conn: Connection,
        send: SendStream,
        recv: RecvStream,
        observed: ObservedFingerprint,
        key_enrolled: bool,
        username: &str,
    ) -> Result<Client> {
        info!(user = username, "authenticated");
        Ok(Client {
            _endpoint: endpoint,
            conn,
            ctrl_send: send,
            ctrl_recv: recv,
            observed: observed.get(),
            key_enrolled,
        })
    }

    /// Connect and authenticate with a password.
    pub async fn connect(opts: &ClientOptions, username: &str, password: &[u8]) -> Result<Client> {
        transport(opts)
            .await?
            .authenticate_password(username, password, None)
            .await
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// The fingerprint the server presented.
    pub fn observed_fingerprint(&self) -> Option<Fingerprint> {
        self.observed
    }

    /// Whether a device key was enrolled during this connection.
    pub fn key_enrolled(&self) -> bool {
        self.key_enrolled
    }

    /// Ask the server to listen on `bind_port` and forward connections back to
    /// this client, which will dial `host:port`. Returns the bound port.
    pub async fn request_remote_forward(
        &mut self,
        bind_port: u16,
        host: &str,
        port: u16,
    ) -> Result<u16> {
        rmp_proto::write_message(
            &mut self.ctrl_send,
            &Message::RemoteForwardBind(RemoteForwardBind {
                bind_port,
                target_host: host.to_string(),
                target_port: port,
            }),
        )
        .await?;
        match rmp_proto::read_message(&mut self.ctrl_recv).await? {
            Message::RemoteForwardBindResult(r) if r.ok => Ok(r.bound_port),
            Message::RemoteForwardBindResult(r) => {
                bail!("remote forward refused: {}", r.reason.unwrap_or_default())
            }
            other => bail!("unexpected response: {:?}", other.frame_type()),
        }
    }

    /// Send a control-stream `Ping` and wait for the matching `Pong`.
    ///
    /// This is also used by integration tests to verify the server's
    /// application-level keepalive handling.
    pub async fn ping(&mut self, nonce: u64) -> Result<u64> {
        rmp_proto::write_message(&mut self.ctrl_send, &Message::Ping(Ping { nonce }))
            .await
            .context("sending Ping")?;
        loop {
            match rmp_proto::read_message(&mut self.ctrl_recv).await {
                Ok(Message::Pong(Pong { nonce })) => return Ok(nonce),
                Ok(Message::Ping(Ping { nonce })) => {
                    let _ = rmp_proto::write_message(
                        &mut self.ctrl_send,
                        &Message::Pong(Pong { nonce }),
                    )
                    .await;
                }
                Ok(_) => {}
                Err(rmp_proto::StreamError::Closed) => {
                    bail!("control stream closed before Pong")
                }
                Err(e) => return Err(e).context("reading Pong"),
            }
        }
    }

    /// Run a command and collect all output.
    pub async fn exec(&self, command: &str) -> Result<ExecOutput> {
        let (mut send, mut recv) = self.conn.open_bi().await.context("opening session")?;
        rmp_proto::write_message(
            &mut send,
            &Message::Exec(Exec {
                command: command.to_string(),
            }),
        )
        .await?;

        let mut data = Vec::new();
        loop {
            match rmp_proto::read_message(&mut recv).await {
                Ok(Message::Data(d)) => data.extend_from_slice(&d.data),
                Ok(Message::ExitStatus(ExitStatus { exit_code, .. })) => {
                    let _ = send.finish();
                    return Ok(ExecOutput { data, exit_code });
                }
                Err(rmp_proto::StreamError::Closed) => {
                    bail!("connection closed before the command reported an exit status");
                }
                Err(e) => return Err(e).context("reading exec output"),
                Ok(_) => {}
            }
        }
    }

    /// Run a script through an interactive PTY session and collect the output.
    pub async fn pty_capture(&self, script: &str) -> Result<ExecOutput> {
        let (mut send, mut recv) = self.conn.open_bi().await.context("opening pty session")?;
        rmp_proto::write_message(
            &mut send,
            &Message::PtyRequest(PtyRequest {
                term: "xterm-256color".to_string(),
                cols: 80,
                rows: 24,
                pixel_w: 0,
                pixel_h: 0,
                modes: Vec::new(),
            }),
        )
        .await?;
        rmp_proto::write_message(&mut send, &Message::Shell).await?;

        let mut input = script.as_bytes().to_vec();
        if !input.ends_with(b"\n") {
            input.push(b'\n');
        }
        rmp_proto::write_message(&mut send, &Message::Data(Data { data: input })).await?;

        let mut data = Vec::new();
        loop {
            match rmp_proto::read_message(&mut recv).await {
                Ok(Message::Data(d)) => data.extend_from_slice(&d.data),
                Ok(Message::ExitStatus(ExitStatus { exit_code, .. })) => {
                    let _ = send.finish();
                    return Ok(ExecOutput { data, exit_code });
                }
                Err(rmp_proto::StreamError::Closed) => {
                    bail!("connection closed before the shell reported an exit status");
                }
                Err(e) => return Err(e).context("reading pty output"),
                Ok(_) => {}
            }
        }
    }

    /// Create `remote` (and its parents) as a directory.
    pub async fn mkdir(&self, remote: &str, mode: u32) -> Result<()> {
        let (mut send, mut recv) = self.conn.open_bi().await.context("opening file stream")?;
        rmp_proto::write_message(
            &mut send,
            &Message::FileRequest(FileRequest {
                op: FileOp::Mkdir,
                path: remote.to_string(),
                mode,
                size: 0,
            }),
        )
        .await?;

        match rmp_proto::read_message(&mut recv).await? {
            Message::FileResponse(r) if r.ok => {}
            Message::FileResponse(r) => {
                bail!("remote refused mkdir: {}", r.reason.unwrap_or_default())
            }
            other => bail!("unexpected response: {:?}", other.frame_type()),
        }
        match rmp_proto::read_message(&mut recv).await? {
            Message::ExitStatus(s) if s.exit_code == 0 => Ok(()),
            Message::ExitStatus(s) => bail!("remote mkdir failed (exit {})", s.exit_code),
            other => bail!("unexpected response: {:?}", other.frame_type()),
        }
    }

    /// List a remote directory.
    pub async fn list(&self, remote: &str) -> Result<Vec<FileEntry>> {
        let (mut send, mut recv) = self.conn.open_bi().await.context("opening file stream")?;
        rmp_proto::write_message(
            &mut send,
            &Message::FileRequest(FileRequest {
                op: FileOp::List,
                path: remote.to_string(),
                mode: 0,
                size: 0,
            }),
        )
        .await?;

        match rmp_proto::read_message(&mut recv).await? {
            Message::FileResponse(r) if r.ok => {}
            Message::FileResponse(r) => {
                bail!("remote refused listing: {}", r.reason.unwrap_or_default())
            }
            other => bail!("unexpected response: {:?}", other.frame_type()),
        }

        let mut entries = Vec::new();
        loop {
            match rmp_proto::read_message(&mut recv).await {
                Ok(Message::FileEntry(entry)) => entries.push(entry),
                Ok(Message::Eof) => break,
                Err(rmp_proto::StreamError::Closed) => {
                    bail!("connection closed before the directory listing finished")
                }
                Ok(_) => {}
                Err(e) => return Err(e).context("reading directory listing"),
            }
        }
        Ok(entries)
    }

    /// Download `remote` to the local path `local`. Returns bytes written.
    ///
    /// The data is written to a sibling temporary file and only renamed into
    /// place after the server sends `Eof`. A dropped connection therefore never
    /// looks like a successful (truncated) download.
    pub async fn download(&self, remote: &str, local: impl AsRef<Path>) -> Result<u64> {
        self.download_with(remote, local, |_| {}).await
    }

    /// Like [`Self::download`], calling `progress(total)` after each chunk.
    pub async fn download_with<F>(
        &self,
        remote: &str,
        local: impl AsRef<Path>,
        mut progress: F,
    ) -> Result<u64>
    where
        F: FnMut(u64),
    {
        let local = local.as_ref();
        let partial = partial_path(local);
        let (mut send, mut recv) = self.conn.open_bi().await.context("opening file stream")?;
        rmp_proto::write_message(
            &mut send,
            &Message::FileRequest(FileRequest {
                op: FileOp::Get,
                path: remote.to_string(),
                mode: 0,
                size: 0,
            }),
        )
        .await?;

        let (mode, size) = match rmp_proto::read_message(&mut recv).await? {
            Message::FileResponse(r) if r.ok => (r.mode, r.size),
            Message::FileResponse(r) => {
                bail!("remote refused: {}", r.reason.unwrap_or_default())
            }
            other => bail!("unexpected response: {:?}", other.frame_type()),
        };

        let mut file = tokio::fs::File::create(&partial)
            .await
            .with_context(|| format!("creating {}", partial.display()))?;
        let mut total = 0u64;
        loop {
            match rmp_proto::read_message(&mut recv).await {
                Ok(Message::Data(d)) => {
                    if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut file, &d.data).await {
                        drop(file);
                        let _ = tokio::fs::remove_file(&partial).await;
                        return Err(e).context("writing download");
                    }
                    total += d.data.len() as u64;
                    progress(total);
                }
                Ok(Message::Eof) => break,
                Ok(_) => {}
                Err(rmp_proto::StreamError::Closed) => {
                    drop(file);
                    let _ = tokio::fs::remove_file(&partial).await;
                    bail!(
                        "connection closed before the download completed ({total} bytes received)"
                    );
                }
                Err(e) => {
                    drop(file);
                    let _ = tokio::fs::remove_file(&partial).await;
                    return Err(e).context("reading file data");
                }
            }
        }
        if let Err(e) = tokio::io::AsyncWriteExt::flush(&mut file).await {
            drop(file);
            let _ = tokio::fs::remove_file(&partial).await;
            return Err(e).context("flushing download");
        }
        drop(file);
        // A dropped connection is handled above; verify the advertised size
        // before publishing the file.
        if total != size {
            let _ = tokio::fs::remove_file(&partial).await;
            bail!(
                "incomplete download of {}: received {total} of {size} bytes",
                local.display()
            );
        }
        apply_mode(&partial, mode);

        if tokio::fs::rename(&partial, local).await.is_err() {
            // On platforms where rename does not replace an existing file,
            // remove the destination and retry once.
            let _ = tokio::fs::remove_file(local).await;
            tokio::fs::rename(&partial, local)
                .await
                .with_context(|| format!("moving download into {}", local.display()))?;
        }
        progress(total);
        Ok(total)
    }

    /// Upload `local` to the remote path `remote`. Returns bytes sent.
    pub async fn upload(&self, local: impl AsRef<Path>, remote: &str) -> Result<u64> {
        self.upload_with(local, remote, |_| {}).await
    }

    /// Like [`Self::upload`], calling `progress(total)` after each chunk.
    pub async fn upload_with<F>(
        &self,
        local: impl AsRef<Path>,
        remote: &str,
        mut progress: F,
    ) -> Result<u64>
    where
        F: FnMut(u64),
    {
        let size = tokio::fs::metadata(local.as_ref())
            .await
            .with_context(|| format!("reading metadata for {}", local.as_ref().display()))?
            .len();
        let (mut send, mut recv) = self.conn.open_bi().await.context("opening file stream")?;
        rmp_proto::write_message(
            &mut send,
            &Message::FileRequest(FileRequest {
                op: FileOp::Put,
                path: remote.to_string(),
                mode: local_mode(local.as_ref()),
                size,
            }),
        )
        .await?;

        match rmp_proto::read_message(&mut recv).await? {
            Message::FileResponse(r) if r.ok => {}
            Message::FileResponse(r) => {
                bail!("remote refused: {}", r.reason.unwrap_or_default())
            }
            other => bail!("unexpected response: {:?}", other.frame_type()),
        }

        let mut file = tokio::fs::File::open(local.as_ref())
            .await
            .with_context(|| format!("opening {}", local.as_ref().display()))?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut file, &mut buf).await?;
            if n == 0 {
                break;
            }
            rmp_proto::write_message(
                &mut send,
                &Message::Data(Data {
                    data: buf[..n].to_vec(),
                }),
            )
            .await?;
            total += n as u64;
            progress(total);
        }
        rmp_proto::write_message(&mut send, &Message::Eof).await?;

        match rmp_proto::read_message(&mut recv).await {
            Ok(Message::ExitStatus(s)) if s.exit_code == 0 => {}
            Ok(Message::ExitStatus(s)) => bail!("remote reported error (exit {})", s.exit_code),
            Ok(other) => bail!("unexpected response: {:?}", other.frame_type()),
            Err(rmp_proto::StreamError::Closed) => {
                bail!("connection closed before the server confirmed the upload")
            }
            Err(e) => return Err(e).context("reading upload confirmation"),
        }
        progress(total);
        Ok(total)
    }

    /// Open an interactive PTY session bridged to the local terminal.
    ///
    /// The control stream carries application-level `Ping`/`Pong` keepalives:
    /// once the server has answered at least one `Ping`, a missing `Pong`
    /// eventually aborts the session instead of silently treating the closed
    /// stream as a clean exit.
    pub async fn interactive(&mut self, term_name: &str, cols: u16, rows: u16) -> Result<u32> {
        let (mut send, mut recv) = self.conn.open_bi().await.context("opening session")?;
        rmp_proto::write_message(
            &mut send,
            &Message::PtyRequest(PtyRequest {
                term: term_name.to_string(),
                cols,
                rows,
                pixel_w: 0,
                pixel_h: 0,
                modes: Vec::new(),
            }),
        )
        .await?;
        rmp_proto::write_message(&mut send, &Message::Shell).await?;

        const PING_INTERVAL: Duration = Duration::from_secs(15);
        const PING_TIMEOUT: Duration = Duration::from_secs(45);

        let ctrl_send = &mut self.ctrl_send;
        let ctrl_recv = &mut self.ctrl_recv;

        // Best effort: if stdin is not a TTY we keep line mode.
        let _raw = term::RawMode::enable().ok();
        let mut stdout = tokio::io::stdout();
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 8192];
        let mut input_closed = false;
        let mut last_size = (cols, rows);
        let mut resize_tick = tokio::time::interval(Duration::from_millis(250));
        let mut ping_tick = tokio::time::interval(PING_INTERVAL);
        ping_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut ping_nonce: u64 = 0;
        let mut last_pong: Option<Instant> = None;

        loop {
            tokio::select! {
                r = stdin.read(&mut buf), if !input_closed => {
                    match r {
                        Ok(0) => {
                            input_closed = true;
                            let _ = rmp_proto::write_message(&mut send, &Message::Eof).await;
                        }
                        Ok(n) => {
                            rmp_proto::write_message(
                                &mut send,
                                &Message::Data(Data { data: buf[..n].to_vec() }),
                            ).await?;
                        }
                        Err(_) => { input_closed = true; }
                    }
                }
                msg = rmp_proto::read_message(&mut recv) => {
                    match msg {
                        Ok(Message::Data(d)) => {
                            stdout.write_all(&d.data).await?;
                            stdout.flush().await?;
                        }
                        Ok(Message::ExitStatus(ExitStatus { exit_code, .. })) => {
                            let _ = send.finish();
                            return Ok(exit_code);
                        }
                        Err(rmp_proto::StreamError::Closed) => {
                            bail!("connection closed before the shell reported an exit status");
                        }
                        Err(e) => return Err(e).context("interactive session"),
                        Ok(_) => {}
                    }
                }
                ctrl = rmp_proto::read_message(ctrl_recv) => {
                    match ctrl {
                        Ok(Message::Ping(Ping { nonce })) => {
                            let _ = rmp_proto::write_message(
                                ctrl_send,
                                &Message::Pong(Pong { nonce }),
                            ).await;
                        }
                        Ok(Message::Pong(_)) => last_pong = Some(Instant::now()),
                        Ok(Message::Disconnect(d)) => {
                            bail!("server disconnected: {:?} ({})", d.reason, d.message);
                        }
                        Ok(_) => {}
                        Err(rmp_proto::StreamError::Closed) => {
                            bail!("control stream closed unexpectedly");
                        }
                        Err(e) => return Err(e).context("control stream"),
                    }
                }
                _ = resize_tick.tick() => {
                    let size = term::terminal_size();
                    if size != last_size {
                        last_size = size;
                        let _ = rmp_proto::write_message(
                            &mut send,
                            &Message::WindowChange(WindowChange {
                                cols: size.0,
                                rows: size.1,
                                pixel_w: 0,
                                pixel_h: 0,
                            }),
                        ).await;
                    }
                }
                _ = ping_tick.tick() => {
                    if let Some(last) = last_pong {
                        if last.elapsed() > PING_TIMEOUT {
                            bail!(
                                "connection lost: no Pong from server in {}s",
                                PING_TIMEOUT.as_secs()
                            );
                        }
                    }
                    ping_nonce = ping_nonce.wrapping_add(1);
                    if let Err(e) = rmp_proto::write_message(
                        ctrl_send,
                        &Message::Ping(Ping { nonce: ping_nonce }),
                    ).await {
                        bail!("control stream closed while sending keepalive: {e}");
                    }
                }
            }
        }
    }
}

/// Sibling temporary path used while a download is in flight.
fn partial_path(local: &Path) -> PathBuf {
    let name = local
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("rmp-download");
    local.with_file_name(format!(".{name}.rmp-part"))
}

/// Unix permission bits of a local file (0 elsewhere). Used to preserve the
/// mode across a `Put`.
#[cfg(unix)]
fn local_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0)
}

#[cfg(not(unix))]
fn local_mode(_path: &Path) -> u32 {
    0
}

/// Apply a Unix mode to a local path (no-op for `mode == 0` or non-Unix).
fn apply_mode(path: &Path, mode: u32) {
    if mode == 0 {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}
