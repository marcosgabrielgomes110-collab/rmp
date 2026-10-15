//! RMP client: connect, authenticate and drive sessions.

use crate::term;
use anyhow::{bail, Context, Result};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rmp_crypto::{self as crypto, DeviceKey, Fingerprint, ObservedFingerprint};
use rmp_proto::{
    key_auth_context, AuthFinish, AuthResponse, AuthResult, AuthStart, Data, Exec, ExitStatus,
    FileOp, FileRequest, Hello, HelloAck, KeyAuthChallenge, KeyAuthProof, KeyAuthRequest, Message,
    PtyRequest, RemoteForwardBind, WindowChange,
};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
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
    expected: Option<Fingerprint>,
    idle_timeout: Duration,
    keep_alive: Duration,
) -> Result<(quinn::ClientConfig, ObservedFingerprint)> {
    let (tls, observed) = crypto::client_config(expected)?;
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
    let (config, observed) = quic_client_config(
        opts.expected_fingerprint,
        opts.idle_timeout,
        opts.keep_alive,
    )?;
    endpoint.set_default_client_config(config);

    let conn = endpoint
        .connect(opts.server_addr, &opts.server_name)
        .context("initiating QUIC connection")?
        .await
        .context("QUIC/TLS handshake")?;

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
                    return Ok(ExecOutput { data, exit_code: 0 });
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
                    return Ok(ExecOutput { data, exit_code: 0 });
                }
                Err(e) => return Err(e).context("reading pty output"),
                Ok(_) => {}
            }
        }
    }

    /// Download `remote` to the local path `local`. Returns bytes written.
    pub async fn download(&self, remote: &str, local: impl AsRef<Path>) -> Result<u64> {
        let (mut send, mut recv) = self.conn.open_bi().await.context("opening file stream")?;
        rmp_proto::write_message(
            &mut send,
            &Message::FileRequest(FileRequest {
                op: FileOp::Get,
                path: remote.to_string(),
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

        let mut file = tokio::fs::File::create(local.as_ref())
            .await
            .with_context(|| format!("creating {}", local.as_ref().display()))?;
        let mut total = 0u64;
        loop {
            match rmp_proto::read_message(&mut recv).await {
                Ok(Message::Data(d)) => {
                    tokio::io::AsyncWriteExt::write_all(&mut file, &d.data).await?;
                    total += d.data.len() as u64;
                }
                Ok(Message::Eof) | Err(rmp_proto::StreamError::Closed) => break,
                Ok(_) => {}
                Err(e) => return Err(e).context("reading file data"),
            }
        }
        tokio::io::AsyncWriteExt::flush(&mut file).await?;
        Ok(total)
    }

    /// Upload `local` to the remote path `remote`. Returns bytes sent.
    pub async fn upload(&self, local: impl AsRef<Path>, remote: &str) -> Result<u64> {
        let (mut send, mut recv) = self.conn.open_bi().await.context("opening file stream")?;
        rmp_proto::write_message(
            &mut send,
            &Message::FileRequest(FileRequest {
                op: FileOp::Put,
                path: remote.to_string(),
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
        }
        rmp_proto::write_message(&mut send, &Message::Eof).await?;

        match rmp_proto::read_message(&mut recv).await? {
            Message::ExitStatus(s) if s.exit_code == 0 => {}
            Message::ExitStatus(s) => bail!("remote reported error (exit {})", s.exit_code),
            other => bail!("unexpected response: {:?}", other.frame_type()),
        }
        Ok(total)
    }

    /// Open an interactive PTY session bridged to the local terminal.
    pub async fn interactive(&self, term_name: &str, cols: u16, rows: u16) -> Result<u32> {
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

        // Best effort: if stdin is not a TTY we keep line mode.
        let _raw = term::RawMode::enable().ok();
        let mut stdout = tokio::io::stdout();
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 8192];
        let mut input_closed = false;
        let mut last_size = (cols, rows);
        let mut resize_tick = tokio::time::interval(Duration::from_millis(250));

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
                        Err(rmp_proto::StreamError::Closed) => return Ok(0),
                        Err(e) => return Err(e).context("interactive session"),
                        Ok(_) => {}
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
            }
        }
    }
}
