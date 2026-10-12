//! RMP client: connect, authenticate and drive sessions.

use crate::term;
use anyhow::{bail, Context, Result};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rmp_crypto::{self as crypto, Fingerprint, ObservedFingerprint};
use rmp_proto::{
    AuthFinish, AuthResponse, AuthResult, AuthStart, Data, Exec, ExitStatus, Hello, HelloAck,
    Message, PtyRequest, WindowChange,
};
use std::net::SocketAddr;
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
///
/// Returns the QUIC endpoint (kept alive by the caller), the connection and the
/// observed server fingerprint.
pub async fn transport(
    opts: &ClientOptions,
) -> Result<(Endpoint, Connection, ObservedFingerprint)> {
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
    Ok((endpoint, conn, observed))
}

/// An authenticated client, holding the control stream open.
pub struct Client {
    _endpoint: Endpoint,
    conn: Connection,
    _ctrl_send: SendStream,
    _ctrl_recv: RecvStream,
    observed: Option<Fingerprint>,
}

/// Output of a non-interactive command.
pub struct ExecOutput {
    pub data: Vec<u8>,
    pub exit_code: u32,
}

impl Client {
    /// Connect and authenticate with a password.
    pub async fn connect(opts: &ClientOptions, username: &str, password: &[u8]) -> Result<Client> {
        let (endpoint, conn, observed) = transport(opts).await?;
        Client::authenticate(endpoint, conn, observed, username, password).await
    }

    /// Authenticate over an already-established transport.
    ///
    /// This is separated from [`Client::connect`] so a caller can verify (and
    /// let the user confirm) the server fingerprint **before** any credential
    /// is sent.
    pub async fn authenticate(
        endpoint: Endpoint,
        conn: Connection,
        observed: ObservedFingerprint,
        username: &str,
        password: &[u8],
    ) -> Result<Client> {
        let observed_fp = observed.get();

        // The control channel: application handshake + authentication.
        let (mut ctrl_send, mut ctrl_recv) =
            conn.open_bi().await.context("opening control stream")?;

        rmp_proto::write_message(
            &mut ctrl_send,
            &Message::Hello(Hello {
                proto_version: rmp_proto::PROTO_VERSION,
                client_name: "rmp".to_string(),
                client_version: env!("CARGO_PKG_VERSION").to_string(),
            }),
        )
        .await
        .context("sending Hello")?;

        let ack = rmp_proto::read_message(&mut ctrl_recv)
            .await
            .context("reading HelloAck")?;
        let Message::HelloAck(HelloAck { proto_version, .. }) = ack else {
            bail!("expected HelloAck, got {:?}", ack.frame_type());
        };
        if proto_version != rmp_proto::PROTO_VERSION {
            bail!("protocol version mismatch: server={proto_version}");
        }

        // OPAQUE authentication.
        let (initial, state) =
            crypto::password::client_start(password).context("OPAQUE client_start")?;
        rmp_proto::write_message(
            &mut ctrl_send,
            &Message::AuthStart(AuthStart {
                username: username.to_string(),
                initial,
            }),
        )
        .await?;

        let response = rmp_proto::read_message(&mut ctrl_recv).await?;
        let Message::AuthResponse(AuthResponse { payload }) = response else {
            bail!("expected AuthResponse, got {:?}", response.frame_type());
        };

        let (finalization, _session_key) =
            crypto::password::client_finish(state, &payload, password)?;

        rmp_proto::write_message(
            &mut ctrl_send,
            &Message::AuthFinish(AuthFinish {
                payload: finalization,
                device_pubkey: None,
            }),
        )
        .await?;

        let result = rmp_proto::read_message(&mut ctrl_recv).await?;
        let Message::AuthResult(AuthResult { ok, reason, .. }) = result else {
            bail!("expected AuthResult, got {:?}", result.frame_type());
        };
        if !ok {
            bail!("authentication rejected: {reason:?}");
        }
        info!(user = username, "authenticated");

        Ok(Client {
            _endpoint: endpoint,
            conn,
            _ctrl_send: ctrl_send,
            _ctrl_recv: ctrl_recv,
            observed: observed_fp,
        })
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// The fingerprint the server presented (available after the handshake).
    pub fn observed_fingerprint(&self) -> Option<Fingerprint> {
        self.observed
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
    ///
    /// The script is written to the shell's stdin; it is expected to end with
    /// `exit` so the session terminates. Useful for tests and automation.
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

    /// Open an interactive PTY session bridged to the local terminal.
    ///
    /// Returns the remote exit code.
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
