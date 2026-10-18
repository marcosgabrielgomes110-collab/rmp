//! Port forwarding (client side).
//!
//! `local_forward` binds a TCP listener; every accepted connection is tunnelled
//! to the server, which dials the requested `host:port` and pipes the bytes
//! back (classic `ssh -L`).

use anyhow::{Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use rmp_proto::{Data, ForwardRequest, ForwardResponse, Message};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Forward each connection accepted on `listener` to `host:port` via `conn`.
///
/// Runs until the listener fails.
pub async fn local_forward(
    conn: Connection,
    listener: TcpListener,
    host: String,
    port: u16,
) -> Result<()> {
    let bind = listener.local_addr().ok();
    tracing::info!(?bind, target = %format!("{host}:{port}"), "local forward listening");

    loop {
        let (tcp, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(?bind, error = %e, "forward accept failed");
                continue;
            }
        };
        let conn = conn.clone();
        let host = host.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(conn, tcp, host, port).await {
                tracing::debug!("forward connection ended: {e}");
            }
        });
    }
}

async fn handle(conn: Connection, tcp: TcpStream, host: String, port: u16) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("opening forward stream")?;
    rmp_proto::write_message(
        &mut send,
        &Message::ForwardRequest(ForwardRequest { host, port }),
    )
    .await?;

    let response = rmp_proto::read_message(&mut recv).await?;
    match response {
        Message::ForwardResponse(ForwardResponse { ok: true, .. }) => {}
        Message::ForwardResponse(ForwardResponse { ok: false, reason }) => {
            anyhow::bail!("forward refused: {}", reason.unwrap_or_default());
        }
        other => anyhow::bail!("unexpected forward response: {:?}", other.frame_type()),
    }

    pipe(tcp, send, recv).await
}

/// Accept server-initiated forwarding streams (for `rmp connect -R`) and dial
/// the requested target, then pipe.
pub async fn remote_forward_accept(conn: Connection) -> Result<()> {
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        tokio::spawn(async move {
            if let Ok(Message::ForwardRequest(ForwardRequest { host, port })) =
                rmp_proto::read_message(&mut recv).await
            {
                match TcpStream::connect((host.as_str(), port)).await {
                    Ok(tcp) => {
                        let _ = rmp_proto::write_message(
                            &mut send,
                            &Message::ForwardResponse(ForwardResponse {
                                ok: true,
                                reason: None,
                            }),
                        )
                        .await;
                        let _ = pipe(tcp, send, recv).await;
                    }
                    Err(e) => {
                        let _ = rmp_proto::write_message(
                            &mut send,
                            &Message::ForwardResponse(ForwardResponse {
                                ok: false,
                                reason: Some(e.to_string()),
                            }),
                        )
                        .await;
                    }
                }
            }
        });
    }
    Ok(())
}

/// Pipe a TCP connection and a framed QUIC stream in both directions.
pub(crate) async fn pipe(tcp: TcpStream, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let stream_to_tcp = async {
        loop {
            match rmp_proto::read_message(&mut recv).await {
                Ok(Message::Data(d)) => {
                    if tcp_write.write_all(&d.data).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Eof) => {
                    let _ = tcp_write.shutdown().await;
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    };

    let tcp_to_stream = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = rmp_proto::write_message(&mut send, &Message::Eof).await;
                    break;
                }
                Ok(n) => {
                    if rmp_proto::write_message(
                        &mut send,
                        &Message::Data(Data {
                            data: buf[..n].to_vec(),
                        }),
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    // Wait for both directions: a half-close (Eof one way) must not cancel
    // the bytes still flowing in the other direction.
    tokio::join!(stream_to_tcp, tcp_to_stream);
    let _ = send.finish();
    Ok(())
}
