//! Port forwarding.
//!
//! A forwarding stream begins with a [`ForwardRequest`]; the receiver of that
//! message is the side that dials the TCP connection, replies with
//! [`ForwardResponse`] and then pipes bytes in both directions using `Data`
//! messages (terminated by `Eof`).

use crate::audit::audit;
use anyhow::Result;
use rmp_proto::{Data, ForwardRequest, ForwardResponse, Message};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Dial the requested target and pipe it with the forwarding stream.
///
/// The I/O is generic so the same implementation can run over a QUIC stream
/// (server) or over the helper process's stdin/stdout (root mode).
pub async fn serve<S, R>(mut send: S, recv: R, req: ForwardRequest, peer: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    let target = format!("{}:{}", req.host, req.port);
    audit!(event = "forward.open", peer = %peer, target = %target);

    match TcpStream::connect(&target).await {
        Ok(tcp) => {
            rmp_proto::write_message(
                &mut send,
                &Message::ForwardResponse(ForwardResponse {
                    ok: true,
                    reason: None,
                }),
            )
            .await?;
            pipe(tcp, send, recv).await?;
            audit!(event = "forward.close", peer = %peer, target = %target);
        }
        Err(e) => {
            audit!(event = "forward.refused", peer = %peer, target = %target, reason = %e);
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
    Ok(())
}

/// Pipe a TCP connection and a framed stream in both directions.
///
/// Ends when both directions close.
pub async fn pipe<S, R>(tcp: TcpStream, mut send: S, mut recv: R) -> Result<()>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
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
    let _ = send.shutdown().await;
    Ok(())
}
