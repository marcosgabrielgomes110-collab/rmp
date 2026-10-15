//! Port forwarding.
//!
//! A forwarding stream begins with a [`ForwardRequest`]; the receiver of that
//! message is the side that dials the TCP connection, replies with
//! [`ForwardResponse`] and then pipes bytes in both directions using `Data`
//! messages (terminated by `Eof`).

use crate::audit::audit;
use anyhow::Result;
use quinn::{RecvStream, SendStream};
use rmp_proto::{Data, ForwardRequest, ForwardResponse, Message};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Dial the requested target and pipe it with the forwarding stream.
pub async fn serve(
    mut send: SendStream,
    recv: RecvStream,
    req: ForwardRequest,
    peer: SocketAddr,
) -> Result<()> {
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

/// Pipe a TCP connection and a framed QUIC stream in both directions.
///
/// Ends when either direction closes.
pub async fn pipe(tcp: TcpStream, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
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

    tokio::select! {
        _ = stream_to_tcp => {}
        _ = tcp_to_stream => {}
    }
    let _ = send.finish();
    Ok(())
}
