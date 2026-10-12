//! Async framing helpers on top of any `AsyncRead`/`AsyncWrite`.
//!
//! These wrap the pure [`encode`]/[`decode`] functions with the minimum amount
//! of I/O needed to move frames over a QUIC stream.

use crate::frame;
use crate::message::{Message, ProtoError};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const HEADER_LEN: usize = 8;

/// Error returned while reading or writing a frame.
#[derive(Debug, Error)]
pub enum StreamError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Proto(#[from] ProtoError),
    /// The peer closed the stream cleanly at a frame boundary.
    #[error("stream closed by peer")]
    Closed,
}

/// Write a single encoded frame and flush it.
pub async fn write_message<W>(w: &mut W, msg: &Message) -> Result<(), StreamError>
where
    W: AsyncWrite + Unpin,
{
    let bytes = frame::encode(msg)?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read exactly one frame, validating its header before reading the payload.
///
/// Returns [`StreamError::Closed`] if the peer closed the stream before sending
/// any byte of a new frame.
pub async fn read_message<R>(r: &mut R) -> Result<Message, StreamError>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; HEADER_LEN];
    let mut read = 0usize;
    while read < HEADER_LEN {
        let n = r.read(&mut header[read..]).await?;
        if n == 0 {
            return if read == 0 {
                Err(StreamError::Closed)
            } else {
                // Truncated mid-header: treat as a protocol error.
                Err(StreamError::Proto(ProtoError::Short))
            };
        }
        read += n;
    }

    // `parse_header` validates magic, version, type and the declared length.
    let hdr = frame::parse_header(&header)?;
    let mut payload = vec![0u8; hdr.length as usize];
    if let Err(e) = r.read_exact(&mut payload).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            // The peer stopped mid-frame; report it as a framing error.
            return Err(StreamError::Proto(ProtoError::Short));
        }
        return Err(StreamError::Io(e));
    }

    let mut full = Vec::with_capacity(HEADER_LEN + payload.len());
    full.extend_from_slice(&header);
    full.extend_from_slice(&payload);
    Ok(frame::decode(&full)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{Data, Message, Ping};
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_over_duplex_stream() {
        let (mut a, mut b) = duplex(4096);

        let writer = tokio::spawn(async move {
            write_message(&mut a, &Message::Ping(Ping { nonce: 7 }))
                .await
                .unwrap();
            write_message(
                &mut a,
                &Message::Data(Data {
                    data: b"hi".to_vec(),
                }),
            )
            .await
            .unwrap();
            drop(a);
        });

        let first = read_message(&mut b).await.unwrap();
        let second = read_message(&mut b).await.unwrap();
        assert_eq!(first, Message::Ping(Ping { nonce: 7 }));
        assert_eq!(
            second,
            Message::Data(Data {
                data: b"hi".to_vec()
            })
        );
        assert!(matches!(
            read_message(&mut b).await,
            Err(StreamError::Closed)
        ));

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn truncated_header_is_protocol_error() {
        // A header claiming a 1_000 byte payload followed by an immediate EOF.
        let (mut a, mut b) = duplex(64);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&crate::MAGIC.to_be_bytes());
        bytes.push(crate::WIRE_VERSION);
        bytes.push(0x46); // Data
        bytes.extend_from_slice(&1_000u32.to_be_bytes());
        a.write_all(&bytes).await.unwrap();
        drop(a);

        assert!(matches!(
            read_message(&mut b).await,
            Err(StreamError::Proto(ProtoError::Short))
        ));
    }
}
