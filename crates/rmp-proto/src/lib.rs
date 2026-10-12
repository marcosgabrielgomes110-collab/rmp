//! # rmp-proto
//!
//! Wire protocol of the RMP (Remote Machine Protocol): versioned framing and the
//! message set exchanged over the QUIC control and session streams.
//!
//! The framing is intentionally small and defensive:
//!
//! * every frame carries a magic number and a wire version, so mismatched or
//!   corrupted input is rejected before any allocation happens;
//! * the payload length is bounded by [`MAX_FRAME`] on encode **and** decode;
//! * the message code in the header is cross-checked against the decoded message,
//!   so a stream cannot smuggle a message of the wrong kind.
//!
//! Encoding uses [`postcard`] (a compact, non-self-describing codec). Secrets are
//! never placed in messages that are logged.

#![forbid(unsafe_code)]

mod frame;
mod message;

#[cfg(feature = "io")]
pub mod stream;

/// Maximum accepted payload size of a single frame (1 MiB).
///
/// Enforced both when encoding and decoding so a hostile peer cannot force a
/// large allocation.
pub const MAX_FRAME: usize = 1024 * 1024;

#[cfg(feature = "io")]
pub use stream::{read_message, write_message, StreamError};

pub use frame::{decode, decode_header, encode, parse_header, Header};
pub use message::*;

/// QUIC ALPN identifier negotiated during the handshake.
pub const ALPN: &[u8] = b"rmp/1";

/// Human-readable protocol name.
pub const PROTOCOL_NAME: &str = "RMP — Remote Machine Protocol";

/// Wire format version carried in every frame.
pub const WIRE_VERSION: u8 = 1;

/// Current application protocol version negotiated in `Hello`/`HelloAck`.
pub const PROTO_VERSION: u16 = 1;

/// Frame magic number (`'R' 'M'`).
pub const MAGIC: u16 = 0x524D;
