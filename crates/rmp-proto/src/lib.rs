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
///
/// Bumped to 2 when the body encoding moved from positional enum indices to an
/// explicit [`FrameType`] tag (not wire-compatible with version 1).
pub const WIRE_VERSION: u8 = 2;

/// Current application protocol version negotiated in `Hello`/`HelloAck`.
pub const PROTO_VERSION: u16 = 3;

/// Domain-separation prefix for device-key authentication signatures.
pub const KEY_AUTH_CONTEXT: &[u8] = b"rmp-keyauth-v1";

/// Bytes a device key signs to authenticate.
///
/// Binds the signature to the protocol version, the account name, the public
/// key and a fresh server nonce, preventing cross-account and replay attacks.
pub fn key_auth_context(username: &str, public_key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        KEY_AUTH_CONTEXT.len() + 2 + username.len() + 2 + public_key.len() + 2 + nonce.len(),
    );
    out.extend_from_slice(KEY_AUTH_CONTEXT);
    push_field(&mut out, username.as_bytes());
    push_field(&mut out, public_key);
    push_field(&mut out, nonce);
    out
}

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Frame magic number (`'R' 'M'`).
pub const MAGIC: u16 = 0x524D;
