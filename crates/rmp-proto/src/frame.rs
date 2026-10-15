//! Frame encoding/decoding.
//!
//! Layout (all integers big-endian):
//!
//! ```text
//! +----------+---------+------------+-------------+-------------------+
//! | MAGIC u16| VER u8  | TYPE u8    | LENGTH u32  | PAYLOAD (LENGTH)  |
//! +----------+---------+------------+-------------+-------------------+
//! ```
//!
//! The payload is a `postcard`-encoded [`Message`].

use crate::message::{FrameType, Message, ProtoError};
use crate::{MAGIC, MAX_FRAME, WIRE_VERSION};

/// Parsed frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub frame_type: FrameType,
    pub length: u32,
}

/// Encode a message into a complete, length-delimited frame.
pub fn encode(message: &Message) -> Result<Vec<u8>, ProtoError> {
    let payload = message.encode_body()?;
    if payload.len() > MAX_FRAME {
        return Err(ProtoError::TooLarge(payload.len()));
    }

    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.push(WIRE_VERSION);
    out.push(message.frame_type().as_u8());
    // Length is bounded by MAX_FRAME which fits in u32 by construction.
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Parse only the fixed-size header of a frame.
///
/// Validates magic, wire version, message code and the declared length, but does
/// not require the payload to be present. This is the primitive used by the
/// streaming reader, which fetches the payload separately.
pub fn parse_header(buf: &[u8]) -> Result<Header, ProtoError> {
    if buf.len() < 8 {
        return Err(ProtoError::Short);
    }
    let magic = u16::from_be_bytes([buf[0], buf[1]]);
    if magic != MAGIC {
        return Err(ProtoError::BadMagic);
    }
    let version = buf[2];
    if version != WIRE_VERSION {
        return Err(ProtoError::UnsupportedVersion(version));
    }
    let frame_type = FrameType::from_u8(buf[3])?;
    let length = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    if length > MAX_FRAME {
        return Err(ProtoError::TooLarge(length));
    }
    Ok(Header {
        version,
        frame_type,
        length: length as u32,
    })
}

/// Parse the header of a frame contained in `buf`.
///
/// Returns the header and the payload slice. Requires the full frame to be
/// present in `buf`.
pub fn decode_header(buf: &[u8]) -> Result<(Header, &[u8]), ProtoError> {
    let header = parse_header(buf)?;
    let length = header.length as usize;
    if buf.len() < 8 + length {
        return Err(ProtoError::Short);
    }
    let payload = &buf[8..8 + length];
    Ok((header, payload))
}

/// Decode a complete frame into a [`Message`].
///
/// The message type comes from the frame header, so decoding is driven by the
/// explicit [`FrameType`] tag rather than the position of an enum variant.
pub fn decode(buf: &[u8]) -> Result<Message, ProtoError> {
    let (header, payload) = decode_header(buf)?;
    Message::decode_body(header.frame_type, payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::*;

    fn roundtrip(msg: Message) {
        let bytes = encode(&msg).expect("encode");
        // Header is exactly 8 bytes and length matches.
        let (hdr, payload) = decode_header(&bytes).expect("header");
        assert_eq!(hdr.frame_type, msg.frame_type());
        assert_eq!(hdr.length as usize, payload.len());
        let back = decode(&bytes).expect("decode");
        assert_eq!(msg, back);
    }

    #[test]
    fn roundtrip_control_messages() {
        roundtrip(Message::Hello(Hello {
            proto_version: 1,
            client_name: "rmp".into(),
            client_version: "0.1.0".into(),
        }));
        roundtrip(Message::HelloAck(HelloAck {
            proto_version: 1,
            server_name: "rmp".into(),
            server_version: "0.1.0".into(),
            capabilities: vec![0, 1, 2],
        }));
        roundtrip(Message::AuthStart(AuthStart {
            username: "alice".into(),
            initial: vec![9, 8, 7],
        }));
        roundtrip(Message::AuthResult(AuthResult {
            ok: true,
            reason: AuthReason::Ok,
            session_token: Some(vec![1, 2, 3]),
            key_enrolled: true,
        }));
        roundtrip(Message::KeyAuthRequest(KeyAuthRequest {
            username: "alice".into(),
            public_key: vec![7u8; 32],
        }));
        roundtrip(Message::KeyAuthChallenge(KeyAuthChallenge {
            nonce: vec![9u8; 32],
        }));
        roundtrip(Message::KeyAuthProof(KeyAuthProof {
            signature: vec![3u8; 64],
        }));
        roundtrip(Message::ChannelOpen(ChannelOpen {
            channel_id: 7,
            kind: ChannelKind::Session,
        }));
        roundtrip(Message::GoAway(GoAway { last_channel: 0 }));
        roundtrip(Message::Disconnect(Disconnect {
            reason: DisconnectReason::Bye,
            message: "goodbye".into(),
        }));
        roundtrip(Message::Ping(Ping { nonce: 42 }));
        roundtrip(Message::Pong(Pong { nonce: 42 }));
    }

    #[test]
    fn roundtrip_session_messages() {
        roundtrip(Message::PtyRequest(PtyRequest {
            term: "xterm-256color".into(),
            cols: 120,
            rows: 40,
            pixel_w: 0,
            pixel_h: 0,
            modes: vec![],
        }));
        roundtrip(Message::Shell);
        roundtrip(Message::Exec(Exec {
            command: "uname -a".into(),
        }));
        roundtrip(Message::Env(Env {
            name: "LANG".into(),
            value: b"C.UTF-8".to_vec(),
        }));
        roundtrip(Message::WindowChange(WindowChange {
            cols: 80,
            rows: 24,
            pixel_w: 0,
            pixel_h: 0,
        }));
        roundtrip(Message::Signal(Signal {
            signal: "INT".into(),
        }));
        roundtrip(Message::Data(Data {
            data: b"hello world".to_vec(),
        }));
        roundtrip(Message::Eof);
        roundtrip(Message::ExitStatus(ExitStatus {
            exit_code: 0,
            signal: None,
        }));
        roundtrip(Message::ExitSignal(ExitSignal {
            signal: "TERM".into(),
            core_dumped: false,
            message: "terminated".into(),
        }));
        roundtrip(Message::ForwardRequest(ForwardRequest {
            host: "localhost".into(),
            port: 8080,
        }));
        roundtrip(Message::ForwardResponse(ForwardResponse {
            ok: false,
            reason: Some("connection refused".into()),
        }));
        roundtrip(Message::RemoteForwardBind(RemoteForwardBind {
            bind_port: 9000,
            target_host: "localhost".into(),
            target_port: 5432,
        }));
        roundtrip(Message::RemoteForwardBindResult(RemoteForwardBindResult {
            ok: true,
            bound_port: 9000,
            reason: None,
        }));
        roundtrip(Message::FileRequest(FileRequest {
            op: FileOp::Get,
            path: "/etc/hosts".into(),
            mode: 0o644,
        }));
        roundtrip(Message::FileResponse(FileResponse {
            ok: true,
            size: 1234,
            reason: None,
            mode: 0o755,
        }));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = encode(&Message::Shell).unwrap();
        bytes[0] = 0x00;
        assert_eq!(decode(&bytes), Err(ProtoError::BadMagic));
    }

    #[test]
    fn rejects_bad_version() {
        let mut bytes = encode(&Message::Shell).unwrap();
        bytes[2] = 99;
        assert_eq!(decode(&bytes), Err(ProtoError::UnsupportedVersion(99)));
    }

    #[test]
    fn rejects_short_buffer() {
        assert_eq!(decode(&[0x52, 0x4D]), Err(ProtoError::Short));
    }

    #[test]
    fn rejects_oversized_declared_length() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC.to_be_bytes());
        bytes.push(WIRE_VERSION);
        bytes.push(FrameType::Data.as_u8());
        bytes.extend_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());
        assert!(matches!(
            decode_header(&bytes),
            Err(ProtoError::TooLarge(_))
        ));
    }

    #[test]
    fn rejects_wrong_body_for_type() {
        // Build a frame whose header says Data but whose payload is a Ping.
        let payload = postcard::to_allocvec(&Ping { nonce: 1 }).unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAGIC.to_be_bytes());
        bytes.push(WIRE_VERSION);
        bytes.push(FrameType::Data.as_u8());
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&payload);
        // A Ping body does not decode as a Data body, so this must error.
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn body_encoding_is_not_enum_tagged() {
        // The body must contain only the message fields, not an enum tag.
        // `Ping { nonce: 0 }` -> a single varint 0x00.
        let frame = encode(&Message::Ping(Ping { nonce: 0 })).unwrap();
        let (_, body) = decode_header(&frame).unwrap();
        assert_eq!(body, &[0x00]);
    }

    #[test]
    fn control_and_session_classification() {
        assert!(Message::Ping(Ping { nonce: 0 }).is_control());
        assert!(!Message::Ping(Ping { nonce: 0 }).is_session());
        assert!(Message::Data(Data { data: vec![] }).is_session());
        assert!(!Message::Data(Data { data: vec![] }).is_control());
        assert!(Message::Shell.expect_session().is_ok());
        assert!(Message::Shell.expect_control().is_err());
        assert!(Message::KeyAuthRequest(KeyAuthRequest {
            username: "a".into(),
            public_key: vec![],
        })
        .is_control());
    }

    #[test]
    fn key_auth_context_binds_fields() {
        let a = crate::key_auth_context("alice", &[1, 2, 3], &[9, 9]);
        let b = crate::key_auth_context("alice", &[1, 2, 3], &[9, 9]);
        assert_eq!(a, b, "deterministic");
        assert_ne!(a, crate::key_auth_context("bob", &[1, 2, 3], &[9, 9]));
        assert_ne!(a, crate::key_auth_context("alice", &[1, 2, 4], &[9, 9]));
        assert_ne!(a, crate::key_auth_context("alice", &[1, 2, 3], &[9, 8]));
        assert!(a.starts_with(crate::KEY_AUTH_CONTEXT));
    }
}
