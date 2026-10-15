//! Message types exchanged over RMP streams.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced by protocol decoding/validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("frame too large: {0} bytes (max {max})", max = crate::MAX_FRAME)]
    TooLarge(usize),
    #[error("buffer too short to contain a frame header")]
    Short,
    #[error("bad frame magic")]
    BadMagic,
    #[error("unsupported wire version {0}")]
    UnsupportedVersion(u8),
    #[error("message code {header} does not match decoded message {actual}")]
    TypeMismatch { header: u8, actual: u8 },
    #[error("unknown message code {0}")]
    UnknownType(u8),
    #[error("message is not valid in this context: {0:?}")]
    UnexpectedType(FrameType),
    #[error("codec error: {0}")]
    Codec(String),
}

impl From<postcard::Error> for ProtoError {
    fn from(e: postcard::Error) -> Self {
        ProtoError::Codec(e.to_string())
    }
}

/// Convenience alias for a decodable message.
pub type WireError = ProtoError;

/// Numeric message code carried in the frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    // Control: application handshake (0x0_)
    Hello = 0x01,
    HelloAck = 0x02,
    Capabilities = 0x03,
    // Control: authentication (0x1_)
    AuthStart = 0x10,
    AuthResponse = 0x11,
    AuthFinish = 0x12,
    AuthResult = 0x13,
    KeyAuthRequest = 0x14,
    KeyAuthChallenge = 0x15,
    KeyAuthProof = 0x16,
    // Control: channel management (0x2_)
    ChannelOpen = 0x20,
    ChannelOpenAck = 0x21,
    ChannelClose = 0x22,
    WindowAdjust = 0x23,
    // Control: liveness / teardown (0x3_)
    Ping = 0x30,
    Pong = 0x31,
    Disconnect = 0x32,
    GoAway = 0x33,
    RemoteForwardBind = 0x34,
    RemoteForwardBindResult = 0x35,
    // Session channel (0x4_)
    PtyRequest = 0x40,
    Shell = 0x41,
    Exec = 0x42,
    Env = 0x43,
    WindowChange = 0x44,
    Signal = 0x45,
    Data = 0x46,
    Eof = 0x47,
    ExitStatus = 0x48,
    ExitSignal = 0x49,
    // Port forwarding (0x5_)
    ForwardRequest = 0x50,
    ForwardResponse = 0x51,
}

impl FrameType {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Result<Self, ProtoError> {
        use FrameType::*;
        Ok(match v {
            0x01 => Hello,
            0x02 => HelloAck,
            0x03 => Capabilities,
            0x10 => AuthStart,
            0x11 => AuthResponse,
            0x12 => AuthFinish,
            0x13 => AuthResult,
            0x14 => KeyAuthRequest,
            0x15 => KeyAuthChallenge,
            0x16 => KeyAuthProof,
            0x20 => ChannelOpen,
            0x21 => ChannelOpenAck,
            0x22 => ChannelClose,
            0x23 => WindowAdjust,
            0x30 => Ping,
            0x31 => Pong,
            0x32 => Disconnect,
            0x33 => GoAway,
            0x34 => RemoteForwardBind,
            0x35 => RemoteForwardBindResult,
            0x40 => PtyRequest,
            0x41 => Shell,
            0x42 => Exec,
            0x43 => Env,
            0x44 => WindowChange,
            0x45 => Signal,
            0x46 => Data,
            0x47 => Eof,
            0x48 => ExitStatus,
            0x49 => ExitSignal,
            0x50 => ForwardRequest,
            0x51 => ForwardResponse,
            other => return Err(ProtoError::UnknownType(other)),
        })
    }

    /// Whether this message may appear on the control stream.
    pub const fn is_control(self) -> bool {
        matches!(self.as_u8(), 0x01..=0x3F)
    }

    /// Whether this message may appear on a session or forwarding stream.
    pub const fn is_session(self) -> bool {
        matches!(self.as_u8(), 0x40..=0x6F)
    }
}

/// Capability flags negotiated after the transport handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Capability {
    Pty = 0,
    Exec = 1,
    Signals = 2,
    EnrollKey = 3,
    Resume0Rtt = 4,
}

/// Kind of channel requested by the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ChannelKind {
    /// Interactive PTY session.
    Session = 0,
    /// Non-interactive command execution.
    Exec = 1,
}

/// Reason a channel is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CloseReason {
    Normal = 0,
    RemoteExited = 1,
    ProtocolError = 2,
    Refused = 3,
}

/// Reason a connection is disconnected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DisconnectReason {
    Bye = 0,
    ProtocolError = 1,
    AuthFailed = 2,
    AuthLocked = 3,
    IdleTimeout = 4,
    FrameTooLarge = 5,
    ServerShutdown = 6,
    Internal = 255,
}

/// Reason returned after an authentication attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthReason {
    /// Authentication succeeded.
    Ok = 0,
    InvalidCredentials = 1,
    LockedOut = 2,
    RateLimited = 3,
    KeyEnrolled = 4,
    Unknown = 255,
}

// ---------------------------------------------------------------------------
// Control messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    pub proto_version: u16,
    pub client_name: String,
    pub client_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAck {
    pub proto_version: u16,
    pub server_name: String,
    pub server_version: String,
    pub capabilities: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub client: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStart {
    pub username: String,
    /// OPAQUE credential request (never the password itself).
    pub initial: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResponse {
    /// OPAQUE server response.
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthFinish {
    /// OPAQUE client finish message.
    pub payload: Vec<u8>,
    /// Optional device public key for passwordless enrollment.
    pub device_pubkey: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResult {
    pub ok: bool,
    pub reason: AuthReason,
    pub session_token: Option<Vec<u8>>,
    /// Set when the server stored a device key sent in `AuthFinish`.
    #[serde(default)]
    pub key_enrolled: bool,
}

/// Client requests key-based authentication for `username`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAuthRequest {
    pub username: String,
    /// Raw Ed25519 public key (32 bytes).
    pub public_key: Vec<u8>,
}

/// Server-issued nonce the client must sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAuthChallenge {
    pub nonce: Vec<u8>,
}

/// Client's proof of possession of the device key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAuthProof {
    /// Ed25519 signature (64 bytes) over [`crate::key_auth_context`].
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelOpen {
    pub channel_id: u32,
    pub kind: ChannelKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelOpenAck {
    pub channel_id: u32,
    pub ok: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelClose {
    pub channel_id: u32,
    pub reason: CloseReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowAdjust {
    pub channel_id: u32,
    pub delta_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ping {
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pong {
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disconnect {
    pub reason: DisconnectReason,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoAway {
    pub last_channel: u32,
}

// ---------------------------------------------------------------------------
// Session messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyRequest {
    pub term: String,
    pub cols: u16,
    pub rows: u16,
    pub pixel_w: u16,
    pub pixel_h: u16,
    pub modes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exec {
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Env {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowChange {
    pub cols: u16,
    pub rows: u16,
    pub pixel_w: u16,
    pub pixel_h: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    pub signal: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Data {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStatus {
    pub exit_code: u32,
    pub signal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitSignal {
    pub signal: String,
    pub core_dumped: bool,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Port forwarding
// ---------------------------------------------------------------------------

/// Ask the peer to connect to `host:port` and pipe the stream to it.
///
/// Sent at the start of a dedicated forwarding stream. The receiver of this
/// message is the side that dials the TCP connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardRequest {
    pub host: String,
    pub port: u16,
}

/// Whether the peer managed to connect to the requested target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForwardResponse {
    pub ok: bool,
    pub reason: Option<String>,
}

/// Client asks the server to listen on `bind_port` (127.0.0.1) and forward
/// incoming connections back to the client, which then dials `target_host:target_port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteForwardBind {
    pub bind_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

/// Server's answer to [`RemoteForwardBind`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteForwardBindResult {
    pub ok: bool,
    pub bound_port: u16,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Unified message enum
// ---------------------------------------------------------------------------

/// Every message that can travel in an RMP frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    Hello(Hello),
    HelloAck(HelloAck),
    Capabilities(Capabilities),
    AuthStart(AuthStart),
    AuthResponse(AuthResponse),
    AuthFinish(AuthFinish),
    AuthResult(AuthResult),
    KeyAuthRequest(KeyAuthRequest),
    KeyAuthChallenge(KeyAuthChallenge),
    KeyAuthProof(KeyAuthProof),
    ChannelOpen(ChannelOpen),
    ChannelOpenAck(ChannelOpenAck),
    ChannelClose(ChannelClose),
    WindowAdjust(WindowAdjust),
    Ping(Ping),
    Pong(Pong),
    Disconnect(Disconnect),
    GoAway(GoAway),
    RemoteForwardBind(RemoteForwardBind),
    RemoteForwardBindResult(RemoteForwardBindResult),
    PtyRequest(PtyRequest),
    Shell,
    Exec(Exec),
    Env(Env),
    WindowChange(WindowChange),
    Signal(Signal),
    Data(Data),
    Eof,
    ExitStatus(ExitStatus),
    ExitSignal(ExitSignal),
    ForwardRequest(ForwardRequest),
    ForwardResponse(ForwardResponse),
}

impl Message {
    /// The header code that must accompany this message.
    pub const fn frame_type(&self) -> FrameType {
        use Message::*;
        match self {
            Hello(_) => FrameType::Hello,
            HelloAck(_) => FrameType::HelloAck,
            Capabilities(_) => FrameType::Capabilities,
            AuthStart(_) => FrameType::AuthStart,
            AuthResponse(_) => FrameType::AuthResponse,
            AuthFinish(_) => FrameType::AuthFinish,
            AuthResult(_) => FrameType::AuthResult,
            KeyAuthRequest(_) => FrameType::KeyAuthRequest,
            KeyAuthChallenge(_) => FrameType::KeyAuthChallenge,
            KeyAuthProof(_) => FrameType::KeyAuthProof,
            ChannelOpen(_) => FrameType::ChannelOpen,
            ChannelOpenAck(_) => FrameType::ChannelOpenAck,
            ChannelClose(_) => FrameType::ChannelClose,
            WindowAdjust(_) => FrameType::WindowAdjust,
            Ping(_) => FrameType::Ping,
            Pong(_) => FrameType::Pong,
            Disconnect(_) => FrameType::Disconnect,
            GoAway(_) => FrameType::GoAway,
            RemoteForwardBind(_) => FrameType::RemoteForwardBind,
            RemoteForwardBindResult(_) => FrameType::RemoteForwardBindResult,
            PtyRequest(_) => FrameType::PtyRequest,
            Shell => FrameType::Shell,
            Exec(_) => FrameType::Exec,
            Env(_) => FrameType::Env,
            WindowChange(_) => FrameType::WindowChange,
            Signal(_) => FrameType::Signal,
            Data(_) => FrameType::Data,
            Eof => FrameType::Eof,
            ExitStatus(_) => FrameType::ExitStatus,
            ExitSignal(_) => FrameType::ExitSignal,
            ForwardRequest(_) => FrameType::ForwardRequest,
            ForwardResponse(_) => FrameType::ForwardResponse,
        }
    }

    /// Whether this message travels on the control stream.
    pub const fn is_control(&self) -> bool {
        self.frame_type().is_control()
    }

    /// Whether this message travels on a session stream.
    pub const fn is_session(&self) -> bool {
        self.frame_type().is_session()
    }

    /// Require that the message is a control message.
    pub fn expect_control(self) -> Result<Self, ProtoError> {
        if self.is_control() {
            Ok(self)
        } else {
            Err(ProtoError::UnexpectedType(self.frame_type()))
        }
    }

    /// Require that the message is a session message.
    pub fn expect_session(self) -> Result<Self, ProtoError> {
        if self.is_session() {
            Ok(self)
        } else {
            Err(ProtoError::UnexpectedType(self.frame_type()))
        }
    }
}
