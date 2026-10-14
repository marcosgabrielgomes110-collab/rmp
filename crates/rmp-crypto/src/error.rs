//! Errors of the cryptography layer.

use thiserror::Error;

/// Anything that can go wrong while loading keys, building TLS configs or
/// running the OPAQUE authentication.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("failed to generate or parse a key/certificate: {0}")]
    Rcgen(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS configuration error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("invalid hexadecimal fingerprint")]
    BadFingerprint,

    #[error("host key mismatch for {host}: expected {expected}, server presented {got}")]
    HostKeyMismatch {
        host: String,
        expected: String,
        got: String,
    },

    #[error("unknown host {0}: refusing to connect (strict host key checking)")]
    UnknownHost(String),

    #[error("password authentication failed")]
    AuthFailed,

    #[error("OPAQUE protocol error: {0}")]
    Opaque(String),

    #[error("password file is malformed or truncated")]
    MalformedPasswordFile,

    #[error("invalid device key material")]
    BadKeyMaterial,
}

impl From<rcgen::Error> for CryptoError {
    fn from(e: rcgen::Error) -> Self {
        CryptoError::Rcgen(e.to_string())
    }
}

/// Convert any OPAQUE protocol error into [`CryptoError::Opaque`].
///
/// The OPAQUE error type is generic over the KSF error; the bound keeps this
/// conversion usable for every instantiation.
pub fn opaque_err<T: std::fmt::Display>(e: opaque_ke::errors::ProtocolError<T>) -> CryptoError {
    CryptoError::Opaque(e.to_string())
}
