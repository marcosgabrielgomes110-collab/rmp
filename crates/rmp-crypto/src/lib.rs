//! # rmp-crypto
//!
//! The cryptography layer of RMP:
//!
//! * [`hostkey`] — Ed25519 host identity and certificate fingerprints.
//! * [`known_hosts`] — trust-on-first-use storage of server fingerprints.
//! * [`password`] — OPAQUE (RFC 9807) password authentication.
//! * [`tls`] — TLS 1.3 (+ hybrid post-quantum) configuration with a
//!   fingerprint-pinning client verifier.
//!
//! The design rule throughout is *fail closed*: any mismatch or parse error
//! aborts the connection before a credential is exposed.

#![forbid(unsafe_code)]

pub mod device;
pub mod error;
pub mod hostkey;
pub mod known_hosts;
pub mod password;
pub mod tls;

pub use device::{verify as verify_device_signature, DeviceKey};
pub use error::CryptoError;
pub use hostkey::{Fingerprint, HostKey};
pub use known_hosts::{KnownHosts, Trust};
pub use password::{PasswordFile, Setup as OpaqueSetup};
pub use rmp_dirs::{HOST_CERT_FILE, HOST_KEY_FILE};
pub use tls::{client_config, server_config, ObservedFingerprint};
