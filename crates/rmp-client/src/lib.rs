//! # rmp-client
//!
//! Client library for RMP: encrypted transport, TOFU server verification,
//! OPAQUE password authentication and interactive/exec sessions.

#![deny(unsafe_code)]

pub mod client;
pub mod forward;
pub mod term;

pub use client::{transport, Client, ClientOptions, ExecOutput, Transport};
pub use forward::local_forward;
pub use rmp_crypto::{DeviceKey, Fingerprint, KnownHosts, Trust};
