//! # rmp-server
//!
//! QUIC listener, password authentication (OPAQUE) and PTY/exec session
//! handling for RMP.

#![forbid(unsafe_code)]

pub mod auth;
pub mod files;
pub mod forward;
pub mod keys;
pub mod net;
pub mod server;
pub mod session;

mod audit;

pub use auth::{Authed, Principal};
pub use keys::AuthorizedKeys;
pub use net::Cidr;
pub use server::{bind, quic_server_config, serve, ServerOptions};
