//! Internal helper for root mode.
//!
//! When `rmp serve` runs as root, file transfer and forwarding must execute
//! with the target user's credentials. The server authenticates and then spawns
//! `runuser -l <user> -- <rmp> __helper`, writes the original request to the
//! helper's stdin and relays the framed stream in both directions.
//!
//! This command is hidden from `--help` and only performs operations with the
//! privileges of the user running it.

use anyhow::{bail, Result};
use rmp_proto::Message;
use std::net::SocketAddr;

/// Read one request from stdin and serve it over stdin/stdout.
pub async fn run() -> Result<()> {
    let mut stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let first = rmp_proto::read_message(&mut stdin).await?;

    // Audit events have no subscriber in the helper; the server logs the proxy
    // lifecycle. The peer is only used for those events.
    let peer = SocketAddr::from(([127, 0, 0, 1], 0));

    match first {
        Message::FileRequest(req) => {
            rmp_server::files::serve(stdout, stdin, req, peer).await?;
        }
        Message::ForwardRequest(req) => {
            rmp_server::forward::serve(stdout, stdin, req, peer).await?;
        }
        other => bail!("unexpected helper request: {:?}", other.frame_type()),
    }
    Ok(())
}
