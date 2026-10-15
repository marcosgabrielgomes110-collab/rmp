//! File transfer (server side).
//!
//! A file stream begins with a [`FileRequest`]; the server replies with a
//! [`FileResponse`] and then the bytes flow as `Data` messages terminated by
//! `Eof` (for `Put`, the server confirms with an `ExitStatus`).

use crate::audit::audit;
use anyhow::{Context, Result};
use quinn::{RecvStream, SendStream};
use rmp_proto::{Data, ExitStatus, FileOp, FileRequest, FileResponse, Message};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CHUNK: usize = 64 * 1024;

/// Resolve a requested path. Relative paths are taken from the server user's
/// home directory; absolute paths are used as-is (the OS enforces permissions).
fn resolve(path: &str) -> PathBuf {
    let p = PathBuf::from(path);
    if p.is_absolute() {
        return p;
    }
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(p),
        None => p,
    }
}

/// Handle a file-transfer stream.
pub async fn serve(
    mut send: SendStream,
    mut recv: RecvStream,
    req: FileRequest,
    peer: SocketAddr,
) -> Result<()> {
    let path = resolve(&req.path);
    match req.op {
        FileOp::Get => get(&mut send, &path, peer).await,
        FileOp::Put => put(&mut send, &mut recv, &path, peer).await,
    }
}

async fn get(send: &mut SendStream, path: &Path, peer: SocketAddr) -> Result<()> {
    let meta = match fs::metadata(path).await {
        Ok(m) if m.is_file() => m,
        Ok(_) => return refuse(send, "not a regular file").await,
        Err(e) => return refuse(send, &e.to_string()).await,
    };

    rmp_proto::write_message(
        send,
        &Message::FileResponse(FileResponse {
            ok: true,
            size: meta.len(),
            reason: None,
        }),
    )
    .await?;

    let mut file = fs::File::open(path)
        .await
        .context("opening file for read")?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        rmp_proto::write_message(
            send,
            &Message::Data(Data {
                data: buf[..n].to_vec(),
            }),
        )
        .await?;
    }
    rmp_proto::write_message(send, &Message::Eof).await?;

    audit!(event = "file.get", peer = %peer, path = %path.display(), size = meta.len());
    Ok(())
}

async fn put(
    send: &mut SendStream,
    recv: &mut RecvStream,
    path: &Path,
    peer: SocketAddr,
) -> Result<()> {
    if let Ok(m) = fs::metadata(path).await {
        if m.is_dir() {
            return refuse(send, "target is a directory").await;
        }
    }

    let mut file = match fs::File::create(path).await {
        Ok(f) => f,
        Err(e) => return refuse(send, &e.to_string()).await,
    };

    rmp_proto::write_message(
        send,
        &Message::FileResponse(FileResponse {
            ok: true,
            size: 0,
            reason: None,
        }),
    )
    .await?;

    let mut total: u64 = 0;
    loop {
        match rmp_proto::read_message(recv).await {
            Ok(Message::Data(d)) => {
                file.write_all(&d.data).await?;
                total += d.data.len() as u64;
            }
            Ok(Message::Eof) => break,
            Ok(_) => {}
            Err(_) => break, // client closed the stream
        }
    }
    file.flush().await?;
    drop(file);

    rmp_proto::write_message(
        send,
        &Message::ExitStatus(ExitStatus {
            exit_code: 0,
            signal: None,
        }),
    )
    .await?;

    audit!(event = "file.put", peer = %peer, path = %path.display(), size = total);
    Ok(())
}

async fn refuse(send: &mut SendStream, reason: &str) -> Result<()> {
    rmp_proto::write_message(
        send,
        &Message::FileResponse(FileResponse {
            ok: false,
            size: 0,
            reason: Some(reason.to_string()),
        }),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_paths_are_kept() {
        assert_eq!(resolve("/etc/hosts"), PathBuf::from("/etc/hosts"));
    }

    #[test]
    fn relative_paths_use_home() {
        std::env::set_var("HOME", "/home/tester");
        assert_eq!(resolve("file.txt"), PathBuf::from("/home/tester/file.txt"));
    }
}
