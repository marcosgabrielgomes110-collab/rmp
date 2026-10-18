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

/// Resolve a requested path. `~` / `~/...` expand to the server user's home;
/// relative paths are taken from home; absolute paths are used as-is.
fn resolve(path: &str) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);

    if path == "~" {
        if let Some(home) = &home {
            return home.clone();
        }
    }
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = &home {
            return home.join(rest);
        }
    }

    let p = PathBuf::from(path);
    if p.is_absolute() {
        return p;
    }
    match home {
        Some(home) => home.join(p),
        None => p,
    }
}

/// The Unix permission bits of a file (0 on non-Unix platforms).
#[cfg(unix)]
fn unix_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn unix_mode(_meta: &std::fs::Metadata) -> u32 {
    0
}

/// Apply a Unix mode to a path (no-op for `mode == 0` or non-Unix).
fn apply_mode(path: &Path, mode: u32) {
    if mode == 0 {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
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
        FileOp::Put => put(&mut send, &mut recv, &path, req.mode, peer).await,
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
            mode: unix_mode(&meta),
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
    mode: u32,
    peer: SocketAddr,
) -> Result<()> {
    if let Ok(m) = fs::metadata(path).await {
        if m.is_dir() {
            return refuse(send, "target is a directory").await;
        }
    }

    // Write to a sibling temporary file and rename only after the client sends
    // `Eof`. An interrupted upload must not leave a truncated destination that
    // looks like a successful copy.
    let partial = partial_path(path);
    let mut file = match fs::File::create(&partial).await {
        Ok(f) => f,
        Err(e) => return refuse(send, &e.to_string()).await,
    };

    rmp_proto::write_message(
        send,
        &Message::FileResponse(FileResponse {
            ok: true,
            size: 0,
            reason: None,
            mode: 0,
        }),
    )
    .await?;

    let mut total: u64 = 0;
    loop {
        match rmp_proto::read_message(recv).await {
            Ok(Message::Data(d)) => {
                if let Err(e) = file.write_all(&d.data).await {
                    drop(file);
                    let _ = fs::remove_file(&partial).await;
                    return Err(e).context("writing upload");
                }
                total += d.data.len() as u64;
            }
            Ok(Message::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                drop(file);
                let _ = fs::remove_file(&partial).await;
                audit!(event = "file.put.aborted", peer = %peer, path = %path.display(),
                       size = total, reason = %e);
                return Err(e).context("upload interrupted before Eof");
            }
        }
    }
    if let Err(e) = file.flush().await {
        drop(file);
        let _ = fs::remove_file(&partial).await;
        return Err(e).context("flushing upload");
    }
    drop(file);

    apply_mode(&partial, mode);
    if let Err(e) = rename_replace(&partial, path).await {
        let _ = fs::remove_file(&partial).await;
        let _ = rmp_proto::write_message(
            send,
            &Message::ExitStatus(ExitStatus {
                exit_code: 1,
                signal: None,
            }),
        )
        .await;
        return Err(e).context("moving upload into place");
    }

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

/// Sibling temporary path used while an upload is in flight.
fn partial_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("rmp-upload");
    path.with_file_name(format!(".{name}.rmp-part"))
}

/// Rename `from` over `to`, replacing the destination if the platform requires.
async fn rename_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    if fs::rename(from, to).await.is_ok() {
        return Ok(());
    }
    let _ = fs::remove_file(to).await;
    fs::rename(from, to).await
}

async fn refuse(send: &mut SendStream, reason: &str) -> Result<()> {
    rmp_proto::write_message(
        send,
        &Message::FileResponse(FileResponse {
            ok: false,
            size: 0,
            reason: Some(reason.to_string()),
            mode: 0,
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

    #[test]
    fn tilde_expands_to_home() {
        std::env::set_var("HOME", "/home/tester");
        assert_eq!(resolve("~"), PathBuf::from("/home/tester"));
        assert_eq!(resolve("~/bin/x"), PathBuf::from("/home/tester/bin/x"));
    }
}
