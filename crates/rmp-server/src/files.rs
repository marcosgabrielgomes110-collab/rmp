//! File transfer (server side).
//!
//! A file stream begins with a [`FileRequest`]; the server replies with a
//! [`FileResponse`] and then the bytes flow as `Data` messages terminated by
//! `Eof` (for `Put`, the server confirms with an `ExitStatus`).

use crate::audit::audit;
use anyhow::{Context, Result};
use rmp_proto::{
    Data, ExitStatus, FileEntry, FileKind, FileOp, FileRequest, FileResponse, Message,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
///
/// The I/O is generic so the same implementation can run over a QUIC stream
/// (server) or over the helper process's stdin/stdout (root mode).
pub async fn serve<S, R>(mut send: S, mut recv: R, req: FileRequest, peer: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    let path = resolve(&req.path);
    match req.op {
        FileOp::Get => get(&mut send, &path, peer).await,
        FileOp::Put => put(&mut send, &mut recv, &path, req.mode, req.size, peer).await,
        FileOp::Mkdir => mkdir(&mut send, &path, req.mode, peer).await,
        FileOp::List => list(&mut send, &path, peer).await,
    }
}

async fn get<S>(send: &mut S, path: &Path, peer: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin + Send,
{
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

async fn mkdir<S>(send: &mut S, path: &Path, mode: u32, peer: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin + Send,
{
    if let Err(e) = fs::create_dir_all(path).await {
        return refuse(send, &e.to_string()).await;
    }
    if mode != 0 {
        apply_mode(path, mode);
    }
    rmp_proto::write_message(
        send,
        &Message::FileResponse(FileResponse {
            ok: true,
            size: 0,
            reason: None,
            mode,
        }),
    )
    .await?;
    rmp_proto::write_message(
        send,
        &Message::ExitStatus(ExitStatus {
            exit_code: 0,
            signal: None,
        }),
    )
    .await?;

    audit!(event = "file.mkdir", peer = %peer, path = %path.display());
    Ok(())
}

async fn list<S>(send: &mut S, path: &Path, peer: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin + Send,
{
    let meta = match fs::metadata(path).await {
        Ok(m) if m.is_dir() => m,
        Ok(_) => return refuse(send, "not a directory").await,
        Err(e) => return refuse(send, &e.to_string()).await,
    };

    rmp_proto::write_message(
        send,
        &Message::FileResponse(FileResponse {
            ok: true,
            size: 0,
            reason: None,
            mode: unix_mode(&meta),
        }),
    )
    .await?;

    let mut entries = fs::read_dir(path)
        .await
        .with_context(|| format!("listing {}", path.display()))?;
    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        let kind = if file_type.is_dir() {
            FileKind::Dir
        } else if file_type.is_file() {
            FileKind::File
        } else if file_type.is_symlink() {
            FileKind::Symlink
        } else {
            // Sockets, devices, FIFOs: skip.
            continue;
        };
        // The protocol carries UTF-8 names; skip entries that cannot be
        // represented instead of silently mangling them.
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let meta = entry.metadata().await?;
        rmp_proto::write_message(
            send,
            &Message::FileEntry(FileEntry {
                name,
                kind,
                size: meta.len(),
                mode: unix_mode(&meta),
            }),
        )
        .await?;
    }
    rmp_proto::write_message(send, &Message::Eof).await?;

    audit!(event = "file.list", peer = %peer, path = %path.display());
    Ok(())
}

/// Temporary path next to `path`, so the final rename stays on one filesystem.
fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("upload");
    path.with_file_name(format!(
        ".{name}.rmp-{}-{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ))
}

async fn report_put_failure<S>(
    send: &mut S,
    tmp: &Path,
    peer: SocketAddr,
    path: &Path,
    reason: &str,
    total: u64,
) where
    S: AsyncWrite + Unpin + Send,
{
    let _ = fs::remove_file(tmp).await;
    audit!(event = "file.put_failed", peer = %peer, path = %path.display(),
           size = total, reason = %reason);
    let _ = rmp_proto::write_message(
        send,
        &Message::ExitStatus(ExitStatus {
            exit_code: 1,
            signal: None,
        }),
    )
    .await;
}

async fn put<S, R>(
    send: &mut S,
    recv: &mut R,
    path: &Path,
    mode: u32,
    expected_size: u64,
    peer: SocketAddr,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin + Send,
{
    if let Ok(m) = fs::metadata(path).await {
        if m.is_dir() {
            return refuse(send, "target is a directory").await;
        }
    }

    // Never write directly to the destination: an interrupted upload must not
    // leave a partial file in place. `create_new` also avoids following a
    // symlink planted at the temporary path.
    let tmp = temp_path(path);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = match options.open(&tmp).await {
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
                    report_put_failure(send, &tmp, peer, path, &e.to_string(), total).await;
                    return Ok(());
                }
                total += d.data.len() as u64;
            }
            Ok(Message::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                // Client vanished or sent a malformed frame: abort, do not
                // commit the partial file.
                drop(file);
                report_put_failure(send, &tmp, peer, path, &e.to_string(), total).await;
                return Ok(());
            }
        }
    }

    if total != expected_size {
        drop(file);
        report_put_failure(
            send,
            &tmp,
            peer,
            path,
            &format!("size mismatch: received {total} of {expected_size} bytes"),
            total,
        )
        .await;
        return Ok(());
    }

    if let Err(e) = file.flush().await {
        drop(file);
        report_put_failure(send, &tmp, peer, path, &e.to_string(), total).await;
        return Ok(());
    }
    if let Err(e) = file.sync_all().await {
        drop(file);
        report_put_failure(send, &tmp, peer, path, &e.to_string(), total).await;
        return Ok(());
    }
    drop(file);

    // Set the final mode before publishing the file, so there is no window
    // where it is readable with the default mode.
    apply_mode(&tmp, mode);

    // `rename` replaces atomically on Unix; Windows requires removing the old
    // destination first.
    #[cfg(windows)]
    {
        let _ = fs::remove_file(path).await;
    }
    if let Err(e) = fs::rename(&tmp, path).await {
        report_put_failure(send, &tmp, peer, path, &e.to_string(), total).await;
        return Ok(());
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

async fn refuse<S>(send: &mut S, reason: &str) -> Result<()>
where
    S: AsyncWrite + Unpin + Send,
{
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

    fn request(op: rmp_proto::FileOp, path: &Path, mode: u32, size: u64) -> FileRequest {
        FileRequest {
            op,
            path: path.to_string_lossy().into_owned(),
            mode,
            size,
        }
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }

    #[tokio::test]
    async fn mkdir_creates_directory_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new/nested");

        let (server, client) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, _client_write) = tokio::io::split(client);
        let task = tokio::spawn(serve(
            server_write,
            server_read,
            request(rmp_proto::FileOp::Mkdir, &path, 0o750, 0),
            peer(),
        ));

        match rmp_proto::read_message(&mut client_read).await.unwrap() {
            Message::FileResponse(r) => assert!(r.ok),
            other => panic!("unexpected response: {other:?}"),
        }
        match rmp_proto::read_message(&mut client_read).await.unwrap() {
            Message::ExitStatus(s) => assert_eq!(s.exit_code, 0),
            other => panic!("unexpected response: {other:?}"),
        }
        task.await.unwrap().unwrap();
        assert!(path.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o750);
        }
    }

    #[tokio::test]
    async fn list_returns_entries() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("file.txt"), b"hello").unwrap();

        let (server, client) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, _client_write) = tokio::io::split(client);
        let task = tokio::spawn(serve(
            server_write,
            server_read,
            request(rmp_proto::FileOp::List, dir.path(), 0, 0),
            peer(),
        ));

        match rmp_proto::read_message(&mut client_read).await.unwrap() {
            Message::FileResponse(r) => assert!(r.ok),
            other => panic!("unexpected response: {other:?}"),
        }

        let mut entries = std::collections::HashMap::new();
        loop {
            match rmp_proto::read_message(&mut client_read).await.unwrap() {
                Message::FileEntry(entry) => {
                    entries.insert(entry.name, entry.kind);
                }
                Message::Eof => break,
                other => panic!("unexpected message: {other:?}"),
            }
        }
        assert_eq!(entries.get("file.txt"), Some(&FileKind::File));
        assert_eq!(entries.get("sub"), Some(&FileKind::Dir));
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn get_works_over_generic_stream() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("source.txt");
        std::fs::write(&path, b"generic-get").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let (server, client) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, _client_write) = tokio::io::split(client);
        let task = tokio::spawn(serve(
            server_write,
            server_read,
            request(rmp_proto::FileOp::Get, &path, 0, 0),
            peer(),
        ));

        let response = rmp_proto::read_message(&mut client_read).await.unwrap();
        let mode = match response {
            Message::FileResponse(r) => {
                assert!(r.ok);
                assert_eq!(r.size, 11);
                r.mode
            }
            other => panic!("unexpected response: {other:?}"),
        };
        #[cfg(unix)]
        assert_eq!(mode & 0o777, 0o755);

        let mut data = Vec::new();
        loop {
            match rmp_proto::read_message(&mut client_read).await.unwrap() {
                Message::Data(d) => data.extend_from_slice(&d.data),
                Message::Eof => break,
                other => panic!("unexpected message: {other:?}"),
            }
        }
        assert_eq!(data, b"generic-get");
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn put_verifies_size_and_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target.txt");
        let payload = b"generic-put";

        let (server, client) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let mode = 0o640;
        let task = tokio::spawn(serve(
            server_write,
            server_read,
            request(rmp_proto::FileOp::Put, &path, mode, payload.len() as u64),
            peer(),
        ));

        match rmp_proto::read_message(&mut client_read).await.unwrap() {
            Message::FileResponse(r) => assert!(r.ok),
            other => panic!("unexpected response: {other:?}"),
        }
        rmp_proto::write_message(
            &mut client_write,
            &Message::Data(Data {
                data: payload.to_vec(),
            }),
        )
        .await
        .unwrap();
        rmp_proto::write_message(&mut client_write, &Message::Eof)
            .await
            .unwrap();

        match rmp_proto::read_message(&mut client_read).await.unwrap() {
            Message::ExitStatus(s) => assert_eq!(s.exit_code, 0),
            other => panic!("unexpected response: {other:?}"),
        }
        task.await.unwrap().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), payload);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let got = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(got, mode);
        }
    }

    #[tokio::test]
    async fn put_rejects_size_mismatch_without_publishing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target.txt");

        let (server, client) = tokio::io::duplex(64 * 1024);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let task = tokio::spawn(serve(
            server_write,
            server_read,
            request(rmp_proto::FileOp::Put, &path, 0o600, 99),
            peer(),
        ));

        match rmp_proto::read_message(&mut client_read).await.unwrap() {
            Message::FileResponse(r) => assert!(r.ok),
            other => panic!("unexpected response: {other:?}"),
        }
        rmp_proto::write_message(
            &mut client_write,
            &Message::Data(Data {
                data: b"short".to_vec(),
            }),
        )
        .await
        .unwrap();
        rmp_proto::write_message(&mut client_write, &Message::Eof)
            .await
            .unwrap();

        match rmp_proto::read_message(&mut client_read).await.unwrap() {
            Message::ExitStatus(s) => assert_eq!(s.exit_code, 1),
            other => panic!("unexpected response: {other:?}"),
        }
        task.await.unwrap().unwrap();
        assert!(!path.exists(), "a failed upload must not publish a file");
    }
}
