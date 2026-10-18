//! `rmp cp` — copy a file to/from a remote machine.
//!
//! One side must be a remote spec `user@host:path`; the other is a local path.
//! The remote port defaults to 2222 and can be set with `--port`.

use crate::authflow;
use crate::config::FileConfig;
use crate::logging::AUDIT_TARGET;
use anyhow::{bail, Context, Result};
use rmp_client::Client;
use rmp_dirs::Layout;
use rmp_proto::FileKind;
use std::path::{Path, PathBuf};

/// Run a copy.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    src: &str,
    dst: &str,
    layout: &Layout,
    port: u16,
    accept_new_flag: bool,
    update_host_key_flag: bool,
    fingerprint: Option<&str>,
    show_progress: bool,
    recursive: bool,
) -> Result<i32> {
    let _ = layout.ensure_config();
    let config = FileConfig::load_or_default(&layout.config_file())
        .with_context(|| format!("reading {}", layout.config_file().display()))?;
    let _log = crate::logging::init(layout, &config.logging).ok();
    let accept_new = accept_new_flag || config.client.accept_new_hosts;
    let idle_secs = config.client.idle_timeout_secs;
    let pinned = match fingerprint {
        Some(hex) => Some(rmp_crypto::Fingerprint::from_hex(hex).context("invalid --fingerprint")?),
        None => None,
    };

    let (remote, remote_path, local_path, upload) = classify(src, dst)?;
    let target = authflow::parse_target(&remote, port)?;

    let client = authflow::connect_authenticated(
        layout,
        &config,
        &target,
        accept_new,
        update_host_key_flag,
        idle_secs,
        false,
        pinned,
    )
    .await?;

    if recursive {
        let local = Path::new(&local_path);
        let (files, bytes) = if upload {
            upload_dir(&client, local, &remote_path, show_progress).await?
        } else {
            download_dir(&client, &remote_path, local, show_progress).await?
        };
        let event = if upload {
            "cp.upload_dir"
        } else {
            "cp.download_dir"
        };
        tracing::info!(target: AUDIT_TARGET, event = event, host = %target.key(),
                       path = %remote_path, files = files, bytes = bytes);
        let verb = if upload { "enviado(s)" } else { "recebido(s)" };
        println!("{verb} {files} arquivo(s), {bytes} bytes");
        return Ok(0);
    }

    if upload {
        if let Ok(meta) = tokio::fs::metadata(&local_path).await {
            if meta.is_dir() {
                bail!("{} is a directory; use -r/--recursive", local_path);
            }
        }
        let n = if show_progress {
            let mut last = 0u64;
            let n = client
                .upload_with(&local_path, &remote_path, |done| {
                    if done.saturating_sub(last) >= 1024 * 1024 {
                        eprint!("\r[rmp] enviando {done} bytes");
                        last = done;
                    }
                })
                .await?;
            eprintln!();
            n
        } else {
            client.upload(&local_path, &remote_path).await?
        };
        tracing::info!(target: AUDIT_TARGET, event = "cp.upload", host = %target.key(),
                       path = %remote_path, bytes = n);
        println!("enviado   {local_path}  ->  {remote}:{remote_path}  ({n} bytes)");
    } else {
        let n = if show_progress {
            let mut last = 0u64;
            let n = client
                .download_with(&remote_path, &local_path, |done| {
                    if done.saturating_sub(last) >= 1024 * 1024 {
                        eprint!("\r[rmp] recebendo {done} bytes");
                        last = done;
                    }
                })
                .await?;
            eprintln!();
            n
        } else {
            client.download(&remote_path, &local_path).await?
        };
        tracing::info!(target: AUDIT_TARGET, event = "cp.download", host = %target.key(),
                       path = %remote_path, bytes = n);
        println!("recebido  {remote}:{remote_path}  ->  {local_path}  ({n} bytes)");
    }
    Ok(0)
}

/// Join a remote directory and a single entry name.
fn join_remote(base: &str, name: &str) -> String {
    if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Reject entry names that could escape the destination directory.
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

#[cfg(unix)]
fn local_mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0)
}

#[cfg(not(unix))]
fn local_mode(_path: &Path) -> u32 {
    0
}

#[cfg(unix)]
fn apply_dir_mode(path: &Path, mode: u32) {
    if mode == 0 {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777));
}

#[cfg(not(unix))]
fn apply_dir_mode(_path: &Path, _mode: u32) {}

/// Upload a local directory tree, creating remote directories as needed.
async fn upload_dir(
    client: &Client,
    local_root: &Path,
    remote_root: &str,
    show_progress: bool,
) -> Result<(u64, u64)> {
    let meta = tokio::fs::metadata(local_root)
        .await
        .with_context(|| format!("reading {}", local_root.display()))?;
    if !meta.is_dir() {
        bail!("{} is not a directory", local_root.display());
    }

    let mut stack: Vec<(PathBuf, String)> =
        vec![(local_root.to_path_buf(), remote_root.to_string())];
    let mut files = 0u64;
    let mut bytes = 0u64;

    while let Some((local_dir, remote_dir)) = stack.pop() {
        client.mkdir(&remote_dir, local_mode(&local_dir)).await?;

        let mut entries = tokio::fs::read_dir(&local_dir)
            .await
            .with_context(|| format!("reading {}", local_dir.display()))?;
        while let Some(entry) = entries.next_entry().await? {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                eprintln!("[rmp] pulando nome não-UTF-8 em {}", local_dir.display());
                continue;
            };
            if !safe_name(&name) {
                bail!("unsafe file name {:?} in {}", name, local_dir.display());
            }
            let file_type = entry.file_type().await?;
            let remote_child = join_remote(&remote_dir, &name);
            let local_child = entry.path();

            if file_type.is_dir() {
                stack.push((local_child, remote_child));
            } else if file_type.is_file() {
                let size = entry.metadata().await?.len();
                client
                    .upload(&local_child, &remote_child)
                    .await
                    .with_context(|| format!("uploading {}", local_child.display()))?;
                files += 1;
                bytes += size;
                if show_progress {
                    eprintln!("[rmp] enviado {remote_child} ({size} bytes)");
                }
            } else {
                eprintln!(
                    "[rmp] pulando {} (não é arquivo nem diretório)",
                    local_child.display()
                );
            }
        }
    }
    Ok((files, bytes))
}

/// Download a remote directory tree, creating local directories as needed.
async fn download_dir(
    client: &Client,
    remote_root: &str,
    local_root: &Path,
    show_progress: bool,
) -> Result<(u64, u64)> {
    let mut stack: Vec<(String, PathBuf, u32)> =
        vec![(remote_root.to_string(), local_root.to_path_buf(), 0)];
    let mut files = 0u64;
    let mut bytes = 0u64;

    while let Some((remote_dir, local_dir, mode)) = stack.pop() {
        tokio::fs::create_dir_all(&local_dir)
            .await
            .with_context(|| format!("creating {}", local_dir.display()))?;
        apply_dir_mode(&local_dir, mode);

        for entry in client.list(&remote_dir).await? {
            if !safe_name(&entry.name) {
                bail!("remote sent unsafe file name {:?}", entry.name);
            }
            let remote_child = join_remote(&remote_dir, &entry.name);
            let local_child = local_dir.join(&entry.name);

            match entry.kind {
                FileKind::Dir => stack.push((remote_child, local_child, entry.mode)),
                FileKind::File => {
                    client
                        .download(&remote_child, &local_child)
                        .await
                        .with_context(|| format!("downloading {remote_child}"))?;
                    files += 1;
                    bytes += entry.size;
                    if show_progress {
                        eprintln!("[rmp] recebido {remote_child} ({} bytes)", entry.size);
                    }
                }
                FileKind::Symlink => {
                    eprintln!("[rmp] pulando symlink {remote_child}");
                }
            }
        }
    }
    Ok((files, bytes))
}

/// Split a remote spec into `(user@host[:port], path)`.
///
/// Accepts `user@host:path` (scp-style) and `user@host/path`, and bracketed
/// IPv6 hosts: `user@[::1]:path` / `user@[::1]/path`.
fn split_remote(s: &str) -> Option<(String, String)> {
    let (user, rest) = s.split_once('@')?;
    if user.is_empty() || user.contains('/') {
        return None;
    }

    // Bracketed IPv6 host.
    if let Some(after) = rest.strip_prefix('[') {
        let end = after.find(']')?;
        let host = &after[..end];
        let tail = &after[end + 1..];
        let path = tail.strip_prefix(':').unwrap_or(tail).to_string();
        if host.is_empty() || path.is_empty() {
            return None;
        }
        return Some((format!("{user}@[{host}]"), path));
    }

    // `user@host:path`
    if let Some((host, path)) = rest.split_once(':') {
        if host.is_empty() || path.is_empty() {
            return None;
        }
        return Some((format!("{user}@{host}"), path.to_string()));
    }

    // `user@host/path` (the path keeps its leading '/')
    if let Some(idx) = rest.find('/') {
        let (host, path) = rest.split_at(idx);
        if host.is_empty() || path.is_empty() {
            return None;
        }
        return Some((format!("{user}@{host}"), path.to_string()));
    }

    None
}

/// Returns `(remote_spec, remote_path, local_path, upload)`.
fn classify(src: &str, dst: &str) -> Result<(String, String, String, bool)> {
    match (split_remote(src), split_remote(dst)) {
        (Some(_), Some(_)) => bail!("both paths are remote; not supported"),
        (Some((remote, path)), None) => Ok((remote, path, dst.to_string(), false)),
        (None, Some((remote, path))) => Ok((remote, path, src.to_string(), true)),
        (None, None) => bail!(
            "one side must be a remote spec `user@host:path` \
             (e.g. dev@host:/tmp/file or dev@host:~/bin/file)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_remote_sides() {
        let (r, rp, lp, up) = classify("dev@host:/tmp/a", "./a").unwrap();
        assert_eq!(
            (r.as_str(), rp.as_str(), lp.as_str(), up),
            ("dev@host", "/tmp/a", "./a", false)
        );

        let (r, rp, lp, up) = classify("./a", "dev@host:/tmp/a").unwrap();
        assert_eq!(
            (r.as_str(), rp.as_str(), lp.as_str(), up),
            ("dev@host", "/tmp/a", "./a", true)
        );
    }

    #[test]
    fn both_local_is_an_error() {
        assert!(classify("./a", "./b").is_err());
    }

    #[test]
    fn accepts_slash_separator_and_ipv6() {
        // `user@host/path` (path is absolute)
        let (r, rp, _, up) = classify("./a", "dev@host/usr/local/bin/x").unwrap();
        assert_eq!(
            (r.as_str(), rp.as_str(), up),
            ("dev@host", "/usr/local/bin/x", true)
        );
        // bracketed IPv6
        let (r, rp, _, up) = classify("./a", "dev@[::1]:/tmp/x").unwrap();
        assert_eq!((r.as_str(), rp.as_str(), up), ("dev@[::1]", "/tmp/x", true));
        let (r, rp, _, _) = classify("dev@[::1]/tmp/x", "./a").unwrap();
        assert_eq!((r.as_str(), rp.as_str()), ("dev@[::1]", "/tmp/x"));
    }

    #[test]
    fn parses_ipv6_targets() {
        let t = crate::authflow::parse_target("dev@[::1]:2222", 2222).unwrap();
        assert_eq!((t.host.as_str(), t.port), ("::1", 2222));
        assert_eq!(t.key(), "[::1]:2222");

        let t = crate::authflow::parse_target("dev@::1", 2222).unwrap();
        assert_eq!((t.host.as_str(), t.port), ("::1", 2222));

        let t = crate::authflow::parse_target("dev@192.168.56.111:3333", 2222).unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.key().as_str()),
            ("192.168.56.111", 3333, "192.168.56.111:3333")
        );
    }
}
