//! `rmp cp` — copy a file to/from a remote machine.
//!
//! One side must be a remote spec `user@host:path`; the other is a local path.
//! The remote port defaults to 2222 and can be set with `--port`.

use crate::authflow;
use crate::config::FileConfig;
use crate::logging::AUDIT_TARGET;
use anyhow::{bail, Result};
use rmp_dirs::Layout;

/// Run a copy.
pub async fn run(
    src: &str,
    dst: &str,
    layout: &Layout,
    port: u16,
    accept_new_flag: bool,
) -> Result<i32> {
    let _ = layout.ensure_config();
    let config = FileConfig::load_or_default(&layout.config_file()).unwrap_or_default();
    let _log = crate::logging::init(layout, &config.logging).ok();
    let accept_new = accept_new_flag || config.client.accept_new_hosts;
    let idle_secs = config.client.idle_timeout_secs;

    let (remote, remote_path, local_path, upload) = classify(src, dst)?;
    let target = authflow::parse_target(&remote, port)?;

    let client =
        authflow::connect_authenticated(layout, &config, &target, accept_new, idle_secs, false)
            .await?;

    if upload {
        let n = client.upload(&local_path, &remote_path).await?;
        tracing::info!(target: AUDIT_TARGET, event = "cp.upload", host = %target.key(),
                       path = %remote_path, bytes = n);
        println!("enviado   {local_path}  ->  {remote}:{remote_path}  ({n} bytes)");
    } else {
        let n = client.download(&remote_path, &local_path).await?;
        tracing::info!(target: AUDIT_TARGET, event = "cp.download", host = %target.key(),
                       path = %remote_path, bytes = n);
        println!("recebido  {remote}:{remote_path}  ->  {local_path}  ({n} bytes)");
    }
    Ok(0)
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
