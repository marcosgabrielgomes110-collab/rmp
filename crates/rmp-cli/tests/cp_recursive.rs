//! End-to-end test for `rmp cp -r` using a real server and a device key.

#![cfg(unix)]

use rmp_crypto::{password, DeviceKey, HostKey};
use rmp_server::{bind, serve, AuthorizedKeys, ServerOptions};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn cp_recursive_uploads_and_downloads_trees() {
    let dir = tempfile::tempdir().unwrap();
    let layout = dir.path();

    let host_key = HostKey::generate().unwrap();
    let setup = password::new_setup();
    let password_file = password::enroll(b"unused", "alice", &setup).unwrap();

    let device = DeviceKey::generate();
    let identities = layout.join("identities");
    let authorized = layout.join("authorized_keys");
    AuthorizedKeys::load(&authorized)
        .unwrap()
        .add(&device.public_key(), "cp-recursive-test")
        .unwrap();

    let mut opts = ServerOptions::new("alice".to_string(), host_key, setup, password_file);
    opts.authorized_keys_path = authorized;
    let endpoint = bind("127.0.0.1:0".parse().unwrap(), &opts).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(serve(endpoint, Arc::new(opts)));

    device
        .save(&identities.join(format!("127.0.0.1_{}__alice.key", addr.port())))
        .unwrap();

    // Local source tree.
    let source = layout.join("tree");
    std::fs::create_dir_all(source.join("sub")).unwrap();
    std::fs::create_dir_all(source.join("empty")).unwrap();
    std::fs::write(source.join("root.txt"), b"root-file").unwrap();
    std::fs::write(source.join("a b.txt"), b"with space").unwrap();
    std::fs::write(source.join("sub/file.txt"), b"nested").unwrap();
    std::fs::write(source.join("sub/run.sh"), b"#!/bin/sh\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            source.join("sub/run.sh"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }

    let remote = layout.join("remote");
    let remote_spec = format!("alice@127.0.0.1:{}", remote.display());
    let port = addr.port().to_string();

    // Upload.
    let output = run_cp(&[
        "-r",
        source.to_str().unwrap(),
        &remote_spec,
        "--port",
        &port,
        "--accept-new",
        "--dir",
        layout.to_str().unwrap(),
    ])
    .await;
    assert!(
        output.status.success(),
        "recursive upload failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        std::fs::read(remote.join("root.txt")).unwrap(),
        b"root-file"
    );
    assert_eq!(
        std::fs::read(remote.join("a b.txt")).unwrap(),
        b"with space"
    );
    assert_eq!(
        std::fs::read(remote.join("sub/file.txt")).unwrap(),
        b"nested"
    );
    assert!(remote.join("empty").is_dir());
    assert_eq!(mode(&remote.join("sub/run.sh")), 0o755);

    // Download into a fresh directory.
    let out = layout.join("out");
    let output = run_cp(&[
        "-r",
        &remote_spec,
        out.to_str().unwrap(),
        "--port",
        &port,
        "--accept-new",
        "--dir",
        layout.to_str().unwrap(),
    ])
    .await;
    assert!(
        output.status.success(),
        "recursive download failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(std::fs::read(out.join("root.txt")).unwrap(), b"root-file");
    assert_eq!(std::fs::read(out.join("a b.txt")).unwrap(), b"with space");
    assert_eq!(std::fs::read(out.join("sub/file.txt")).unwrap(), b"nested");
    assert!(out.join("empty").is_dir());
    assert_eq!(mode(&out.join("sub/run.sh")), 0o755);
}

async fn run_cp(args: &[&str]) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_rmp"))
            .arg("cp")
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("rmp cp timed out")
    .expect("run rmp cp")
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}
