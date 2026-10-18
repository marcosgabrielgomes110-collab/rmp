//! End-to-end test for `rmp exec` using a real server and a pre-enrolled device
//! key (so the command never prompts for a password).

#![cfg(unix)]

use rmp_crypto::{password, DeviceKey, HostKey};
use rmp_server::{bind, serve, AuthorizedKeys, ServerOptions};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn exec_runs_a_command_and_returns_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let layout = dir.path();

    // Server identity and a password record (not used: login is by device key).
    let host_key = HostKey::generate().unwrap();
    let setup = password::new_setup();
    let password_file = password::enroll(b"unused", "alice", &setup).unwrap();

    // Client identity, authorized server-side.
    let device = DeviceKey::generate();
    let identities = layout.join("identities");
    let authorized = layout.join("authorized_keys");
    AuthorizedKeys::load(&authorized)
        .unwrap()
        .add(&device.public_key(), "exec-test")
        .unwrap();

    let mut opts = ServerOptions::new("alice".to_string(), host_key, setup, password_file);
    opts.shell = Some("/bin/sh".to_string());
    opts.authorized_keys_path = authorized;
    let endpoint = bind("127.0.0.1:0".parse().unwrap(), &opts).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(serve(endpoint, Arc::new(opts)));

    // The identity file name includes the real port; create it after binding.
    let identity_path = identities.join(format!("127.0.0.1_{}__alice.key", addr.port()));
    device.save(&identity_path).unwrap();

    let output = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_rmp"))
            .arg("exec")
            .arg(format!("alice@127.0.0.1:{}", addr.port()))
            .arg("--accept-new")
            .arg("--dir")
            .arg(layout)
            .arg("--")
            .arg("echo")
            .arg("hello-exec")
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("rmp exec timed out")
    .expect("run rmp exec");

    assert!(
        output.status.success(),
        "rmp exec failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello-exec"),
        "unexpected stdout: {stdout:?}"
    );
}
