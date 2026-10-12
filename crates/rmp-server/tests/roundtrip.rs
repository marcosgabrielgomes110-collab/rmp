//! End-to-end tests: a real QUIC server and client over loopback.

use rmp_client::{Client, ClientOptions, Fingerprint};
use rmp_crypto as crypto;
use rmp_server::{bind, serve, ServerOptions};
use std::sync::Arc;
use std::time::Duration;

const USER: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";

struct Harness {
    addr: std::net::SocketAddr,
    fingerprint: Fingerprint,
}

async fn start_server() -> Harness {
    let host_key = crypto::HostKey::generate().unwrap();
    let fingerprint = host_key.fingerprint();
    let setup = crypto::password::new_setup();
    let password_file = crypto::password::enroll(PASSWORD.as_bytes(), USER, &setup).unwrap();

    #[cfg(unix)]
    let shell = Some("/bin/sh".to_string());
    #[cfg(not(unix))]
    let shell = None;

    let mut opts = ServerOptions::new(USER.to_string(), host_key, setup, password_file);
    opts.shell = shell;
    opts.idle_timeout = Duration::from_secs(30);
    opts.keep_alive = Duration::from_secs(5);

    let endpoint = bind("127.0.0.1:0".parse().unwrap(), &opts).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(serve(endpoint, Arc::new(opts)));

    Harness { addr, fingerprint }
}

fn client_opts(h: &Harness, expected: Option<Fingerprint>) -> ClientOptions {
    ClientOptions {
        server_addr: h.addr,
        server_name: "rmp".to_string(),
        idle_timeout: Duration::from_secs(30),
        keep_alive: Duration::from_secs(5),
        expected_fingerprint: expected,
    }
}

#[tokio::test]
async fn exec_roundtrip() {
    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .expect("connect + auth");

    let out = tokio::time::timeout(Duration::from_secs(10), client.exec("echo hello-rmp"))
        .await
        .expect("no timeout")
        .expect("exec");

    let text = String::from_utf8_lossy(&out.data);
    assert!(text.contains("hello-rmp"), "unexpected output: {text:?}");
    assert_eq!(out.exit_code, 0);
    assert_eq!(client.observed_fingerprint(), Some(h.fingerprint));
}

#[tokio::test]
async fn exec_reports_exit_code() {
    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .unwrap();

    let out = tokio::time::timeout(Duration::from_secs(10), client.exec("exit 7"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(out.exit_code, 7);
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Client::connect(&opts, USER, b"not-the-password"),
    )
    .await
    .expect("no timeout");
    assert!(result.is_err(), "wrong password must not authenticate");
}

#[tokio::test]
async fn unknown_user_is_rejected() {
    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Client::connect(&opts, "mallory", PASSWORD.as_bytes()),
    )
    .await
    .expect("no timeout");
    assert!(result.is_err(), "unknown user must not authenticate");
}

#[tokio::test]
async fn fingerprint_mismatch_aborts_handshake() {
    let h = start_server().await;
    let wrong = crypto::HostKey::generate().unwrap().fingerprint();
    let opts = client_opts(&h, Some(wrong));
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        Client::connect(&opts, USER, PASSWORD.as_bytes()),
    )
    .await
    .expect("no timeout");
    assert!(
        result.is_err(),
        "a pinned fingerprint that does not match must abort"
    );
}

#[tokio::test]
async fn tofu_accepts_unknown_host() {
    let h = start_server().await;
    // No expected fingerprint: TOFU accepts and records the observed one.
    let opts = client_opts(&h, None);
    let client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .expect("tofu connect");
    assert_eq!(client.observed_fingerprint(), Some(h.fingerprint));
}

#[cfg(unix)]
#[tokio::test]
async fn pty_roundtrip() {
    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .unwrap();

    let out = tokio::time::timeout(
        Duration::from_secs(15),
        client.pty_capture("echo pty-ok; exit 3"),
    )
    .await
    .expect("no timeout")
    .expect("pty session");

    let text = String::from_utf8_lossy(&out.data);
    assert!(text.contains("pty-ok"), "unexpected pty output: {text:?}");
    assert_eq!(out.exit_code, 3);
}
