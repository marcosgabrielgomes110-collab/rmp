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
    authorized_keys: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn start_server() -> Harness {
    start_server_with(true, true).await
}

async fn start_server_with(allow_key_auth: bool, allow_key_enrollment: bool) -> Harness {
    let host_key = crypto::HostKey::generate().unwrap();
    let fingerprint = host_key.fingerprint();
    let setup = crypto::password::new_setup();
    let password_file = crypto::password::enroll(PASSWORD.as_bytes(), USER, &setup).unwrap();

    #[cfg(unix)]
    let shell = Some("/bin/sh".to_string());
    #[cfg(not(unix))]
    let shell = None;

    let dir = tempfile::tempdir().unwrap();
    let authorized_keys = dir.path().join("authorized_keys");

    let mut opts = ServerOptions::new(USER.to_string(), host_key, setup, password_file);
    opts.shell = shell;
    opts.idle_timeout = Duration::from_secs(30);
    opts.keep_alive = Duration::from_secs(5);
    opts.allow_key_auth = allow_key_auth;
    opts.allow_key_enrollment = allow_key_enrollment;
    opts.authorized_keys_path = authorized_keys.clone();

    let endpoint = bind("127.0.0.1:0".parse().unwrap(), &opts).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(serve(endpoint, Arc::new(opts)));

    Harness {
        addr,
        fingerprint,
        authorized_keys,
        _dir: dir,
    }
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

#[tokio::test]
async fn key_enrollment_then_passwordless_login() {
    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));

    // 1. Password login that enrolls a fresh device key.
    let device = rmp_client::DeviceKey::generate();
    let transport = rmp_client::transport(&opts).await.unwrap();
    let client = transport
        .authenticate_password(USER, PASSWORD.as_bytes(), Some(device.public_key()))
        .await
        .unwrap();
    assert!(client.key_enrolled(), "server should have enrolled the key");

    // The public key must be persisted server-side.
    assert!(h.authorized_keys.exists());
    let stored = std::fs::read_to_string(&h.authorized_keys).unwrap();
    assert!(
        stored.contains(&hex::encode(device.public_key())),
        "authorized_keys should contain the enrolled key"
    );

    // 2. Subsequent login uses the key only — no password.
    let transport = rmp_client::transport(&opts).await.unwrap();
    let client = tokio::time::timeout(
        Duration::from_secs(10),
        transport.authenticate_key(USER, &device),
    )
    .await
    .unwrap()
    .expect("key login");

    let out = tokio::time::timeout(Duration::from_secs(10), client.exec("echo key-login-ok"))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.data).contains("key-login-ok"));
}

#[tokio::test]
async fn unknown_device_key_is_rejected() {
    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let unknown = rmp_client::DeviceKey::generate();

    let transport = rmp_client::transport(&opts).await.unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        transport.authenticate_key(USER, &unknown),
    )
    .await
    .unwrap();
    assert!(result.is_err(), "unknown key must not authenticate");
}

#[tokio::test]
async fn enrollment_disabled_does_not_store_key() {
    let h = start_server_with(true, false).await;
    let opts = client_opts(&h, Some(h.fingerprint));

    let device = rmp_client::DeviceKey::generate();
    let transport = rmp_client::transport(&opts).await.unwrap();
    let client = transport
        .authenticate_password(USER, PASSWORD.as_bytes(), Some(device.public_key()))
        .await
        .unwrap();
    assert!(!client.key_enrolled(), "enrollment is disabled");
    assert!(
        !h.authorized_keys.exists(),
        "no key should have been written"
    );

    // And key login must fail since the key was never stored.
    let transport = rmp_client::transport(&opts).await.unwrap();
    let result = transport.authenticate_key(USER, &device).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn key_auth_disabled_rejects_key() {
    let h = start_server_with(false, true).await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let device = rmp_client::DeviceKey::generate();

    let transport = rmp_client::transport(&opts).await.unwrap();
    let result = transport.authenticate_key(USER, &device).await;
    assert!(result.is_err(), "key auth disabled must reject keys");
}

#[tokio::test]
async fn local_port_forward_roundtrip() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .unwrap();

    // A TCP echo server, reachable from the server side (same host here).
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = echo.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    // Set up the local forward (bind an ephemeral port so we know it).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let conn = client.connection().clone();
    tokio::spawn(rmp_client::local_forward(
        conn,
        listener,
        "127.0.0.1".to_string(),
        echo_port,
    ));

    // Send data through the tunnel and expect it echoed back.
    let mut tun = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", local_port)),
    )
    .await
    .expect("no timeout")
    .expect("connect through tunnel");

    tun.write_all(b"ping-through-rmp").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), tun.read(&mut buf))
        .await
        .expect("no timeout")
        .expect("read echo");
    assert_eq!(&buf[..n], b"ping-through-rmp");
}
