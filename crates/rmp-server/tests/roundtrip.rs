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
    start_server_with(true, true, false, true, 128).await
}

async fn start_server_with(
    allow_key_auth: bool,
    allow_key_enrollment: bool,
    allow_remote_forward: bool,
    allow_file_transfer: bool,
    max_connections: usize,
) -> Harness {
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
    opts.allow_remote_forward = allow_remote_forward;
    opts.allow_file_transfer = allow_file_transfer;
    opts.max_connections = max_connections;
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
    let error = match result {
        Ok(_) => panic!("a pinned fingerprint that does not match must abort"),
        Err(error) => error,
    };
    let text = format!("{error:#}");
    assert!(
        text.contains("HOST KEY MISMATCH"),
        "expected an actionable mismatch error, got: {text}"
    );
}

#[tokio::test]
async fn control_ping_roundtrip() {
    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let mut client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .unwrap();

    let nonce = tokio::time::timeout(Duration::from_secs(5), client.ping(4242))
        .await
        .expect("ping timeout")
        .expect("ping");
    assert_eq!(nonce, 4242);
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
    let h = start_server_with(true, false, false, true, 128).await;
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
    let h = start_server_with(false, true, false, true, 128).await;
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

#[tokio::test]
async fn remote_port_forward_roundtrip() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    // Server that allows -R.
    let h = start_server_with(true, true, true, true, 128).await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let mut client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .unwrap();

    // A client-side echo target.
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

    // Accept server-initiated forwarding streams.
    let conn = client.connection().clone();
    tokio::spawn(rmp_client::remote_forward_accept(conn));

    // Ask the server to listen (ephemeral port) and forward to our echo.
    let bound = client
        .request_remote_forward(0, "127.0.0.1", echo_port)
        .await
        .expect("remote forward bound");

    // Connect to the server's bound port; the bytes must reach our echo server.
    let mut tun = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", bound)),
    )
    .await
    .expect("no timeout")
    .expect("connect to server bound port");

    tun.write_all(b"remote-ping").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), tun.read(&mut buf))
        .await
        .expect("no timeout")
        .expect("read echo");
    assert_eq!(&buf[..n], b"remote-ping");
}

#[tokio::test]
async fn remote_forward_disabled_is_refused() {
    // Default server has allow_remote_forward = false.
    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let mut client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .unwrap();

    let result = client.request_remote_forward(0, "127.0.0.1", 9).await;
    assert!(result.is_err(), "remote forwarding must be refused");
}

#[tokio::test]
async fn file_transfer_roundtrip() {
    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let payload = b"hello file transfer over rmp";

    // Upload a local file to the "remote" path.
    let local_src = dir.path().join("src.txt");
    std::fs::write(&local_src, payload).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&local_src, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let remote = dir.path().join("uploaded.txt");
    let remote_str = remote.to_str().unwrap();

    let mut uploaded = 0u64;
    let sent = client
        .upload_with(&local_src, remote_str, |done| uploaded = done)
        .await
        .expect("upload");
    assert_eq!(sent as usize, payload.len());
    assert_eq!(
        uploaded as usize,
        payload.len(),
        "progress reports final size"
    );
    assert_eq!(std::fs::read(&remote).unwrap(), payload);

    // Download it back to a different local file.
    let local_out = dir.path().join("downloaded.txt");
    let mut downloaded = 0u64;
    let got = client
        .download_with(remote_str, &local_out, |done| downloaded = done)
        .await
        .expect("download");
    assert_eq!(got as usize, payload.len());
    assert_eq!(
        downloaded as usize,
        payload.len(),
        "progress reports final size"
    );
    assert_eq!(std::fs::read(&local_out).unwrap(), payload);

    // The executable bit is preserved in both directions (Unix).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let up = std::fs::metadata(&remote).unwrap().permissions().mode();
        let down = std::fs::metadata(&local_out).unwrap().permissions().mode();
        assert_ne!(up & 0o111, 0, "remote upload must be executable");
        assert_ne!(down & 0o111, 0, "downloaded file must be executable");
    }
}

#[tokio::test]
async fn download_missing_file_is_refused() {
    let h = start_server().await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out.txt");
    let res = client.download("/no/such/file/rmp-test-xyz", &out).await;
    assert!(res.is_err(), "missing file must be refused");
    assert!(!out.exists(), "no local file should be created on refusal");
}

#[tokio::test]
async fn file_transfer_disabled_is_refused() {
    // allow_file_transfer = false
    let h = start_server_with(true, true, false, false, 128).await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let local = dir.path().join("x.txt");
    std::fs::write(&local, b"x").unwrap();
    let remote = dir.path().join("y.txt");
    let res = client.upload(&local, remote.to_str().unwrap()).await;
    assert!(res.is_err(), "file transfer must be refused when disabled");
}

#[tokio::test]
async fn max_connections_is_enforced() {
    let h = start_server_with(true, true, false, true, 1).await;
    let opts = client_opts(&h, Some(h.fingerprint));

    let first = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .expect("first connection");

    let second = tokio::time::timeout(Duration::from_secs(5), rmp_client::transport(&opts))
        .await
        .expect("second attempt must not hang");

    assert!(
        second.is_err(),
        "a second connection must be refused when max_connections = 1"
    );

    drop(first);
}

#[tokio::test]
async fn remote_forward_listener_is_released_on_disconnect() {
    let h = start_server_with(true, true, true, true, 128).await;
    let opts = client_opts(&h, Some(h.fingerprint));
    let mut client = Client::connect(&opts, USER, PASSWORD.as_bytes())
        .await
        .unwrap();

    let bound = client
        .request_remote_forward(0, "127.0.0.1", 9)
        .await
        .expect("remote forward bound");

    drop(client);

    // The listener must be closed when the QUIC connection goes away.
    for _ in 0..50 {
        if tokio::net::TcpListener::bind(("127.0.0.1", bound))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("port {bound} was not released after the client disconnected");
}

#[tokio::test]
async fn password_change_is_reloaded_without_restart() {
    let host_key = crypto::HostKey::generate().unwrap();
    let fingerprint = host_key.fingerprint();
    let setup = crypto::password::new_setup();
    let setup_bytes = crypto::password::setup_to_bytes(&setup);
    let old_file = crypto::password::enroll(PASSWORD.as_bytes(), USER, &setup).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let password_path = dir.path().join("password_file.bin");
    old_file.save(&password_path).unwrap();

    #[cfg(unix)]
    let shell = Some("/bin/sh".to_string());
    #[cfg(not(unix))]
    let shell = None;

    let mut opts = ServerOptions::new(USER.to_string(), host_key, setup, old_file);
    opts.shell = shell;
    opts.password_file_path = Some(password_path.clone());
    opts.authorized_keys_path = dir.path().join("authorized_keys");
    opts.idle_timeout = Duration::from_secs(30);
    opts.keep_alive = Duration::from_secs(5);

    let endpoint = bind("127.0.0.1:0".parse().unwrap(), &opts).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(serve(endpoint, Arc::new(opts)));

    let client_opts = ClientOptions {
        server_addr: addr,
        server_name: "rmp".to_string(),
        idle_timeout: Duration::from_secs(30),
        keep_alive: Duration::from_secs(5),
        expected_fingerprint: Some(fingerprint),
    };

    // The new password is not valid yet.
    assert!(Client::connect(&client_opts, USER, b"new-password")
        .await
        .is_err());

    // Replace the registration record on disk; the running server must pick it
    // up on the next login, without a restart.
    let setup = crypto::password::setup_from_bytes(&setup_bytes).unwrap();
    let new_file = crypto::password::enroll(b"new-password", USER, &setup).unwrap();
    new_file.save(&password_path).unwrap();

    let client = Client::connect(&client_opts, USER, b"new-password")
        .await
        .expect("new password should be accepted without restart");
    let out = client.exec("echo reloaded").await.unwrap();
    assert!(String::from_utf8_lossy(&out.data).contains("reloaded"));
}
