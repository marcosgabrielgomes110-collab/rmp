//! The hidden `rmp __helper` process is used by the server in root mode to run
//! file/forward operations as the target user. These tests exercise it without
//! requiring root.

use rmp_proto::{read_message, write_message, Data, FileOp, FileRequest, ForwardRequest, Message};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

#[tokio::test]
async fn helper_serves_a_get_over_stdio() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.txt");
    std::fs::write(&path, b"helper-get").unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_rmp"))
        .arg("__helper")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn helper");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    write_message(
        &mut stdin,
        &Message::FileRequest(FileRequest {
            op: FileOp::Get,
            path: path.to_string_lossy().into_owned(),
            mode: 0,
            size: 0,
        }),
    )
    .await
    .expect("write request");

    let response = tokio::time::timeout(Duration::from_secs(10), read_message(&mut stdout))
        .await
        .expect("no timeout")
        .expect("read response");
    match response {
        Message::FileResponse(r) => {
            assert!(r.ok, "helper refused: {:?}", r.reason);
            assert_eq!(r.size, 10);
        }
        other => panic!("unexpected response: {other:?}"),
    }

    let mut data = Vec::new();
    loop {
        let message = tokio::time::timeout(Duration::from_secs(10), read_message(&mut stdout))
            .await
            .expect("no timeout")
            .expect("read payload");
        match message {
            Message::Data(d) => data.extend_from_slice(&d.data),
            Message::Eof => break,
            other => panic!("unexpected message: {other:?}"),
        }
    }
    assert_eq!(data, b"helper-get");

    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("no timeout")
        .expect("wait for helper");
    assert!(status.success(), "helper failed: {status}");
}

#[tokio::test]
async fn helper_serves_a_forward_over_stdio() {
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
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

    let mut child = Command::new(env!("CARGO_BIN_EXE_rmp"))
        .arg("__helper")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn helper");

    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    write_message(
        &mut stdin,
        &Message::ForwardRequest(ForwardRequest {
            host: "127.0.0.1".to_string(),
            port,
        }),
    )
    .await
    .expect("write request");

    match read_message(&mut stdout).await.expect("response") {
        Message::ForwardResponse(r) => assert!(r.ok, "helper refused: {:?}", r.reason),
        other => panic!("unexpected response: {other:?}"),
    }

    write_message(
        &mut stdin,
        &Message::Data(Data {
            data: b"ping-helper".to_vec(),
        }),
    )
    .await
    .unwrap();

    let echoed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match read_message(&mut stdout).await.expect("forward data") {
                Message::Data(d) => return d.data,
                Message::Eof => return Vec::new(),
                _ => {}
            }
        }
    })
    .await
    .expect("no timeout");
    assert_eq!(echoed, b"ping-helper");

    write_message(&mut stdin, &Message::Eof).await.unwrap();
    // The helper should finish and close its stdout.
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("no timeout")
        .expect("wait for helper");
    assert!(status.success(), "helper failed: {status}");
}
