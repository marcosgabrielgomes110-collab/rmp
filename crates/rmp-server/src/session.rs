//! Session channel handling: non-interactive `Exec` and interactive PTY.

use crate::server::SpawnSpec;
use anyhow::{Context, Result};
use quinn::{RecvStream, SendStream};
use rmp_proto::{Data, ExitStatus, Message, PtyRequest};
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Run a command through the shell, streaming stdout+stderr back as `Data`.
///
/// Returns the exit code. The [`SpawnSpec`] selects the shell (or a privilege
/// dropping wrapper such as `runuser`) plus its environment and working
/// directory.
pub(crate) async fn run_exec(
    send: &mut SendStream,
    _recv: &mut RecvStream,
    command: &str,
    spec: &SpawnSpec,
) -> Result<u32> {
    let mut command_builder = tokio::process::Command::new(&spec.program);
    command_builder.args(&spec.args);
    if let Some(cwd) = &spec.cwd {
        command_builder.current_dir(cwd);
    }
    command_builder.envs(spec.env.iter().map(|(k, v)| (k, v)));
    // `cmd.exe` uses `/C`; POSIX shells use `-c`.
    #[cfg(windows)]
    command_builder.arg("/C");
    #[cfg(not(windows))]
    command_builder.arg("-c");
    let mut child = command_builder
        .arg(command)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("spawning {}", spec.program))?;

    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");

    // Bounded so a fast producer (e.g. `yes`) cannot buffer the whole output
    // in memory while the QUIC stream applies backpressure.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let tx_out = tx.clone();
    let out_task = tokio::spawn(async move { pump(&mut stdout, tx_out).await });
    let tx_err = tx.clone();
    let err_task = tokio::spawn(async move { pump(&mut stderr, tx_err).await });
    drop(tx);

    while let Some(chunk) = rx.recv().await {
        rmp_proto::write_message(send, &Message::Data(Data { data: chunk })).await?;
    }
    let _ = out_task.await;
    let _ = err_task.await;

    let status = child.wait().await?;
    let code: u32 = match status.code() {
        Some(c) => c as u32,
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                status.signal().map(|s| (128 + s) as u32).unwrap_or(1)
            }
            #[cfg(not(unix))]
            {
                1
            }
        }
    };

    rmp_proto::write_message(
        send,
        &Message::ExitStatus(ExitStatus {
            exit_code: code,
            signal: None,
        }),
    )
    .await?;
    Ok(code)
}

async fn pump<R>(reader: &mut R, tx: tokio::sync::mpsc::Sender<Vec<u8>>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if tx.send(buf[..n].to_vec()).await.is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

/// Run an interactive PTY session bridged with the QUIC stream.
///
/// Returns the exit code of the shell.
pub(crate) async fn run_pty(
    send: &mut SendStream,
    recv: &mut RecvStream,
    req: PtyRequest,
    spec: &SpawnSpec,
    motd: Option<&str>,
) -> Result<u32> {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::{Read, Write};

    // Show the message of the day, if any, before the shell output.
    if let Some(motd) = motd {
        let mut text = motd.to_string();
        text.push_str("\r\n");
        rmp_proto::write_message(
            send,
            &Message::Data(Data {
                data: text.into_bytes(),
            }),
        )
        .await?;
    }

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: req.rows,
            cols: req.cols,
            pixel_width: req.pixel_w,
            pixel_height: req.pixel_h,
        })
        .context("opening a PTY")?;

    let mut cmd = CommandBuilder::new(&spec.program);
    if !spec.args.is_empty() {
        cmd.args(spec.args.iter());
    }
    if let Some(cwd) = &spec.cwd {
        cmd.cwd(cwd);
    }
    for (key, value) in &spec.env {
        cmd.env(key, value);
    }
    cmd.env(
        "TERM",
        if req.term.is_empty() {
            "xterm-256color"
        } else {
            &req.term
        },
    );
    let mut child = pair.slave.spawn_command(cmd).context("spawning shell")?;
    // The slave end is owned by the child now.
    drop(pair.slave);

    let master = pair.master;
    let mut reader = master.try_clone_reader().context("pty reader")?;
    let mut writer = master.take_writer().context("pty writer")?;

    // PTY -> network. Bounded so a chatty program cannot grow memory faster
    // than the QUIC stream drains.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // network -> PTY. Also bounded, for the same reason.
    let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        while let Some(chunk) = in_rx.blocking_recv() {
            if writer.write_all(&chunk).is_err() {
                break;
            }
            let _ = writer.flush();
        }
    });

    // Child exit notification.
    let (status_tx, mut status_rx) = tokio::sync::mpsc::unbounded_channel::<u32>();
    std::thread::spawn(move || {
        let code = child.wait().map(|s| s.exit_code()).unwrap_or(0);
        let _ = status_tx.send(code);
    });

    let mut exit_code: u32 = 0;
    loop {
        tokio::select! {
            Some(chunk) = out_rx.recv() => {
                rmp_proto::write_message(send, &Message::Data(Data { data: chunk })).await?;
            }
            msg = rmp_proto::read_message(recv) => {
                match msg {
                    Ok(Message::Data(d)) => {
                        if in_tx.send(d.data).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::WindowChange(w)) => {
                        let _ = master.resize(PtySize {
                            rows: w.rows,
                            cols: w.cols,
                            pixel_width: w.pixel_w,
                            pixel_height: w.pixel_h,
                        });
                    }
                    Ok(Message::Signal(s)) => {
                        if let Some(byte) = signal_byte(&s.signal) {
                            let _ = in_tx.send(vec![byte]).await;
                        }
                    }
                    // Local stdin reached EOF: deliver Ctrl-D to the shell.
                    Ok(Message::Eof) => {
                        let _ = in_tx.send(vec![0x04]).await;
                    }
                    Ok(Message::Shell) => { /* shell already spawned */ }
                    Ok(_) => {}
                    Err(rmp_proto::StreamError::Closed) => break,
                    Err(_) => break,
                }
            }
            Some(code) = status_rx.recv() => {
                // The child exited, but the reader thread may still be
                // delivering the last bytes. Drain until EOF, with a short
                // bound so a background process holding the PTY cannot hang
                // the session.
                let deadline = tokio::time::sleep(Duration::from_millis(500));
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        chunk = out_rx.recv() => match chunk {
                            Some(chunk) => {
                                rmp_proto::write_message(
                                    send,
                                    &Message::Data(Data { data: chunk }),
                                ).await?;
                            }
                            None => break,
                        },
                        _ = &mut deadline => break,
                    }
                }
                rmp_proto::write_message(send, &Message::ExitStatus(ExitStatus {
                    exit_code: code,
                    signal: None,
                })).await?;
                exit_code = code;
                break;
            }
        }
    }
    Ok(exit_code)
}

/// Map a POSIX signal name to the terminal control byte that delivers it.
fn signal_byte(name: &str) -> Option<u8> {
    match name.trim_start_matches("SIG").to_ascii_uppercase().as_str() {
        "INT" => Some(0x03),           // Ctrl-C
        "QUIT" => Some(0x1c),          // Ctrl-\
        "TSTP" | "SUSP" => Some(0x1a), // Ctrl-Z
        "EOF" => Some(0x04),           // Ctrl-D
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_mapping() {
        assert_eq!(signal_byte("INT"), Some(0x03));
        assert_eq!(signal_byte("SIGINT"), Some(0x03));
        assert_eq!(signal_byte("TERM"), None);
    }
}
