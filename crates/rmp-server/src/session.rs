//! Session channel handling: non-interactive `Exec` and interactive PTY.

use anyhow::{Context, Result};
use quinn::{RecvStream, SendStream};
use rmp_proto::{Data, ExitStatus, Message, PtyRequest};
use tokio::io::AsyncReadExt;

/// Run a command through the shell, streaming stdout+stderr back as `Data`.
///
/// Returns the exit code. `program`/`args` select the shell (or a privilege
/// dropping wrapper such as `runuser`).
pub async fn run_exec(
    send: &mut SendStream,
    _recv: &mut RecvStream,
    command: &str,
    program: &str,
    args: &[String],
) -> Result<u32> {
    let mut command_builder = tokio::process::Command::new(program);
    command_builder.args(args);
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
        .with_context(|| format!("spawning {program}"))?;

    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
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

async fn pump<R>(reader: &mut R, tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>)
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if tx.send(buf[..n].to_vec()).is_err() {
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
pub async fn run_pty(
    send: &mut SendStream,
    recv: &mut RecvStream,
    req: PtyRequest,
    program: &str,
    args: &[String],
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

    let mut cmd = CommandBuilder::new(program);
    if !args.is_empty() {
        cmd.args(args);
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

    // PTY -> network.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if out_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // network -> PTY.
    let (in_tx, in_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(chunk) = in_rx.recv() {
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
                    Ok(Message::Data(d)) => { let _ = in_tx.send(d.data); }
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
                            let _ = in_tx.send(vec![byte]);
                        }
                    }
                    Ok(Message::Eof) => { /* stdin closed */ }
                    Ok(Message::Shell) => { /* shell already spawned */ }
                    Ok(_) => {}
                    Err(rmp_proto::StreamError::Closed) => break,
                    Err(_) => break,
                }
            }
            Some(code) = status_rx.recv() => {
                // Flush remaining output before reporting the exit code.
                while let Ok(chunk) = out_rx.try_recv() {
                    rmp_proto::write_message(send, &Message::Data(Data { data: chunk })).await?;
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
