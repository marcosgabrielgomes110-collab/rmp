//! Local terminal helpers: raw mode and window size.
#![allow(unsafe_code)]

use anyhow::Result;

/// Put the local terminal into raw mode for the lifetime of this guard.
#[cfg(unix)]
pub struct RawMode {
    original: libc::termios,
}

#[cfg(unix)]
impl RawMode {
    /// Enable raw mode on stdin. The previous settings are restored on drop.
    pub fn enable() -> Result<Self> {
        unsafe {
            let fd = libc::STDIN_FILENO;
            let mut original: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut original) != 0 {
                anyhow::bail!("tcgetattr failed (not a TTY)");
            }
            let mut raw = original;
            libc::cfmakeraw(&mut raw);
            raw.c_oflag |= libc::OPOST;
            if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
                anyhow::bail!("tcsetattr failed");
            }
            Ok(RawMode { original })
        }
    }
}

#[cfg(unix)]
impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original);
        }
    }
}

/// No-op raw mode on non-Unix platforms.
#[cfg(not(unix))]
pub struct RawMode;

#[cfg(not(unix))]
impl RawMode {
    pub fn enable() -> Result<Self> {
        Ok(RawMode)
    }
}

/// Current terminal size `(cols, rows)`, or a sane default.
#[cfg(unix)]
pub fn terminal_size() -> (u16, u16) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            return (ws.ws_col, ws.ws_row);
        }
    }
    (80, 24)
}

#[cfg(not(unix))]
pub fn terminal_size() -> (u16, u16) {
    (80, 24)
}
