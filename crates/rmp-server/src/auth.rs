//! Authentication policy and the OPAQUE handshake over the control stream.

use crate::audit::audit;
use crate::server::ServerOptions;
use anyhow::Result;
use quinn::{RecvStream, SendStream};
use rmp_crypto as crypto;
use rmp_proto::{AuthFinish, AuthReason, AuthResult, AuthStart, Message};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The identity a successful authentication maps to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// The configured account (`server.username`).
    User,
    /// The `root` account (only when `auth.allow_root` is enabled).
    Root,
}

/// In-memory, per-IP failed-authentication tracker with temporary lockout.
#[derive(Debug)]
pub struct AuthLimiter {
    max_attempts: u32,
    lockout: Duration,
    inner: Mutex<HashMap<IpAddr, Entry>>,
}

#[derive(Debug, Default)]
struct Entry {
    failures: u32,
    locked_until: Option<Instant>,
}

impl AuthLimiter {
    pub fn new(max_attempts: u32, lockout: Duration) -> Self {
        AuthLimiter {
            max_attempts,
            lockout,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `ip` is currently locked out.
    pub fn is_locked(&self, ip: IpAddr) -> bool {
        let mut map = self.inner.lock().expect("limiter mutex poisoned");
        match map.get_mut(&ip) {
            Some(entry) => match entry.locked_until {
                Some(until) if until > Instant::now() => true,
                Some(_) => {
                    map.remove(&ip);
                    false
                }
                None => false,
            },
            None => false,
        }
    }

    fn record_failure(&self, ip: IpAddr) {
        let mut map = self.inner.lock().expect("limiter mutex poisoned");
        let entry = map.entry(ip).or_default();
        entry.failures = entry.failures.saturating_add(1);
        if self.max_attempts != 0 && entry.failures >= self.max_attempts {
            entry.locked_until = Some(Instant::now() + self.lockout);
        }
    }

    fn record_success(&self, ip: IpAddr) {
        self.inner
            .lock()
            .expect("limiter mutex poisoned")
            .remove(&ip);
    }
}

/// Run the authentication exchange.
///
/// Returns `Ok(Some(principal))` on success, `Ok(None)` when authentication
/// fails (the failure is already reported on the control stream).
pub async fn authenticate(
    send: &mut SendStream,
    recv: &mut RecvStream,
    opts: &ServerOptions,
    limiter: &AuthLimiter,
    peer: SocketAddr,
) -> Result<Option<Principal>> {
    let ip = peer.ip();

    if limiter.is_locked(ip) {
        tracing::warn!(%peer, "authentication attempt while locked out");
        audit!(event = "auth.locked_out", peer = %peer, user = %opts.username);
        write_result(send, false, AuthReason::LockedOut).await?;
        return Ok(None);
    }

    let start = match rmp_proto::read_message(recv).await {
        Ok(msg) => msg,
        Err(_) => {
            audit!(event = "auth.aborted", peer = %peer, stage = "start");
            return Ok(None);
        }
    };
    let Message::AuthStart(AuthStart { username, initial }) = start else {
        anyhow::bail!("expected AuthStart, got {:?}", start.frame_type());
    };
    audit!(event = "auth.attempt", peer = %peer, user = %username);

    // Pick the credential for the requested account.
    // - the configured user → its password file (unless password auth is off);
    // - `root` → the root password file (only when allow_root is enabled);
    // - anything else → no file: OPAQUE still answers indistinguishably.
    let (file, principal) = if username == opts.username {
        let file = if opts.password_enabled {
            Some(&opts.password_file)
        } else {
            None
        };
        (file, Principal::User)
    } else if username == "root" && opts.allow_root {
        (opts.root_password_file.as_ref(), Principal::Root)
    } else {
        (None, Principal::User)
    };

    let (response, state) =
        crypto::password::server_start(&opts.opaque_setup, file, &initial, &username)?;
    rmp_proto::write_message(
        send,
        &Message::AuthResponse(rmp_proto::AuthResponse { payload: response }),
    )
    .await?;

    let finish = match rmp_proto::read_message(recv).await {
        Ok(msg) => msg,
        Err(_) => {
            // The client aborted (OPAQUE detects a wrong password client-side).
            limiter.record_failure(ip);
            audit!(event = "auth.failure", peer = %peer, user = %username, reason = "aborted");
            return Ok(None);
        }
    };
    let payload = match finish {
        Message::AuthFinish(AuthFinish { payload, .. }) => payload,
        other => {
            limiter.record_failure(ip);
            audit!(event = "auth.failure", peer = %peer, user = %username,
                   reason = "unexpected_message", got = %format!("{:?}", other.frame_type()));
            write_result(send, false, AuthReason::InvalidCredentials).await?;
            return Ok(None);
        }
    };

    match crypto::password::server_finish(&state, &payload) {
        Ok(_session_key) => {
            limiter.record_success(ip);
            audit!(event = "auth.success", peer = %peer, user = %username,
                   principal = ?principal);
            write_result(send, true, AuthReason::Ok).await?;
            Ok(Some(principal))
        }
        Err(e) => {
            tracing::warn!(%peer, user = %username, error = %e, "authentication failed");
            limiter.record_failure(ip);
            let reason = if limiter.is_locked(ip) {
                audit!(event = "auth.lockout", peer = %peer, user = %username);
                AuthReason::LockedOut
            } else {
                audit!(event = "auth.failure", peer = %peer, user = %username, reason = "invalid_proof");
                AuthReason::InvalidCredentials
            };
            write_result(send, false, reason).await?;
            Ok(None)
        }
    }
}

async fn write_result(send: &mut SendStream, ok: bool, reason: AuthReason) -> Result<()> {
    rmp_proto::write_message(
        send,
        &Message::AuthResult(AuthResult {
            ok,
            reason,
            session_token: None,
        }),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn locks_out_after_max_attempts() {
        let limiter = AuthLimiter::new(3, Duration::from_secs(60));
        let addr = ip(1);
        assert!(!limiter.is_locked(addr));
        limiter.record_failure(addr);
        limiter.record_failure(addr);
        assert!(!limiter.is_locked(addr));
        limiter.record_failure(addr);
        assert!(limiter.is_locked(addr));
    }

    #[test]
    fn success_resets_failures() {
        let limiter = AuthLimiter::new(3, Duration::from_secs(60));
        let addr = ip(2);
        limiter.record_failure(addr);
        limiter.record_failure(addr);
        limiter.record_success(addr);
        limiter.record_failure(addr);
        limiter.record_failure(addr);
        assert!(!limiter.is_locked(addr));
    }

    #[test]
    fn expired_lockout_is_cleared() {
        let limiter = AuthLimiter::new(1, Duration::from_millis(0));
        let addr = ip(3);
        limiter.record_failure(addr);
        assert!(!limiter.is_locked(addr));
    }
}
