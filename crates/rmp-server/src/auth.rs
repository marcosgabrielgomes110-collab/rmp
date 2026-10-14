//! Authentication policy and the OPAQUE / device-key handshakes over the
//! control stream.

use crate::audit::audit;
use crate::keys::AuthorizedKeys;
use crate::server::ServerOptions;
use anyhow::Result;
use quinn::{RecvStream, SendStream};
use rand::RngCore;
use rmp_crypto::{self as crypto, verify_device_signature};
use rmp_proto::{
    key_auth_context, AuthFinish, AuthReason, AuthResult, AuthStart, KeyAuthChallenge,
    KeyAuthProof, KeyAuthRequest, Message,
};
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

/// A successfully authenticated account.
#[derive(Debug, Clone)]
pub struct Authed {
    pub username: String,
    pub principal: Principal,
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
/// Returns `Ok(Some(authed))` on success, `Ok(None)` when authentication fails
/// (the failure is already reported on the control stream).
pub async fn authenticate(
    send: &mut SendStream,
    recv: &mut RecvStream,
    opts: &ServerOptions,
    limiter: &AuthLimiter,
    peer: SocketAddr,
) -> Result<Option<Authed>> {
    let ip = peer.ip();

    if limiter.is_locked(ip) {
        tracing::warn!(%peer, "authentication attempt while locked out");
        audit!(event = "auth.locked_out", peer = %peer);
        write_result(send, false, AuthReason::LockedOut, false).await?;
        return Ok(None);
    }

    let first = match rmp_proto::read_message(recv).await {
        Ok(msg) => msg,
        Err(_) => {
            audit!(event = "auth.aborted", peer = %peer, stage = "start");
            return Ok(None);
        }
    };

    match first {
        Message::AuthStart(start) => {
            authenticate_password(send, recv, opts, limiter, peer, start).await
        }
        Message::KeyAuthRequest(req) => {
            authenticate_key(send, recv, opts, limiter, peer, req).await
        }
        other => anyhow::bail!("unexpected first auth message: {:?}", other.frame_type()),
    }
}

async fn authenticate_password(
    send: &mut SendStream,
    recv: &mut RecvStream,
    opts: &ServerOptions,
    limiter: &AuthLimiter,
    peer: SocketAddr,
    start: AuthStart,
) -> Result<Option<Authed>> {
    let ip = peer.ip();
    let AuthStart { username, initial } = start;
    audit!(event = "auth.attempt", peer = %peer, user = %username, method = "password");

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
            limiter.record_failure(ip);
            audit!(event = "auth.failure", peer = %peer, user = %username, method = "password", reason = "aborted");
            return Ok(None);
        }
    };
    let (payload, device_pubkey) = match finish {
        Message::AuthFinish(AuthFinish {
            payload,
            device_pubkey,
        }) => (payload, device_pubkey),
        other => {
            limiter.record_failure(ip);
            audit!(event = "auth.failure", peer = %peer, user = %username, method = "password",
                   reason = "unexpected_message", got = %format!("{:?}", other.frame_type()));
            write_result(send, false, AuthReason::InvalidCredentials, false).await?;
            return Ok(None);
        }
    };

    match crypto::password::server_finish(&state, &payload) {
        Ok(_session_key) => {
            limiter.record_success(ip);

            // Optional device-key enrollment on a successful password login.
            let mut key_enrolled = false;
            if let Some(public_key) = device_pubkey {
                key_enrolled = enroll(opts, &username, principal, &public_key, peer);
            }

            audit!(event = "auth.success", peer = %peer, user = %username, method = "password",
                   principal = ?principal, key_enrolled = key_enrolled);
            write_result(send, true, AuthReason::Ok, key_enrolled).await?;
            Ok(Some(Authed {
                username,
                principal,
            }))
        }
        Err(e) => {
            tracing::warn!(%peer, user = %username, error = %e, "password authentication failed");
            limiter.record_failure(ip);
            let reason = lockout_reason(limiter, ip, peer, &username);
            write_result(send, false, reason, false).await?;
            Ok(None)
        }
    }
}

async fn authenticate_key(
    send: &mut SendStream,
    recv: &mut RecvStream,
    opts: &ServerOptions,
    limiter: &AuthLimiter,
    peer: SocketAddr,
    req: KeyAuthRequest,
) -> Result<Option<Authed>> {
    let ip = peer.ip();
    let KeyAuthRequest {
        username,
        public_key,
    } = req;
    audit!(event = "auth.attempt", peer = %peer, user = %username, method = "key");

    if !opts.allow_key_auth || public_key.len() != 32 {
        limiter.record_failure(ip);
        audit!(event = "auth.failure", peer = %peer, user = %username, method = "key", reason = "disabled_or_bad_key");
        write_result(send, false, AuthReason::InvalidCredentials, false).await?;
        return Ok(None);
    }

    // Fresh server nonce; a challenge is always issued so a peer cannot probe
    // whether a given key is authorized.
    let mut nonce = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    rmp_proto::write_message(
        send,
        &Message::KeyAuthChallenge(KeyAuthChallenge {
            nonce: nonce.clone(),
        }),
    )
    .await?;

    let proof = match rmp_proto::read_message(recv).await {
        Ok(Message::KeyAuthProof(KeyAuthProof { signature })) => signature,
        _ => {
            limiter.record_failure(ip);
            audit!(event = "auth.failure", peer = %peer, user = %username, method = "key", reason = "aborted");
            return Ok(None);
        }
    };

    let authorized = username == opts.username;
    let key_ok = if authorized {
        AuthorizedKeys::load(&opts.authorized_keys_path)
            .map(|keys| keys.contains(&public_key))
            .unwrap_or(false)
    } else {
        false
    };

    let context = key_auth_context(&username, &public_key, &nonce);
    let signature_ok = verify_device_signature(&public_key, &context, &proof);

    if key_ok && signature_ok {
        limiter.record_success(ip);
        audit!(event = "auth.success", peer = %peer, user = %username, method = "key");
        write_result(send, true, AuthReason::Ok, false).await?;
        Ok(Some(Authed {
            username,
            principal: Principal::User,
        }))
    } else {
        limiter.record_failure(ip);
        let reason = lockout_reason(limiter, ip, peer, &username);
        audit!(event = "auth.failure", peer = %peer, user = %username, method = "key",
               reason = if !key_ok { "unknown_key" } else { "bad_signature" });
        write_result(send, false, reason, false).await?;
        Ok(None)
    }
}

/// Store a device public key if enrollment is enabled. Returns whether a key
/// was enrolled.
fn enroll(
    opts: &ServerOptions,
    username: &str,
    principal: Principal,
    public_key: &[u8],
    peer: SocketAddr,
) -> bool {
    if !opts.allow_key_enrollment || public_key.len() != 32 {
        audit!(event = "key.enroll_rejected", peer = %peer, user = %username);
        return false;
    }
    match AuthorizedKeys::load(&opts.authorized_keys_path).and_then(|mut keys| {
        let comment = format!("{username}@{peer}");
        let added = keys.add(public_key, &comment)?;
        Ok(added)
    }) {
        Ok(added) => {
            audit!(event = "key.enrolled", peer = %peer, user = %username,
                   principal = ?principal, fingerprint = %short_fingerprint(public_key), new = added);
            true
        }
        Err(e) => {
            tracing::warn!(%peer, error = %e, "failed to enroll device key");
            audit!(event = "key.enroll_rejected", peer = %peer, user = %username, reason = "io");
            false
        }
    }
}

fn short_fingerprint(public_key: &[u8]) -> String {
    rmp_crypto::Fingerprint::of_bytes(public_key).to_hex()
}

fn lockout_reason(
    limiter: &AuthLimiter,
    ip: IpAddr,
    peer: SocketAddr,
    username: &str,
) -> AuthReason {
    if limiter.is_locked(ip) {
        audit!(event = "auth.lockout", peer = %peer, user = %username);
        AuthReason::LockedOut
    } else {
        AuthReason::InvalidCredentials
    }
}

async fn write_result(
    send: &mut SendStream,
    ok: bool,
    reason: AuthReason,
    key_enrolled: bool,
) -> Result<()> {
    rmp_proto::write_message(
        send,
        &Message::AuthResult(AuthResult {
            ok,
            reason,
            session_token: None,
            key_enrolled,
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
