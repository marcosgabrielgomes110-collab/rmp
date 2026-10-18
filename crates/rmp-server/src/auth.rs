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

/// Upper bound on tracked principals/IPs, to keep a username-spraying attacker
/// from growing the limiter without limit.
const MAX_TRACKED: usize = 4096;

/// In-memory failed-authentication tracker with temporary lockout.
///
/// Attempts are tracked per `(network, username)` and, with a higher threshold,
/// per network. IPv6 addresses are grouped by `/64` so rotating the host bits
/// does not bypass the limit.
#[derive(Debug)]
pub struct AuthLimiter {
    max_attempts: u32,
    lockout: Duration,
    principals: Mutex<HashMap<(IpAddr, String), Entry>>,
    networks: Mutex<HashMap<IpAddr, Entry>>,
}

#[derive(Debug, Default)]
struct Entry {
    failures: u32,
    last_failure: Option<Instant>,
    locked_until: Option<Instant>,
}

impl AuthLimiter {
    pub fn new(max_attempts: u32, lockout: Duration) -> Self {
        AuthLimiter {
            max_attempts,
            lockout,
            principals: Mutex::new(HashMap::new()),
            networks: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `user` from `ip` is currently locked out.
    pub fn is_locked(&self, ip: IpAddr, user: &str) -> bool {
        let now = Instant::now();
        let key_ip = network_key(ip);

        let mut principals = self.principals.lock().expect("limiter mutex poisoned");
        let key = (key_ip, user.to_string());
        if let Some(entry) = principals.get_mut(&key) {
            match entry.locked_until {
                Some(until) if until > now => return true,
                // Expired lockout: drop the entry and start over.
                Some(_) => {
                    principals.remove(&key);
                }
                // Still accumulating failures; keep the count.
                None => {}
            }
        }

        let mut networks = self.networks.lock().expect("limiter mutex poisoned");
        if let Some(entry) = networks.get_mut(&key_ip) {
            match entry.locked_until {
                Some(until) if until > now => return true,
                Some(_) => {
                    networks.remove(&key_ip);
                }
                None => {}
            }
        }
        false
    }

    fn record_failure(&self, ip: IpAddr, user: &str) {
        if self.max_attempts == 0 {
            return;
        }

        let key_ip = network_key(ip);
        let now = Instant::now();
        let key = (key_ip, user.to_string());

        {
            let mut map = self.principals.lock().expect("limiter mutex poisoned");
            if !map.contains_key(&key) && map.len() >= MAX_TRACKED {
                prune(&mut map, now, self.lockout);
            }
            if map.len() < MAX_TRACKED || map.contains_key(&key) {
                record(
                    map.entry(key).or_default(),
                    now,
                    self.max_attempts,
                    self.lockout,
                );
            }
        }

        // A higher aggregate threshold avoids one user's failures locking every
        // other user behind the same NAT, while still bounding spraying.
        {
            let mut map = self.networks.lock().expect("limiter mutex poisoned");
            if !map.contains_key(&key_ip) && map.len() >= MAX_TRACKED {
                prune(&mut map, now, self.lockout);
            }
            if map.len() < MAX_TRACKED || map.contains_key(&key_ip) {
                let threshold = self.max_attempts.saturating_mul(4);
                record(map.entry(key_ip).or_default(), now, threshold, self.lockout);
            }
        }
    }

    fn record_success(&self, ip: IpAddr, user: &str) {
        let key_ip = network_key(ip);
        self.principals
            .lock()
            .expect("limiter mutex poisoned")
            .remove(&(key_ip, user.to_string()));
        // A successful login clears the aggregate too, so collateral lockouts
        // from a shared NAT do not persist.
        self.networks
            .lock()
            .expect("limiter mutex poisoned")
            .remove(&key_ip);
    }
}

/// Group IPv6 addresses by `/64`; keep IPv4 addresses as-is.
fn network_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                0,
                0,
            ))
        }
        IpAddr::V4(_) => ip,
    }
}

fn record(entry: &mut Entry, now: Instant, threshold: u32, lockout: Duration) {
    entry.failures = entry.failures.saturating_add(1);
    entry.last_failure = Some(now);
    if threshold != 0 && entry.failures >= threshold {
        entry.locked_until = Some(now + lockout);
    }
}

fn prune<K>(map: &mut HashMap<K, Entry>, now: Instant, window: Duration) {
    map.retain(|_, entry| {
        if entry.locked_until.is_some_and(|until| until > now) {
            return true;
        }
        entry
            .last_failure
            .is_some_and(|last| now.duration_since(last) < window)
    });
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

    let first = match rmp_proto::read_message(recv).await {
        Ok(msg) => msg,
        Err(_) => {
            audit!(event = "auth.aborted", peer = %peer, stage = "start");
            return Ok(None);
        }
    };

    let username = match &first {
        Message::AuthStart(start) => start.username.clone(),
        Message::KeyAuthRequest(req) => req.username.clone(),
        other => anyhow::bail!("unexpected first auth message: {:?}", other.frame_type()),
    };

    if limiter.is_locked(ip, &username) {
        tracing::warn!(%peer, user = %username, "authentication attempt while locked out");
        audit!(event = "auth.locked_out", peer = %peer, user = %username);
        write_result(send, false, AuthReason::LockedOut, false).await?;
        return Ok(None);
    }

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
    // `root` is checked first and never shares the normal account's password
    // file, even if a misconfiguration made `server.username = "root"`.
    let (file, principal) = if username == "root" {
        if opts.allow_root {
            (opts.root_password_file.as_ref(), Principal::Root)
        } else {
            (None, Principal::User)
        }
    } else if username == opts.username {
        let file = if opts.password_enabled {
            Some(&opts.password_file)
        } else {
            None
        };
        (file, Principal::User)
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
            limiter.record_failure(ip, &username);
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
            limiter.record_failure(ip, &username);
            audit!(event = "auth.failure", peer = %peer, user = %username, method = "password",
                   reason = "unexpected_message", got = %format!("{:?}", other.frame_type()));
            write_result(send, false, AuthReason::InvalidCredentials, false).await?;
            return Ok(None);
        }
    };

    match crypto::password::server_finish(&state, &payload) {
        Ok(_session_key) => {
            limiter.record_success(ip, &username);

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
            limiter.record_failure(ip, &username);
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

    // Device keys are only supported for the normal account. Root always
    // requires its separate password.
    if username == "root" || !opts.allow_key_auth || public_key.len() != 32 {
        limiter.record_failure(ip, &username);
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
            limiter.record_failure(ip, &username);
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
        limiter.record_success(ip, &username);
        audit!(event = "auth.success", peer = %peer, user = %username, method = "key");
        write_result(send, true, AuthReason::Ok, false).await?;
        Ok(Some(Authed {
            username,
            principal: Principal::User,
        }))
    } else {
        limiter.record_failure(ip, &username);
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
    // Root cannot authenticate with a device key, so enrolling one would only
    // create a useless entry.
    if principal == Principal::Root || !opts.allow_key_enrollment || public_key.len() != 32 {
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
    if limiter.is_locked(ip, username) {
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
        limiter.record_failure(addr, "alice");
        limiter.record_failure(addr, "alice");
        assert!(!limiter.is_locked(addr, "alice"));
        limiter.record_failure(addr, "alice");
        assert!(limiter.is_locked(addr, "alice"));
    }

    #[test]
    fn success_resets_failures() {
        let limiter = AuthLimiter::new(3, Duration::from_secs(60));
        let addr = ip(2);
        limiter.record_failure(addr, "alice");
        limiter.record_failure(addr, "alice");
        limiter.record_success(addr, "alice");
        limiter.record_failure(addr, "alice");
        limiter.record_failure(addr, "alice");
        assert!(!limiter.is_locked(addr, "alice"));
    }

    #[test]
    fn expired_lockout_is_cleared() {
        let limiter = AuthLimiter::new(1, Duration::from_millis(0));
        let addr = ip(3);
        limiter.record_failure(addr, "alice");
        assert!(!limiter.is_locked(addr, "alice"));
    }

    #[test]
    fn users_are_limited_independently() {
        let limiter = AuthLimiter::new(3, Duration::from_secs(60));
        let addr = ip(4);
        for _ in 0..3 {
            limiter.record_failure(addr, "alice");
        }
        assert!(limiter.is_locked(addr, "alice"));
        assert!(
            !limiter.is_locked(addr, "bob"),
            "one user's failures must not lock another user behind the same IP"
        );
    }

    #[test]
    fn ipv6_is_grouped_by_64() {
        let limiter = AuthLimiter::new(1, Duration::from_secs(60));
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::9999".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();

        limiter.record_failure(a, "alice");
        assert!(
            limiter.is_locked(b, "alice"),
            "same /64 must share the limit"
        );
        assert!(!limiter.is_locked(other, "alice"));
    }
}
