# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `rmp doctor` (alias `rmp status`): local diagnostics for config, host key,
  password files, permissions, `authorized_keys`, `known_hosts`, UDP listener,
  PID file and the systemd service. Exits non-zero when it finds errors.
- `rmp known-hosts list|update|remove`: inspect and edit the client trust store
  without hand-editing the file. Hosts accept optional ports and IPv6 literals.
- `rmp keys list|revoke`: audit and revoke server-side device keys by fingerprint
  or public-key hex. Revocation applies to the next login; the last key is
  protected from revocation when password authentication is disabled.
- `rmp connect` / `rmp cp --update-host-key`: deliberately update a changed
  server fingerprint in `known_hosts` after showing the old and new values.
- `rmp init --new-host-key`: rotate the server host key explicitly. Without it,
  `rmp init --force` now preserves the existing key.
- Application-level `Ping`/`Pong` keepalive on the control stream during
  interactive sessions, with detection of a link that stops answering.
- A PID file and a clear "already running / address in use" error; `rmp init`
  refuses to overwrite state while a server is running.
- Graceful `SIGTERM` handling (and `SIGHUP` ignored) for service managers.

### Changed

- `rmp init` now merges an existing `config.toml` instead of overwriting it
  with the template. Comments and custom settings are preserved; only
  `server.username`, `server.listen` and `auth.allow_root` are updated. Invalid
  TOML aborts before any host key/password state is replaced.
- Host-key pinning is now enforced after the TLS handshake and before
  authentication, so a mismatch reports both fingerprints and a recovery path
  instead of an opaque rustls `ApplicationVerificationFailure`.
- Password files are re-read on every login, so `rmp passwd` takes effect
  without restarting `rmp serve`.
- `rmp passwd --user` must match `server.username`; renaming the account is done
  with `rmp init --user ... --force` (host key preserved).
- When the account name changes, old device keys are moved to
  `authorized_keys.bak` instead of silently authenticating as the new account.

### Fixed

- Interrupted sessions/transfers are no longer reported as success:
  `StreamError::Closed` without an `ExitStatus`/`Eof` returns an error.
- Downloads and uploads write to a temporary file and rename on completion, so
  a dropped connection does not leave a truncated destination marked as valid.
- Server connection close reasons are logged.

### Planned

- Fuzzing of the wire format and 0-RTT resumption.

## [0.5.1] - 2026-10-15

### Fixed

- CLI accepts **IPv6 literal** targets: `rmp connect user@[::1]:2222` and bare IPv6
  (`user@::1`); the `known_hosts` key is bracketed (`[::1]:2222`) for IPv6 hosts. The
  transport (QUIC over UDP) and the CIDR allow/deny lists already supported IPv6.
- `rmp cp` accepts the `/` separator (`user@host/path`) in addition to `:`, and bracketed
  IPv6 hosts (`user@[::1]:/path`).

## [0.5.0] - 2026-10-15

### Changed

- **File transfer preserves Unix permissions** in both directions: `Put` sends the source
  mode and `Get` returns the remote mode, applied to the local file. `PROTO_VERSION`
  bumped to 3 (`FileRequest`/`FileResponse` gained a `mode` field).

### Fixed

- `rmp cp` remote paths accept `~` / `~/...` (expand to the server user's home).
- `rmp cp` error message now shows the expected `user@host:path` syntax.

## [0.4.0] - 2026-10-15

### Added

- **`rmp install-service` / `rmp uninstall-service`.** Install a systemd system unit so
  `rmp serve` starts at boot (Linux). Detects the service user (`SUDO_USER`) and its home
  from `/etc/passwd`, uses the running binary by default, and supports `--no-start` and
  `--dry-run`.

## [0.3.0] - 2026-10-15

### Added

- **File transfer (`rmp cp <src> <dst>`).** Upload or download a file to/from
  `user@host:path` over a dedicated QUIC stream (`FileRequest`/`FileResponse` +
  `Data`/`Eof`); `Put` is confirmed with an `ExitStatus`. Relative paths resolve to the
  server user's home directory. Gated by `[server] allow_file_transfer`.

## [0.2.0] - 2026-10-15

### Changed

- **Wire format v2 (breaking).** Messages are now framed with an explicit `FrameType` tag
  and the body is serialized on its own, instead of serializing the `Message` enum whose
  variants are numbered positionally. Adding new message types no longer shifts the
  encoding of existing ones, so incompatible versions fail fast (version negotiation)
  rather than failing mid-session. `WIRE_VERSION` and `PROTO_VERSION` are bumped to 2.

### Fixed

- `rmp connect` now establishes the connection and verifies the server host key (TOFU)
  *before* offering device-key enrollment and asking for the password.

## [0.1.1] - 2026-10-15

### Added

- **Device-key enrollment and passwordless login.** After a successful password login a
  client may enroll an Ed25519 device key (stored server-side in `authorized_keys`,
  `0600`). Subsequent logins authenticate by signing a fresh server nonce
  (`KeyAuthRequest` → `KeyAuthChallenge` → `KeyAuthProof`), bound to the account and key.
  Controlled by `[auth] allow_key_auth` / `allow_key_enrollment` and
  `[client] enable_key_auth` / `offer_enrollment`.
- **Local port forwarding (`rmp connect -L [bind:]port:host:hostport`, `-N`).** Each
  accepted TCP connection is tunnelled over a dedicated QUIC stream; the server dials the
  target and pipes bytes (`ForwardRequest`/`ForwardResponse` + `Data`). Gated by
  `[server] allow_local_forward`.
- **Remote port forwarding (`rmp connect -R [bind:]port:host:hostport`).** The client asks
  the server to listen on `127.0.0.1:port` (`RemoteForwardBind`); each accepted connection
  is offered back over a server-initiated QUIC stream (`ForwardRequest`) and the client
  dials the target. Gated by `[server] allow_remote_forward` (default `false`; loopback
  only).

### Changed

- The server now serves multiple concurrent streams per connection (sessions and forwards).

## [0.1.0] - 2026-10-12

Initial MVP: a functional, tested, SSH-like remote shell.

### Added

- **Protocol (`rmp-proto`)**: versioned binary framing with defensive validation
  (magic, wire version, bounded length, message-type cross-check) and the control/session
  message set.
- **Crypto (`rmp-crypto`)**: Ed25519 host keys with self-signed certificates,
  TLS 1.3 with hybrid post-quantum key exchange (X25519 + ML-KEM-768), fingerprint-based
  trust-on-first-use client verifier, and **OPAQUE** password authentication.
- **Transport**: QUIC via `quinn` (multiplexed streams, loss recovery, congestion
  control, keep-alive, connection migration).
- **Server (`rmp-server`)**: QUIC listener, authentication with per-IP rate limiting and
  lockout, CIDR allow/deny lists, interactive PTY and non-interactive `exec` sessions,
  optional root login with privilege dropping, and a dedicated audit log.
- **Client (`rmp-client`)**: pinned transport, OPAQUE login, `exec`, PTY capture and an
  interactive shell with raw mode and window resize.
- **CLI (`rmp-cli`)**: `rmp init`, `rmp serve`, `rmp connect`, `rmp passwd`.
- **Layout (`rmp-dirs`)**: XDG directories for user installs and FHS directories
  (`/etc`, `/var/lib`, `/var/log`) for system services, with `0700`/`0600` permissions.
- **Logging**: rotating `rmp.log` (everything) and `audit.log` (security events only).
- Fully commented [configuration example](config.example.toml).

[Unreleased]: https://github.com/marcosgabrielgomes110-collab/rmp/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/marcosgabrielgomes110-collab/rmp/releases/tag/v0.5.1
[0.5.0]: https://github.com/marcosgabrielgomes110-collab/rmp/releases/tag/v0.5.0
[0.4.0]: https://github.com/marcosgabrielgomes110-collab/rmp/releases/tag/v0.4.0
[0.3.0]: https://github.com/marcosgabrielgomes110-collab/rmp/releases/tag/v0.3.0
[0.2.0]: https://github.com/marcosgabrielgomes110-collab/rmp/releases/tag/v0.2.0
[0.1.1]: https://github.com/marcosgabrielgomes110-collab/rmp/releases/tag/v0.1.1
[0.1.0]: https://github.com/marcosgabrielgomes110-collab/rmp/releases/tag/v0.1.0
