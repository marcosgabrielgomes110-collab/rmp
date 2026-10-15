# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned

- File transfer (SFTP-like channel).
- Fuzzing of the wire format and 0-RTT resumption.

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

[Unreleased]: https://github.com/marcosgabrielgomes110-collab/rmp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/marcosgabrielgomes110-collab/rmp/releases/tag/v0.2.0
[0.1.1]: https://github.com/marcosgabrielgomes110-collab/rmp/releases/tag/v0.1.1
[0.1.0]: https://github.com/marcosgabrielgomes110-collab/rmp/releases/tag/v0.1.0
