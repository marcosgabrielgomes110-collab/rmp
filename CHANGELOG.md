# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`rmp exec user@host -- command`**: non-interactive remote execution with the
  remote exit status and stdout forwarded.
- **`rmp known-hosts list|remove`** and **`rmp keys list|revoke`**: inspect/remove
  TOFU entries and revoke enrolled device keys.
- **`--fingerprint <hex>`** on `connect`, `cp` and `exec` for out-of-band host key
  pinning (no TOFU prompt and no `known_hosts` update).
- **`--password-stdin`** for `rmp init`/`rmp passwd` (normal account first, then
  root when `--root` is used) and **`--reset-keys`** for `rmp init`.
- **`rmp config-check`**: validates TOML, unknown keys, CIDRs, listen address and
  limits without starting the server.
- **`rmp cp -r/--recursive`**: upload/download directory trees (nested directories,
  empty directories, Unix modes). Symlinks and special files are skipped.
- **`rmp cp --progress`** and **`[logging] format = "json"`** (structured file
  logs; console output remains text).
- **`rmp doctor`**: checks config, directory/file permissions, required secrets and
  `runuser` availability.
- Directory overrides (`--dir`, `--system`, `--config-dir`, …) are now global and
  can appear before or after the subcommand.

### Security

- **Root mode privilege boundary.** While `rmp serve` runs as root, non-root
  logins run `rmp cp` and local forwarding (`-L`) through a
  `runuser -l <user> -- rmp __helper` process, so file and network operations use
  the target user's credentials instead of the daemon's. Remote forwarding (`-R`)
  permits high ports (>= 1024) in root mode; privileged ports require the explicit
  `[server] allow_privileged_ports = true` opt-in. `root` can no longer be configured as
  `server.username` (use `--root`), and root password authentication always uses
  the separate root record.
- Passwords, OPAQUE login states and the temporary device-key seed are zeroized
  when dropped.
- Files written by `rmp init`/`rmp passwd`/key enrollment are re-tightened to
  `0600` even when they already existed with looser permissions.
- `known_hosts` is written atomically through a private temporary file.
- Device-key enrollment is rejected for the root principal, and device-key
  authentication is never accepted for `root`.
- The server rejects an incompatible `Hello.proto_version` before authentication
  instead of failing later in the session.

### Changed

- **File transfer protocol version 5.** `FileOp::Mkdir`/`FileOp::List` and the
  `FileEntry` message (0x62) support recursive `rmp cp`. Version 4 had added the
  expected size to `FileRequest` for `Put`; the server rejects a size mismatch
  (`ExitStatus{1}`) and discards the temporary file.

### Fixed

- Interrupted uploads no longer commit partial files: `Put` writes to a
  temporary file and renames only after `Eof`, size verification, `flush` and
  `fsync`.
- Truncated downloads are rejected (size is verified and partial local files are
  removed) instead of being reported as successful.
- Failed authentication closes the QUIC connection instead of keeping it (and
  its task) alive until the idle timeout. Handshake/auth exchanges now have
  timeouts, and `server.max_connections` bounds concurrent connections.
- PTY output is drained before `ExitStatus`; session/exec channels are bounded so
  a fast producer cannot grow memory without limit.
- Forwarded TCP streams wait for both directions, preserving half-closes.
- `rmp connect -L/-R` accepts bracketed IPv6 addresses (`8080:[::1]:80`).
- `rmp serve` handles `SIGTERM` (e.g. `systemctl stop`) and logs `server.stop`.
- Log files have retention (14 days for `rmp.log`, 30 for `audit.log`), are kept
  in a `0700` directory, and an invalid `logging.level` no longer panics.
- **Rate limiting is per `(user, network)`** and, with a higher threshold, per
  network; IPv6 hosts are grouped by `/64`. Successful logins clear both counters.
- `rmp connect`/`rmp cp` no longer silently fall back to defaults when
  `config.toml` is malformed; `rmp config-check` reports unknown options.
- The generated systemd unit includes `NoNewPrivileges`, `ProtectSystem=full`,
  kernel/control-group protection, `RestrictSUIDSGID`, `LockPersonality`,
  `RestrictAddressFamilies` and `LimitNOFILE`.
- Releases publish `SHA256SUMS`; `scripts/update.sh` verifies the downloaded
  archive before running it.

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
