# Contributing to RMP

Thanks for your interest in RMP (Remote Machine Protocol)! This document explains how to
build, test and contribute.

## Development environment

- **Rust**: the toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml)
  (stable + `rustfmt` + `clippy`).
- **Linux/macOS**: a C toolchain is required for `aws-lc-rs` (the default crypto
  provider). On Debian/Ubuntu: `build-essential cmake`.
- **Windows**: MSVC build tools; `nasm` may be needed for `aws-lc-rs`.

## Build and test

```sh
cargo build                 # debug
cargo build --release       # optimized binary (LTO + strip)
cargo test                  # unit + end-to-end integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

Or, with the provided Makefile:

```sh
make            # release build
make test
make clippy
make fmt-check
```

## Project layout

| Crate | Responsibility |
|---|---|
| `rmp-proto` | Wire protocol: framing, messages, codecs |
| `rmp-dirs` | Filesystem layout (XDG / FHS) |
| `rmp-crypto` | TLS 1.3 + PQC, host keys, OPAQUE, known_hosts |
| `rmp-server` | QUIC listener, authentication, PTY/exec sessions, audit log |
| `rmp-client` | Transport, authentication, interactive/exec client |
| `rmp-cli` | The `rmp` binary (`init`/`serve`/`connect`/`passwd`) |

## Guidelines

- **Security first.** This project handles authentication and terminal data. Never log
  secrets, use constant-time comparison for sensitive data, and prefer bounded,
  fail-closed parsing.
- **No `unsafe`** unless strictly necessary and justified (the crates are `deny`/`forbid`
  unsafe where possible).
- **Tests.** New behavior must come with tests. Protocol changes go in `rmp-proto` with
  round-trip tests; end-to-end behavior goes in
  `crates/rmp-server/tests/roundtrip.rs`.
- **Formatting & lints.** CI enforces `cargo fmt --check` and `cargo clippy -D warnings`.
- **Commits.** Use clear, imperative subject lines. Keep changes focused.

## Pull requests

1. Fork and create a topic branch.
2. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` all pass.
3. Update documentation (`README.md`, `docs/`, `CHANGELOG.md`) when behavior changes.
4. Open a PR using the template; describe the motivation and any security implications.

## Reporting security issues

Do **not** open a public issue for vulnerabilities — see [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the terms of the
project: **MIT**.
