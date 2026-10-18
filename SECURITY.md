# Security Policy

## Supported versions

RMP is pre-1.0. Security fixes are applied to the latest release on the default branch.

| Version | Supported |
|---|---|
| 0.5.x   | ✅        |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use one of the following private channels:

- GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  (Security → Report a vulnerability), or
- email the maintainers.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a proof of concept if possible),
- affected version/commit,
- any suggested mitigation.

We aim to acknowledge reports within **72 hours** and will keep you informed of progress.
Please allow us reasonable time to release a fix before public disclosure.

## Scope

In scope: `rmp-proto`, `rmp-crypto`, `rmp-server`, `rmp-client`, `rmp-cli`, `rmp-dirs`.

Out of scope: issues in dependencies (please report upstream), and deployments configured
insecurely (e.g. `client.strict_host_key = false`, `[auth] password_enabled = true` with a
trivial password, or exposing the service without an allow-list).

## Design notes for reviewers

- Transport: QUIC + TLS 1.3 (no plaintext, no downgrade), hybrid post-quantum key
  exchange by default.
- Password authentication uses **OPAQUE (RFC 9807)**; the password never travels and the
  server stores only an offline-attack-resistant record.
- Server identity is an Ed25519 host key, verified by fingerprint (trust-on-first-use).
- See [`docs/threat-model.md`](docs/threat-model.md) for assets, adversaries, guarantees
  and **non-guarantees**.
