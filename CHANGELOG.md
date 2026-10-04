# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-10-05

### Added

- `passkey_prompt` setting (`always`, `unregistered`, `never`; default `always`) in `config` and the Caddy directive. After a password sign-in with a return URL, the login page offers passkey registration before returning to the original page.
- `/challenge` returns `passkeyPrompt`.

### Changed

- Registering a passkey from the login page returns to the original page when there is one.

## [0.1.0] - 2026-10-05

First public release.

### Added

- Login page with passkey (WebAuthn: ES256, RS256, EdDSA) and argon2id password sign-in, passkey autofill, and passkey registration for the signed-in user.
- `passwd` file with one user per line and any number of credentials; password hashes are compatible with Caddy `basic_auth`.
- Sessions identified by a cookie, with expiry counted from the last confirmation (`expired_sec`), kept in memory or in `session.dat` written every `flush_sec` and merged with changes made elsewhere.
- Standalone server (`uauthn listen`) with `/auth` for Caddy `forward_auth`, nginx `auth_request`, and Traefik `forwardAuth`, passing the user in `Remote-User`.
- `uauthn add` to create users and set or reset credentials.
- Windows service (`uauthn install` / `uninstall`) with Event Log output.
- Caddy module `http.handlers.uauthn` with the `uauthn` directive and the `caddy uauthn add` subcommand.
