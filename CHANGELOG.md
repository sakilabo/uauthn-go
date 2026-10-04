# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-10-05

### Added

- `title` setting (default `Sign in`) in `config` and the Caddy directive for the title and heading of the login page. `/challenge` returns `title`.

### Removed

- The message on the login page that asked for passkey registration after a password sign-in.

## [0.3.0] - 2026-10-05

### Removed

- The `caddy uauthn add` options `--config` / `--adapter`. The subcommand does not read Caddy's config; give the `passwd` file with `--passwd_file`, or omit it to use `uauthn/passwd` in the default storage.

## [0.2.0] - 2026-10-05

### Added

- `passwd_file` and `index_file` settings in `config` and the Caddy directive. When set, no other location is searched.
- `caddy uauthn add` accepts `--config` / `--adapter` and writes to the storage of that config, resolved like `caddy storage export`.

### Changed

- The Caddy module keeps `passwd` in Caddy's storage (`uauthn/passwd`) and reads the login page from `uauthn/index.html`, falling back to the embedded page. It no longer looks for files next to the `caddy` executable or in `~/.uauthn`.
- The Caddy subdirectives `passwd` / `index` are replaced by `passwd_file` / `index_file`, and the `caddy uauthn add` option `--passwd` by `--passwd_file`.

### Fixed

- The standalone server took a directory named `config` or `passwd` next to the executable as its data files.

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
