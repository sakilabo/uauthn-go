# uauthn

[日本語](README.ja.md)

uauthn is a lightweight implementation for using passkeys easily in web applications behind a reverse proxy.

uauthn runs as a standalone server for `forward_auth` / `auth_request`, as a Windows service, or as a Caddy module. It supports passwords and passkeys (WebAuthn), and offers passkey registration to users who sign in with a password.

- Passkeys (ES256, RS256, EdDSA) and argon2id passwords, on one login page
- After a password sign-in, passkey registration is offered before returning to the original page (`passkey_prompt`)
- Simple file layout: `config`, `passwd`, `session.dat`, `index.html`
- Go standard library and `golang.org/x` only; no cgo
- A simple, browser-only implementation.

## Standalone server

### Install

Download an archive from [Releases](https://github.com/sakilabo/uauthn-go/releases), or:

```sh
go install github.com/sakilabo/uauthn-go/cmd/uauthn@latest
```

### Commands

```sh
uauthn listen [--data_dir DIR] [[ADDR:]PORT]
uauthn add [--data_dir DIR] [--password PASSWORD] [--reset] USERNAME
uauthn install [--data_dir DIR] | uninstall      (Windows service)
uauthn index --output FILE
uauthn version
```

- `listen`: an address given here overrides `bind` / `port`.
- `add`: creates the user or replaces the user's password. Without `--password`, the password is read from the terminal twice. `--reset` drops every credential of the user, passkeys included, and creates it again. There is no other editing command; edit `passwd` directly or reset.
- `index`: writes the built-in login page to the `--output` file (`uauthn index --output index.html`).

### Data directory

The data directory can be given with `--data_dir`. Without it, the executable's directory is chosen when it contains a `config` or `passwd` file; otherwise `~/.uauthn` is chosen.

| File | Content |
| --- | --- |
| `config` | Settings (optional) |
| `passwd` | Users and credentials |
| `index.html` | Login page (optional; the embedded page is used when absent) |
| `session.dat` | Session times (`session = file`) |

`passwd` and `index.html` can be placed anywhere by setting `passwd_file` and `index_file`.

### config file

INI without sections. Lines starting with `#` or `;` are comments.

```ini
bind = 0.0.0.0
port = 10997
prefix = /uauthn
domain =
expired_sec = 259200
session = file
flush_sec = 5
log_file =
log_max_size = 1048576
log_generations = 3
passkey_prompt = always
title = Sign in
passwd_file =
index_file =
```

| Key | Default | Meaning |
| --- | --- | --- |
| `bind` | `0.0.0.0` | Listen address |
| `port` | `10997` | Listen port |
| `prefix` | `/uauthn` | Public path of the login page and its endpoints |
| `domain` | (empty) | Cookie `Domain` and the WebAuthn RP ID. Empty: host-only cookie, RP ID = request host |
| `expired_sec` | `259200` | Expiry of a session ID: seconds since authentication was last confirmed |
| `session` | `file` | `file` (alias `storage`) or `memory` |
| `flush_sec` | `5` | Interval in seconds for synchronizing `session.dat` with the storage |
| `log_file` | (empty) | Log file. Empty: standard output, or the Event Log while running as a Windows service |
| `log_max_size` | `1048576` | The log file is rotated when it exceeds this size. `0`: no limit |
| `log_generations` | `3` | Number of old logs kept (`*.1` to `*.N`). `0`: none are kept |
| `passkey_prompt` | `always` | How passkey registration is offered after a password sign-in: `always` always offers it, `unregistered` offers it when the user has no passkey, `never` does not offer it. |
| `title` | `Sign in` | Title of the login page and heading of the sign-in form |
| `passwd_file` | (empty) | `passwd` file; a relative path is resolved against the data directory |
| `index_file` | (empty) | `index.html` file; a relative path is resolved against the data directory |

### passwd file

One user per line: the UID and the user name, then several credentials separated by tabs. Sign-in succeeds when any one of the credentials matches.

```
1a2b3c4d	alice	$argon2id$v=19$m=47104,t=1,p=1$<salt>$<hash>	passkey:<credential ID>:<alg>:<public key>
```

- UID: a 32-bit value unique to each user, generated automatically by the `add` command.
- Password: argon2id in the PHC format, the same as Caddy `basic_auth`. Set by the `add` command.
- Passkey: `passkey:` + credential ID (base64url) + COSE algorithm (`-7`, `-257`, `-8`) + SubjectPublicKeyInfo (base64url). Registered from the login page.
- Lines starting with `#` are ignored as comments.

### session.dat file

`session.dat` is a binary file that records, for each session ID, the date and time when authentication was last confirmed.

The session ID is a 256-bit value made of the UID (32 bits) and random bits (224 bits). This value is set in the cookie `uauthn` in base64url (`Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS).

Header:

| Offset | Size | Content |
| --- | --- | --- |
| 0 | 6 | `UAUTHN` |
| 6 | 2 | Version (`2`, big endian) |

Record (40 bytes from offset `8 + 40n`):

| Offset in the record | Size | Content |
| --- | --- | --- |
| 0 | 32 | Session ID (the first 4 bytes are the UID, big endian) |
| 32 | 8 | Date and time when authentication was last confirmed (Unix time, big endian) |

- The number of records is a multiple of 16; a record with an all-zero session ID or time 0 is empty.
- The table lives in memory and is synchronized with the storage every `flush_sec`. When the content or size of the file is invalid, the file is overwritten from memory.
- The sessions of a user removed from `passwd` become invalid immediately.

### Endpoints

Paths below `prefix`. The server accepts them with or without the prefix, so the proxy may strip it.

| Path | Method | |
| --- | --- | --- |
| `/` | GET | Login page |
| `/challenge` | GET | Challenge; for a signed-in user also the registration parameters |
| `/login` | POST | Password or passkey sign-in; sets the cookie |
| `/passkey` | POST | Registers a passkey for the signed-in user |
| `/logout` | GET, POST | Ends the session; redirects to `rd` (a local path) or the login page |
| `/auth` | GET | For the proxy: `200` with `Remote-User`, or `401` |

`/challenge` returns JSON; a custom `index.html` reads the same fields. Each challenge is single-use and valid for 10 minutes.

| Field | When | Content |
| --- | --- | --- |
| `challenge` | always | base64url challenge; for sign-in when signed out, for registration when signed in |
| `rpId` | always | WebAuthn RP ID (`domain`, or the request host) |
| `passkeyPrompt` | always | `always`, `unregistered`, or `never` |
| `title` | always | Value of `title` |
| `user` | signed in | User name |
| `userId` | signed in | base64url UID (4 bytes), for `user.id` in `create()` |
| `exclude` | signed in | base64url credential IDs already registered, for `excludeCredentials` |

Without a valid session, `/auth` answers `401` with an HTML body that redirects to `<prefix>/?rd=<original URI>`. The original URI is taken from `X-Forwarded-Uri`, then `X-Original-URI`. The scheme and host for the WebAuthn origin are taken from `X-Forwarded-Proto` / `X-Forwarded-Host`.

### Login page

A passkey sign-in returns to the page the sign-in started from.

After a password sign-in, the standard `index` page reads `passkeyPrompt` (`passkey_prompt` in config) from `/challenge` and, following the setting, shows the passkey registration page or returns to the page the sign-in started from.

### Reverse proxy

Caddy:

```caddyfile
example.com {
	handle_path /uauthn/* {
		reverse_proxy 127.0.0.1:10997
	}
	handle {
		forward_auth 127.0.0.1:10997 {
			uri /auth
			copy_headers Remote-User
		}
		reverse_proxy 127.0.0.1:8080
	}
}
```

nginx (`auth_request` treats any status other than 2xx, 401 and 403 as an error, so the redirect is done with `error_page`):

```nginx
location /uauthn/ {
    proxy_pass http://127.0.0.1:10997;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
location = /_uauthn {
    internal;
    proxy_pass http://127.0.0.1:10997/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Host $host;
    proxy_set_header X-Original-URI $request_uri;
}
location / {
    auth_request /_uauthn;
    auth_request_set $user $upstream_http_remote_user;
    proxy_set_header Remote-User $user;
    error_page 401 = @login;
    proxy_pass http://127.0.0.1:8080;
}
location @login {
    return 302 /uauthn/?rd=$uri;
}
```

Traefik: a `forwardAuth` middleware with `address: http://127.0.0.1:10997/auth` and `authResponseHeaders: [Remote-User]`, and a router for `PathPrefix(/uauthn)` to the uauthn service.

## Windows service

```
uauthn install [--data_dir DIR]
uauthn uninstall
```

`install` registers the service `uauthn` (automatic start, LocalSystem, `listen` with `config`) and the Event Log source `uauthn`; with `--data_dir`, the service uses that directory. It needs administrator rights. `uninstall` stops and removes both. As LocalSystem, `~` is `C:\Windows\System32\config\systemprofile`, so placing `config` and `passwd` next to the executable or giving `--data_dir` is recommended. Without `log_file`, messages are written to the Application log.

## Caddy module

The module `http.handlers.uauthn` serves the login page and checks the session inside Caddy, without a separate process or `forward_auth`. Its files live in Caddy's storage under `uauthn/`, so there is no file location to manage either.

```sh
xcaddy build --with github.com/sakilabo/uauthn-go/caddy
```

```caddyfile
example.com {
	uauthn
	reverse_proxy 127.0.0.1:8080
}
```

An example with values given in subdirectives:

```caddyfile
example.com {
	uauthn {
		prefix /signin
		domain example.com
		expired_sec 604800
		session file
		flush_sec 10
		passkey_prompt unregistered
		title "Example sign in"
		passwd_file /etc/uauthn/passwd
		index_file /etc/uauthn/index.html
	}
	reverse_proxy 127.0.0.1:8080
}
```

| Key in Caddy's storage | Content |
| --- | --- |
| `uauthn/passwd` | Users and credentials (unless `passwd_file` is set) |
| `uauthn/index.html` | Login page (unless `index_file` is set); the embedded page is used when absent |
| `uauthn/session.dat` | Session times (`session file`) |

| Subdirective | Default | |
| --- | --- | --- |
| `prefix` | `/uauthn` | Path of the login page and its endpoints |
| `passwd_file` | (empty) | When not given, `uauthn/passwd` in Caddy's storage is chosen |
| `index_file` | (empty) | When not given, `uauthn/index.html` in Caddy's storage is chosen |
| `domain` | (empty) | Cookie `Domain` and RP ID |
| `expired_sec` | `259200` | Expiry of a session ID: seconds since authentication was last confirmed |
| `session` | `file` | `file` / `storage`: `uauthn/session.dat` in Caddy's storage. `memory`: kept across config reloads, lost on restart |
| `flush_sec` | `5` | Interval in seconds for synchronizing `uauthn/session.dat` with Caddy's storage |
| `passkey_prompt` | `always` | `always`, `unregistered`, or `never` |
| `title` | `"Sign in"` | Title of the login page and heading of the sign-in form; quote it when it contains spaces |

- Requests under `prefix` are answered by uauthn. Other requests pass with `Remote-User` set (any incoming `Remote-User` is removed) and `{http.auth.user.id}` available, or get the redirecting `401`.
- A request matcher limits the protected requests: `uauthn @protected { ... }`. The directive is ordered before `basic_auth`.
- Users are managed with a `caddy` subcommand. The subcommand does not read Caddy's config, so give the `passwd` file with `--passwd_file`. When `--passwd_file` is omitted, Caddy's default storage is chosen.

```sh
caddy uauthn add [--passwd_file PATH] [--password PASSWORD] [--reset] USERNAME
```

- `caddy uauthn index --output FILE` writes the built-in login page to a file.

## License

[UPL 1.0](LICENSE)

## Author

[Sakilabo Corporation Ltd.](https://sakilabo.jp)
