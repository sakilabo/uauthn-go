# uauthn

[日本語](README.ja.md)

uauthn is a lightweight implementation for putting passkeys in front of web applications behind a reverse proxy. Its purpose is to make passkey authentication easy to adopt: a user signs in once with a password and is then led to register a passkey. It signs users in with a passkey (WebAuthn) or a password and tells the proxy who is signed in. It runs as a standalone server for `forward_auth` / `auth_request`, as a Windows service, or as a Caddy module.

- Passkeys (ES256, RS256, EdDSA) and argon2id passwords, on one login page
- After a password sign-in, passkey registration is offered before returning to the original page (`passkey_prompt`)
- Plain files: `config`, `passwd`, `session.dat`, `index.html`
- Go standard library and `golang.org/x` only; no cgo
- Browser-only; requires HTTPS (or `http://localhost`)

## Standalone server

### Install

Download an archive from [Releases](https://github.com/sakilabo/uauthn-go/releases), or:

```sh
go install github.com/sakilabo/uauthn-go/cmd/uauthn@latest
```

### Commands

```
uauthn listen [[ADDR:]PORT]
uauthn add [--password PASSWORD] [--reset] USERNAME
uauthn install | uninstall      (Windows service)
uauthn version
```

- `listen`: an address given here overrides `bind` / `port`.
- `add`: creates the user or replaces the user's password. Without `--password`, the password is read from the terminal twice. `--reset` drops every credential of the user, passkeys included. There is no other editing command; edit `passwd` directly or reset.

### Data directory

The executable's directory when it contains `config` or `passwd`; otherwise `~/.uauthn`. All files live there.

| File | Content |
| --- | --- |
| `config` | Settings (optional) |
| `passwd` | Users and credentials |
| `session.dat` | Session times (`session = file`) |
| `index.html` | Login page (optional; the embedded page is used when absent) |

An existing file is rewritten in place, so `passwd` and `session.dat` may be symbolic links.

### config

INI without sections. `#` or `;` starts a comment line.

```ini
bind = 0.0.0.0
port = 10997
prefix = /uauthn
domain =
expired_sec = 86400
session = file
flush_sec = 5
log =
log_max_size = 1048576
passkey_prompt = always
```

| Key | Default | Meaning |
| --- | --- | --- |
| `bind` | `0.0.0.0` | Listen address |
| `port` | `10997` | Listen port |
| `prefix` | `/uauthn` | Public path of the login page and its endpoints |
| `domain` | (empty) | Cookie `Domain` and the WebAuthn RP ID. Empty: host-only cookie, RP ID = request host |
| `expired_sec` | `86400` | A session expires this many seconds after its last confirmation |
| `session` | `file` | `file` (alias `storage`) or `memory` |
| `flush_sec` | `5` | Interval for writing `session.dat` |
| `log` | (empty) | Log file. Empty: standard output, or the Event Log when running as a Windows service |
| `log_max_size` | `1048576` | When the log would exceed this size, it is renamed to `*.old`. `0`: no limit |
| `passkey_prompt` | `always` | After a password sign-in with a return URL: `always` offers passkey registration, `unregistered` offers it only when the user has no passkey, `never` returns at once |

The log file is opened for each line, so external rotation may rename or delete it at any time.

### Login page

After a password sign-in, the page reads `passkeyPrompt` from `/challenge` and either shows the passkey registration (with "Continue" to the original page) or returns to the original page. Registering a passkey also returns there. A passkey sign-in returns at once. The default is `always` because the purpose of uauthn is to get users onto passkeys.

### passwd

One user per line: the user name, then any number of credentials separated by tabs, in no particular order. Lines starting with `#` are kept as they are.

```
alice	$argon2id$v=19$m=47104,t=1,p=1$<salt>$<hash>	passkey:<credential ID>:<alg>:<public key>
```

- Password: argon2id in the PHC format, the same as Caddy `basic_auth` (`caddy hash-password --algorithm argon2id`). Several hashes may be listed; any of them matches.
- Passkey: `passkey:` + credential ID (base64url) + COSE algorithm (`-7`, `-257`, `-8`) + SubjectPublicKeyInfo (base64url). Added from the login page.
- The file is re-read when its size or modification time changes.

### Sessions

The cookie `uauthn` carries `base64url(user).base64url(key)` with a 32-byte random key (`Path=/`, `HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS). `session.dat` holds only the last confirmation time of each session, keyed by `SHA-256(user + key)`; each request that passes moves the time forward.

`session.dat` layout (little endian):

| Offset | Size | Content |
| --- | --- | --- |
| 0 | 6 | `UAUTHN` |
| 6 | 2 | Version (`1`) |
| 8 + 40n | 32 | `SHA-256(user + key)` |
| 40 + 40n | 8 | Unix time of the last confirmation |

- The number of records is a multiple of 16; a record with an all-zero key or time 0 is empty.
- The table lives in memory and is written every `flush_sec`. Before writing, a file changed elsewhere is read and merged (newer time wins). A file whose size is not `8 + 40 × 16k` is discarded and overwritten from memory.
- A user removed from `passwd` loses its sessions immediately.

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
| `user` | signed in | User name |
| `userId` | signed in | base64url `SHA-256(user name)`, for `user.id` in `create()` |
| `exclude` | signed in | base64url credential IDs already registered, for `excludeCredentials` |

Without a valid session, `/auth` answers `401` with an HTML body that redirects to `<prefix>/?rd=<original URI>`. The original URI is taken from `X-Forwarded-Uri`, then `X-Original-URI`. The scheme and host for the WebAuthn origin are taken from `X-Forwarded-Proto` / `X-Forwarded-Host`.

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
uauthn install
uauthn uninstall
```

`install` registers the service `uauthn` (automatic start, LocalSystem, `listen` with `config`) and the Event Log source `uauthn`; it needs administrator rights. `uninstall` stops and removes both. As LocalSystem, `~` is `C:\Windows\System32\config\systemprofile`, so keep `config` and `passwd` next to the executable. Without `log`, messages go to the Application log.

## Caddy module

The module `http.handlers.uauthn` serves the login page and checks the session inside Caddy, without a separate process or `forward_auth`.

```sh
xcaddy build --with github.com/sakilabo/uauthn-go/caddy
```

```caddyfile
example.com {
	uauthn {
		prefix /uauthn
		passwd /etc/caddy/passwd
	}
	reverse_proxy 127.0.0.1:8080
}
```

| Subdirective | Default | |
| --- | --- | --- |
| `prefix` | `/uauthn` | Path of the login page and its endpoints |
| `passwd` | data directory, resolved from the `caddy` executable | `passwd` file |
| `index` | data directory | Login page; the embedded page is used when absent |
| `domain` | (empty) | Cookie `Domain` and RP ID |
| `expired_sec` | `86400` | |
| `session` | `file` | `file` / `storage`: `uauthn/session.dat` in Caddy's storage. `memory`: kept across config reloads, lost on restart |
| `flush_sec` | `5` | |
| `passkey_prompt` | `always` | `always`, `unregistered`, or `never` |

- Requests under `prefix` are answered by uauthn. Other requests pass with `Remote-User` set (any incoming `Remote-User` is removed) and `{http.auth.user.id}` available, or get the redirecting `401`.
- A request matcher limits the protected requests: `uauthn @protected { ... }`. The directive is ordered before `basic_auth`.
- The session table is shared through a usage pool, so config reloads keep sessions.
- Users are managed with a `caddy` subcommand:

```
caddy uauthn add [--password PASSWORD] [--reset] [--passwd PATH] USERNAME
```

## License

[UPL 1.0](LICENSE)

## Author

[Sakilabo Corporation Ltd.](https://sakilabo.jp)
