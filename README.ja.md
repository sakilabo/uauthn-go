# uauthn

[English](README.md)

uauthn は、リバースプロキシの後ろにある Web アプリケーションでパスキーを簡単に使うための軽量な実装です。目的は、パスキー認証を簡単に導入できるようにすることです。ユーザーは一度パスワードでサインインすると、そのままパスキーの登録へ案内されます。パスキー（WebAuthn）またはパスワードでサインインさせ、サインインしているユーザーをプロキシに伝えます。`forward_auth` / `auth_request` 用の単体のサーバー、Windows サービス、Caddy のモジュールとして動作します。

- パスキー（ES256・RS256・EdDSA）と argon2id のパスワードを、1つのログインページで扱う
- パスワードでサインインした後、元のページへ戻る前にパスキーの登録を案内する（`passkey_prompt`）
- 単純なファイル：`config`・`passwd`・`session.dat`・`index.html`
- 依存は Go の標準ライブラリと `golang.org/x` のみ。cgo 不要
- ブラウザー専用。HTTPS（または `http://localhost`）が必要

## 単体のサーバー

### 導入

[Releases](https://github.com/sakilabo/uauthn-go/releases) からアーカイブを取得するか、次のコマンドで導入します。

```sh
go install github.com/sakilabo/uauthn-go/cmd/uauthn@latest
```

### コマンド

```
uauthn listen [[ADDR:]PORT]
uauthn add [--password PASSWORD] [--reset] USERNAME
uauthn install | uninstall      (Windows サービス)
uauthn version
```

- `listen`：引数のアドレスは `bind` / `port` より優先します。
- `add`：ユーザーを作成するか、ユーザーのパスワードを置き換えます。`--password` がなければ、端末からパスワードを2回読み取ります。`--reset` は、パスキーを含むユーザーの認証情報をすべて消してから作り直します。ほかの編集コマンドはありません。`passwd` を直接編集するか、リセットします。

### データディレクトリー

実行ファイルのディレクトリーに、通常のファイルの `config` か `passwd` があればそこ、なければ `~/.uauthn` です。

| ファイル | 内容 | 場所 |
| --- | --- | --- |
| `config` | 設定（省略可） | データディレクトリー |
| `passwd` | ユーザーと認証情報 | `passwd_file`。なければデータディレクトリー |
| `index.html` | ログインページ（省略可。なければ組み込みのページ） | `index_file`。なければデータディレクトリー |
| `session.dat` | セッションの時刻（`session = file`） | データディレクトリー |

`passwd_file` か `index_file` を指定した場合、ほかの場所は探しません。既存のファイルはその場で書き換えるため、`passwd` と `session.dat` はシンボリックリンクにできます。

### config

セクションのない INI 形式です。`#` か `;` で始まる行はコメントです。

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
passwd_file =
index_file =
```

| キー | 既定値 | 内容 |
| --- | --- | --- |
| `bind` | `0.0.0.0` | 待ち受けアドレス |
| `port` | `10997` | 待ち受けポート |
| `prefix` | `/uauthn` | ログインページとエンドポイントの公開パス |
| `domain` | （空） | Cookie の `Domain` と WebAuthn の RP ID。空なら host-only cookie、RP ID はリクエストのホスト |
| `expired_sec` | `86400` | 最後の確認からこの秒数でセッションが切れる |
| `session` | `file` | `file`（別名 `storage`）か `memory` |
| `flush_sec` | `5` | `session.dat` を書き込む間隔 |
| `log` | （空） | ログファイル。空なら標準出力、Windows サービスとして動作中はイベントログ |
| `log_max_size` | `1048576` | ログがこのサイズを超えるとき、`*.old` に名前を変える。`0` で制限なし |
| `passkey_prompt` | `always` | 戻り先のあるパスワードでのサインインの後、`always` はパスキーの登録を案内する。`unregistered` はパスキーが未登録のときだけ案内する。`never` はすぐに戻る |
| `passwd_file` | （空） | `passwd` ファイル。相対パスはデータディレクトリーが基準 |
| `index_file` | （空） | ログインページのファイル。相対パスはデータディレクトリーが基準 |

ログファイルは1行ごとに開いて閉じるため、外部のローテーションがいつでも名前の変更や削除をできます。

### ログインページ

パスワードでサインインした後、ページは `/challenge` の `passkeyPrompt` を読み、パスキーの登録（元のページへ戻る「Continue」付き）を表示するか、元のページへ戻ります。パスキーを登録した場合も元のページへ戻ります。パスキーでサインインした場合はすぐに戻ります。既定値が `always` なのは、uauthn の目的がユーザーをパスキーへ移すことだからです。

### passwd

1ユーザー1行です。ユーザー名の後に、認証情報をタブ区切りで任意の数、順不同に並べます。`#` で始まる行はそのまま残します。

```
alice	$argon2id$v=19$m=47104,t=1,p=1$<salt>$<hash>	passkey:<credential ID>:<alg>:<public key>
```

- パスワード：PHC 形式の argon2id。Caddy の `basic_auth` と同じ形式です（`caddy hash-password --algorithm argon2id`）。複数並べた場合、どれかに一致すれば通ります。
- パスキー：`passkey:` ＋ credential ID（base64url）＋ COSE のアルゴリズム（`-7`・`-257`・`-8`）＋ SubjectPublicKeyInfo（base64url）。ログインページから追加します。
- ファイルのサイズか更新日時が変わると読み直します。

### セッション

Cookie `uauthn` は `base64url(ユーザー名).base64url(キー)` で、キーは32バイトの乱数です（`Path=/`・`HttpOnly`・`SameSite=Lax`、HTTPS では `Secure`）。`session.dat` は、`SHA-256(ユーザー名 + キー)` ごとに最後の確認時刻だけを持ちます。確認が通るたびに時刻を進めます。

`session.dat` の構造（リトルエンディアン）：

| オフセット | サイズ | 内容 |
| --- | --- | --- |
| 0 | 6 | `UAUTHN` |
| 6 | 2 | バージョン（`1`） |
| 8 + 40n | 32 | `SHA-256(ユーザー名 + キー)` |
| 40 + 40n | 8 | 最後の確認時刻（Unix 時刻） |

- レコード数は16の倍数です。キーがすべて0、または時刻が0のレコードは空きです。
- 表はメモリーに持ち、`flush_sec` ごとに書き込みます。書き込みの前に、ほかで変更されたファイルを読み込んでマージします（新しい時刻を採用）。サイズが `8 + 40 × 16k` でないファイルは破棄し、メモリーの内容で上書きします。
- `passwd` から削除したユーザーのセッションは、すぐに無効になります。

### エンドポイント

`prefix` の下のパスです。サーバーはプレフィックスの有無のどちらでも受け付けるため、プロキシ側でプレフィックスを取り除いても構いません。

| パス | メソッド | |
| --- | --- | --- |
| `/` | GET | ログインページ |
| `/challenge` | GET | チャレンジ。サインイン中なら登録用の値も返す |
| `/login` | POST | パスワードかパスキーでサインインし、Cookie を発行する |
| `/passkey` | POST | サインイン中のユーザーにパスキーを登録する |
| `/logout` | GET・POST | セッションを終了し、`rd`（ローカルのパス）かログインページへ転送する |
| `/auth` | GET | プロキシ用。`200` と `Remote-User`、または `401` |

`/challenge` は JSON を返します。独自の `index.html` も同じ項目を読めます。チャレンジは1回だけ使え、有効期間は10分です。

| 項目 | 返す条件 | 内容 |
| --- | --- | --- |
| `challenge` | 常に | base64url のチャレンジ。サインイン前はサインイン用、サインイン中は登録用 |
| `rpId` | 常に | WebAuthn の RP ID（`domain`、またはリクエストのホスト） |
| `passkeyPrompt` | 常に | `always`・`unregistered`・`never` |
| `user` | サインイン中 | ユーザー名 |
| `userId` | サインイン中 | base64url の `SHA-256(ユーザー名)`。`create()` の `user.id` 用 |
| `exclude` | サインイン中 | 登録済みの credential ID（base64url）。`excludeCredentials` 用 |

有効なセッションがなければ、`/auth` は `<prefix>/?rd=<元の URI>` へ移る HTML を本文にした `401` を返します。元の URI は `X-Forwarded-Uri`、次に `X-Original-URI` から取ります。WebAuthn の origin に使うスキームとホストは、`X-Forwarded-Proto` / `X-Forwarded-Host` から取ります。

### リバースプロキシ

Caddy：

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

nginx（`auth_request` は 2xx・401・403 以外の状態コードをエラーとして扱うため、転送は `error_page` で行います）：

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

Traefik：`address: http://127.0.0.1:10997/auth`、`authResponseHeaders: [Remote-User]` の `forwardAuth` ミドルウェアと、`PathPrefix(/uauthn)` を uauthn のサービスへ送るルーターを設定します。

## Windows サービス

```
uauthn install
uauthn uninstall
```

`install` は、サービス `uauthn`（自動起動、LocalSystem、`config` に従って `listen`）とイベントログのソース `uauthn` を登録します。管理者権限が必要です。`uninstall` は両方を停止・削除します。LocalSystem では `~` が `C:\Windows\System32\config\systemprofile` になるため、`config` と `passwd` は実行ファイルと同じディレクトリーに置きます。`log` を指定しなければ、アプリケーションログに出力します。

## Caddy モジュール

モジュール `http.handlers.uauthn` は、ログインページとセッションの確認を Caddy の中で処理します。別のプロセスも `forward_auth` も使いません。ファイルは Caddy のストレージの `uauthn/` の下に置くため、ファイルの場所を管理する必要はありません。

```sh
xcaddy build --with github.com/sakilabo/uauthn-go/caddy
```

```caddyfile
example.com {
	uauthn
	reverse_proxy 127.0.0.1:8080
}
```

| Caddy のストレージのキー | 内容 |
| --- | --- |
| `uauthn/passwd` | ユーザーと認証情報（`passwd_file` を指定しない場合） |
| `uauthn/index.html` | ログインページ（`index_file` を指定しない場合）。なければ組み込みのページ |
| `uauthn/session.dat` | セッションの時刻（`session file`） |

| サブディレクティブ | 既定値 | |
| --- | --- | --- |
| `prefix` | `/uauthn` | ログインページとエンドポイントのパス |
| `passwd_file` | （空） | `uauthn/passwd` の代わりにこのファイルを使う |
| `index_file` | （空） | `uauthn/index.html` の代わりにこのファイルを使う |
| `domain` | （空） | Cookie の `Domain` と RP ID |
| `expired_sec` | `86400` | |
| `session` | `file` | `file` / `storage`：Caddy のストレージの `uauthn/session.dat`。`memory`：設定の再読み込みでは残り、再起動で消える |
| `flush_sec` | `5` | |
| `passkey_prompt` | `always` | `always`・`unregistered`・`never` |

- `prefix` の下のリクエストには uauthn が応答します。それ以外は、`Remote-User` を設定し（受け取った `Remote-User` は削除）、`{http.auth.user.id}` を使える状態で次へ渡すか、ログインページへ移す `401` を返します。
- 保護するリクエストはマッチャーで絞れます：`uauthn @protected { ... }`。ディレクティブの順序は `basic_auth` の前です。
- セッションの表は usage pool で共有するため、設定を再読み込みしてもセッションは残ります。
- ユーザーは `caddy` のサブコマンドで管理します：

```
caddy uauthn add [--password PASSWORD] [--reset] [--config FILE [--adapter NAME]] [--passwd_file PATH] USERNAME
```

  指定した設定のストレージ（`caddy storage export` と同じ方法で決める）、`--config` がなければ既定のストレージの `uauthn/passwd` に書き込みます。Caddy のプロセスと同じ環境で実行します。ディレクティブで `passwd_file` を指定している場合は、同じファイルを `--passwd_file` で指定します。

## ライセンス

[UPL 1.0](LICENSE)

## 作者

[株式会社さきラボ](https://sakilabo.jp)
