# uauthn

[English](README.md)

uauthn は、リバースプロキシの後ろにある Web アプリケーションでパスキーを簡単に使うための軽量な実装です。

uauthn は、`forward_auth` / `auth_request` 用の単体のサーバー、Windows サービス、Caddy のモジュールとして動作します。パスワードとパスキー（WebAuthn）に対応していて、パスワードでサインインしたユーザーにはパスキーの登録を案内するようになっています。

- パスキー（ES256・RS256・EdDSA）と argon2id のパスワードを、1つのログインページで扱う
- パスワードでサインインした後、元のページへ戻る前にパスキーの登録を案内する（`passkey_prompt`）
- 単純なファイル構成：`config`・`passwd`・`session.dat`・`index.html`
- 依存は Go の標準ライブラリと `golang.org/x` のみ。cgo 不要
- ブラウザー専用のシンプルな実装。

## 単体のサーバー

### 導入

[Releases](https://github.com/sakilabo/uauthn-go/releases) からアーカイブを取得するか、次のコマンドで導入します。

```sh
go install github.com/sakilabo/uauthn-go/cmd/uauthn@latest
```

### コマンド

```sh
uauthn listen [--data_dir DIR] [[ADDR:]PORT]
uauthn add [--data_dir DIR] [--password PASSWORD] [--reset] USERNAME
uauthn install [--data_dir DIR] | uninstall      (Windows サービス)
uauthn index --output FILE
uauthn version
```

- `listen`：引数のアドレスは `bind` / `port` より優先します。
- `add`：ユーザーを作成するか、ユーザーのパスワードを置き換えます。`--password` がなければ、端末からパスワードを2回読み取ります。`--reset` は、パスキーを含むユーザーの認証情報をすべて消してから作り直します。ほかの編集コマンドはありません。`passwd` を直接編集するか、リセットします。
- `index`：組み込みのログインページを `--output` のファイルに書き出します（`uauthn index --output index.html`）。

### データディレクトリー

データディレクトリーは `--data_dir` で指定できます。指定がない場合、実行ファイルのディレクトリーに `config` または `passwd` ファイルがあれば、実行ファイルのディレクトリーが選択されます。それ以外の場合は `~/.uauthn` が選択されます。 

| ファイル | 内容 |
| --- | --- |
| `config` | 設定（省略可） |
| `passwd` | ユーザーと認証情報 |
| `index.html` | ログインページ（省略可。なければ組み込みのページ） |
| `session.dat` | セッションの時刻（`session = file`） |

`passwd` と `index.html` は、それぞれ `passwd_file` と `index_file` を指定することで、任意の場所に移動できます。

### config ファイル

セクションのない INI 形式です。`#` か `;` で始まる行はコメントです。

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

| キー | 既定値 | 内容 |
| --- | --- | --- |
| `bind` | `0.0.0.0` | 待ち受けアドレス |
| `port` | `10997` | 待ち受けポート |
| `prefix` | `/uauthn` | ログインページとエンドポイントの公開パス |
| `domain` | （空） | Cookie の `Domain` と WebAuthn の RP ID。空なら host-only cookie、RP ID はリクエストのホスト |
| `expired_sec` | `259200` | セッション ID の有効期限。最後に認証が確認されてからの秒数 |
| `session` | `file` | `file`（別名 `storage`）か `memory` |
| `flush_sec` | `5` | `session.dat` をストレージと同期する間隔（秒） |
| `log_file` | （空） | ログファイル。空なら標準出力、または Windows サービス動作中はイベントログ |
| `log_max_size` | `1048576` | ログファイルがこのサイズを超えるとローテーションする。`0` で制限なし |
| `log_generations` | `3` | 残す古いログの数（`*.1`～`*.N`）。`0` なら残さない |
| `passkey_prompt` | `always` | パスワードでサインインした場合に、パスキーの登録を案内する動作の設定。`always` は常に、`unregistered` はパスキーが未登録のときに案内する。`never` は案内しない。 |
| `title` | `Sign in` | ログインページのタイトルとサインイン画面の見出し |
| `passwd_file` | （空） | `passwd` ファイル。相対パスはデータディレクトリーが基準 |
| `index_file` | （空） | `index.html` ファイル。相対パスはデータディレクトリーが基準 |

### passwd ファイル

1ユーザー1行です。UID とユーザー名の後に、複数の認証情報がタブ区切りで並んでいます。認証情報は、どれか1つでも合致すれば認証成功となります。

```
1a2b3c4d	alice	$argon2id$v=19$m=47104,t=1,p=1$<salt>$<hash>	passkey:<credential ID>:<alg>:<public key>
```

- UID：ユーザーごとにユニークな32ビットの値。`add` コマンドで自動的に生成されます。
- パスワード：PHC 形式の argon2id。Caddy の `basic_auth` と同じ形式です。`add` コマンドが設定します。
- パスキー：`passkey:` ＋ credential ID（base64url）＋ COSE のアルゴリズム（`-7`・`-257`・`-8`）＋ SubjectPublicKeyInfo（base64url）。ログインページから登録します。
- `#` で始まる行はコメントとして無視されます。

### session.dat ファイル

`session.dat` は、セッション ID 毎に「最後に認証が確認された日時」が記録されているバイナリファイルです。

セッション ID は、UID（32ビット）と乱数（224ビット）を合わせた256ビットの値です。この値は、Cookie `uauthn` に base64url で設定されます。（`Path=/`・`HttpOnly`・`SameSite=Lax`、HTTPS では `Secure`）。

ヘッダー：

| オフセット | サイズ | 内容 |
| --- | --- | --- |
| 0 | 6 | `UAUTHN` |
| 6 | 2 | バージョン（`2`、ビッグエンディアン） |

レコード（オフセット `8 + 40n` から40バイト）：

| レコード内のオフセット | サイズ | 内容 |
| --- | --- | --- |
| 0 | 32 | セッション ID（先頭4バイトは UID、ビッグエンディアン） |
| 32 | 8 | 最後に認証が確認された日時（Unix 時刻、ビッグエンディアン） |

- レコード数は16の倍数です。セッション ID がすべて0、または時刻が0のレコードは空きです。
- 表はメモリーに持ち、`flush_sec` ごとにストレージと同期します。ファイルの内容やサイズに問題があった場合には、メモリーの内容でファイルを上書きします。
- `passwd` から削除したユーザーのセッション情報は、すぐに無効になります。

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
| `title` | 常に | `title` の値 |
| `user` | サインイン中 | ユーザー名 |
| `userId` | サインイン中 | base64url の UID（4バイト）。`create()` の `user.id` 用 |
| `exclude` | サインイン中 | 登録済みの credential ID（base64url）。`excludeCredentials` 用 |

有効なセッションがなければ、`/auth` は `<prefix>/?rd=<元の URI>` へ移る HTML を本文にした `401` を返します。元の URI は `X-Forwarded-Uri`、次に `X-Original-URI` から取得します。WebAuthn の origin に使うスキームとホストは、`X-Forwarded-Proto` / `X-Forwarded-Host` から取得します。

### ログインページ

パスキーでサインインした場合は、サインイン元のページに戻ります。

パスワードでサインインした場合、標準の `index` ページは `/challenge` の `passkeyPrompt`（config の `passkey_prompt`）を読み、設定に従ってパスキーの登録ページを表示するか、サインイン元のページへ戻ります。

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
uauthn install [--data_dir DIR]
uauthn uninstall
```

`install` は、サービス `uauthn`（自動起動、LocalSystem、`config` に従って `listen`）とイベントログのソース `uauthn` を登録します。`--data_dir` を指定すると、サービスはそのディレクトリーを使います。管理者権限が必要です。`uninstall` は両方を停止・削除します。LocalSystem では `~` が `C:\Windows\System32\config\systemprofile` になるため、`config` と `passwd` は実行ファイルと同じディレクトリーに置くか、`--data_dir` で指定することが推奨されます。`log_file` を指定しなければ、アプリケーションログに出力されます。

## Caddy モジュール

モジュール `http.handlers.uauthn` は、ログインページとセッションの確認を Caddy の中で処理します。別のプロセスも `forward_auth` も使いません。ファイルは Caddy のストレージの `uauthn/` の下に置くため、ファイルの場所を管理する必要もありません。

```sh
xcaddy build --with github.com/sakilabo/uauthn-go/caddy
```

```caddyfile
example.com {
	uauthn
	reverse_proxy 127.0.0.1:8080
}
```

サブディレクティブで値を指定する例：

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

| Caddy のストレージのキー | 内容 |
| --- | --- |
| `uauthn/passwd` | ユーザーと認証情報（`passwd_file` を指定しない場合） |
| `uauthn/index.html` | ログインページ（`index_file` を指定しない場合）。なければ組み込みのページ |
| `uauthn/session.dat` | セッションの時刻（`session file`） |

| サブディレクティブ | 既定値 | |
| --- | --- | --- |
| `prefix` | `/uauthn` | ログインページとエンドポイントのパス |
| `passwd_file` | （空） | 指定がなければ Caddy ストレージの `uauthn/passwd` が選択される |
| `index_file` | （空） | 指定がなければ Caddy ストレージの `uauthn/index.html` が選択される |
| `domain` | （空） | Cookie の `Domain` と RP ID |
| `expired_sec` | `259200` | セッション ID の有効期限。最後に認証が確認されてからの秒数 |
| `session` | `file` | `file` / `storage`：Caddy のストレージの `uauthn/session.dat`。`memory`：設定の再読み込みでは残り、再起動で消える |
| `flush_sec` | `5` | `uauthn/session.dat` を Caddy のストレージと同期する間隔（秒） |
| `passkey_prompt` | `always` | `always`・`unregistered`・`never` |
| `title` | `"Sign in"` | ログインページのタイトルとサインイン画面の見出し。空白を含む場合は引用符で囲む |

- `prefix` の下のリクエストには uauthn が応答します。それ以外は、`Remote-User` を設定し（受け取った `Remote-User` は削除）、`{http.auth.user.id}` を使える状態で次へ渡すか、ログインページへ移す `401` を返します。
- 保護するリクエストはマッチャーで絞れます：`uauthn @protected { ... }`。ディレクティブの順序は `basic_auth` の前です。
- ユーザーは `caddy` のサブコマンドで管理します。サブコマンドは Caddy の設定を読まないため、`passwd` のファイルを `--passwd_file` で指定してください。`--passwd_file` が省略された場合は Caddy の既定のストレージが選択されます。

```sh
caddy uauthn add [--passwd_file PATH] [--password PASSWORD] [--reset] USERNAME
```

- `caddy uauthn index --output FILE` は、組み込みのログインページをファイルに書き出します。

## ライセンス

[UPL 1.0](LICENSE)

## 作者

[株式会社さきラボ](https://sakilabo.jp)
