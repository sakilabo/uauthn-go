package uauthncaddy

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/certmagic"
	"github.com/spf13/cobra"

	"github.com/sakilabo/uauthn-go"
)

const commandUsage = uauthn.AddUsage + " [--passwd_file PATH]"

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("uauthn", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("uauthn", httpcaddyfile.Before, "basic_auth")
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "uauthn",
		Usage: commandUsage,
		Short: "Manages users of the uauthn handler",
		Long: "Adds a user to uauthn's passwd or replaces the user's password.\n" +
			"The passwd is the file given by --passwd_file, or \"uauthn/passwd\" in the default storage.\n" +
			"Without --password, the password is read from the terminal twice.\n" +
			"--reset removes every credential of the user, including passkeys.",
		CobraFunc: func(cmd *cobra.Command) {
			cmd.DisableFlagParsing = true
			cmd.RunE = func(_ *cobra.Command, args []string) error { return runCommand(args) }
		},
	})
}

const storagePrefix = "uauthn/"

var sessionPool = caddy.NewUsagePool()

type Handler struct {
	Prefix        string `json:"prefix,omitempty"`
	Domain        string `json:"domain,omitempty"`
	ExpiredSec    int    `json:"expired_sec,omitempty"`
	Session       string `json:"session,omitempty"`
	FlushSec      int    `json:"flush_sec,omitempty"`
	PasswdFile    string `json:"passwd_file,omitempty"`
	IndexFile     string `json:"index_file,omitempty"`
	PasskeyPrompt string `json:"passkey_prompt,omitempty"`
	Title         string `json:"title,omitempty"`

	server  *uauthn.Server
	poolKey string
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.uauthn",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(ctx caddy.Context) error {
	def := uauthn.DefaultConfig()
	var err error
	if h.Prefix == "" {
		h.Prefix = def.Prefix
	}
	if h.Prefix, err = uauthn.NormalizePrefix(h.Prefix); err != nil {
		return err
	}
	if h.Session, err = uauthn.NormalizeSessionMode(h.Session); err != nil {
		return err
	}
	if h.PasskeyPrompt, err = uauthn.NormalizePasskeyPrompt(h.PasskeyPrompt); err != nil {
		return err
	}
	if h.ExpiredSec <= 0 {
		h.ExpiredSec = def.ExpiredSec
	}
	if h.FlushSec <= 0 {
		h.FlushSec = def.FlushSec
	}

	storage := ctx.Storage()
	logf := ctx.Logger().Sugar().Infof
	flush := time.Duration(h.FlushSec) * time.Second
	h.poolKey = h.Session + "/" + strconv.Itoa(h.FlushSec)
	val, _, err := sessionPool.LoadOrNew(h.poolKey, func() (caddy.Destructor, error) {
		var backend uauthn.Backend
		if h.Session == uauthn.SessionFileMode {
			backend = newStorageBackend(storage, uauthn.SessionName)
		}
		return pooledSessions{uauthn.NewSessions(backend, flush, logf)}, nil
	})
	if err != nil {
		return err
	}
	h.server = uauthn.NewServer(uauthn.Options{
		Prefix:        h.Prefix,
		Domain:        h.Domain,
		Expire:        time.Duration(h.ExpiredSec) * time.Second,
		Index:         fileOrStorage(h.IndexFile, storage, uauthn.IndexName),
		PasskeyPrompt: h.PasskeyPrompt,
		Title:         h.Title,
		Users:         uauthn.NewUsers(fileOrStorage(h.PasswdFile, storage, uauthn.PasswdName)),
		Sessions:      val.(pooledSessions).Sessions,
		Logf:          logf,
	})
	return nil
}

func fileOrStorage(path string, storage certmagic.Storage, name string) uauthn.Backend {
	if path != "" {
		return uauthn.FileBackend{Path: path}
	}
	return newStorageBackend(storage, name)
}

func (h *Handler) Cleanup() error {
	if h.poolKey == "" {
		return nil
	}
	_, err := sessionPool.Delete(h.poolKey)
	return err
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	r.Header.Del(uauthn.UserHeader)
	if rest, ok := h.server.StripPrefix(r.URL.Path); ok {
		h.server.Handle(w, r, rest)
		return nil
	}
	user, ok := h.server.Authenticate(r)
	if !ok {
		h.server.Unauthorized(w, r, r.URL.RequestURI())
		return nil
	}
	r.Header.Set(uauthn.UserHeader, user)
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set("http.auth.user.id", user)
	}
	return next.ServeHTTP(w, r)
}

func parseCaddyfile(hf httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h := new(Handler)
	err := h.UnmarshalCaddyfile(hf.Dispenser)
	return h, err
}

func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if d.NextArg() {
		return d.ArgErr()
	}
	for d.NextBlock(0) {
		key := d.Val()
		var val string
		if !d.Args(&val) {
			return d.ArgErr()
		}
		var err error
		switch key {
		case "prefix":
			h.Prefix = val
		case "domain":
			h.Domain = val
		case "expired_sec":
			h.ExpiredSec, err = strconv.Atoi(val)
		case "session":
			h.Session = val
		case "flush_sec":
			h.FlushSec, err = strconv.Atoi(val)
		case "title":
			h.Title = val
		case "passwd_file":
			h.PasswdFile = val
		case "index_file":
			h.IndexFile = val
		case "passkey_prompt":
			h.PasskeyPrompt = val
		default:
			return d.Errf("unknown subdirective %q", key)
		}
		if err != nil {
			return d.Errf("%s: %v", key, err)
		}
	}
	return nil
}

type pooledSessions struct{ *uauthn.Sessions }

func (p pooledSessions) Destruct() error {
	p.Close()
	return nil
}

type storageBackend struct {
	storage certmagic.Storage
	key     string
}

func newStorageBackend(storage certmagic.Storage, name string) storageBackend {
	return storageBackend{storage: storage, key: storagePrefix + name}
}

func (s storageBackend) String() string { return "storage:" + s.key }

func (s storageBackend) Stat() (int64, time.Time, error) {
	info, err := s.storage.Stat(context.Background(), s.key)
	if err != nil {
		return 0, time.Time{}, err
	}
	return info.Size, info.Modified, nil
}

func (s storageBackend) Load() ([]byte, error) {
	return s.storage.Load(context.Background(), s.key)
}

func (s storageBackend) Store(data []byte) error {
	return s.storage.Store(context.Background(), s.key, data)
}

func runCommand(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return fmt.Errorf("usage: caddy uauthn %s", commandUsage)
	}
	var passwdFile string
	o, err := uauthn.ParseAddArgs(args[1:], map[string]*string{"passwd_file": &passwdFile})
	if err != nil {
		return err
	}
	if passwdFile != "" {
		return uauthn.RunAdd(o, uauthn.FileBackend{Path: passwdFile}, os.Stdout)
	}
	return uauthn.RunAdd(o, newStorageBackend(caddy.DefaultStorage, uauthn.PasswdName), os.Stdout)
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
