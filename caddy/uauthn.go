package uauthncaddy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
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

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("uauthn", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("uauthn", httpcaddyfile.Before, "basic_auth")
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "uauthn",
		Usage: uauthn.AddUsage + " [--passwd PATH]",
		Short: "Manages users of the uauthn handler",
		Long:  "Adds a user to the uauthn passwd file or replaces the user's password.\nWithout --password, the password is read from the terminal twice.\n--reset removes every credential of the user, including passkeys.",
		CobraFunc: func(cmd *cobra.Command) {
			cmd.DisableFlagParsing = true
			cmd.RunE = func(_ *cobra.Command, args []string) error { return runCommand(args) }
		},
	})
}

const storageKey = "uauthn/" + uauthn.SessionFile

var sessionPool = caddy.NewUsagePool()

type Handler struct {
	Prefix        string `json:"prefix,omitempty"`
	Domain        string `json:"domain,omitempty"`
	ExpiredSec    int    `json:"expired_sec,omitempty"`
	Session       string `json:"session,omitempty"`
	FlushSec      int    `json:"flush_sec,omitempty"`
	Passwd        string `json:"passwd,omitempty"`
	Index         string `json:"index,omitempty"`
	PasskeyPrompt string `json:"passkey_prompt,omitempty"`

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
	if h.Passwd == "" || h.Index == "" {
		dir, err := uauthn.FindDir()
		if err != nil {
			return err
		}
		if h.Passwd == "" {
			h.Passwd = filepath.Join(dir, uauthn.PasswdFile)
		}
		if h.Index == "" {
			h.Index = filepath.Join(dir, uauthn.IndexFile)
		}
	}

	logf := ctx.Logger().Sugar().Infof
	flush := time.Duration(h.FlushSec) * time.Second
	h.poolKey = h.Session + "/" + strconv.Itoa(h.FlushSec)
	val, _, err := sessionPool.LoadOrNew(h.poolKey, func() (caddy.Destructor, error) {
		var backend uauthn.SessionBackend
		if h.Session == uauthn.SessionFileMode {
			backend = storageBackend{storage: ctx.Storage()}
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
		Index:         h.Index,
		PasskeyPrompt: h.PasskeyPrompt,
		Users:         uauthn.NewUsers(h.Passwd),
		Sessions:      val.(pooledSessions).Sessions,
		Logf:          logf,
	})
	return nil
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
		case "passwd":
			h.Passwd = val
		case "index":
			h.Index = val
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

type storageBackend struct{ storage certmagic.Storage }

func (s storageBackend) Stat() (int64, time.Time, error) {
	info, err := s.storage.Stat(context.Background(), storageKey)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, time.Time{}, fs.ErrNotExist
		}
		return 0, time.Time{}, err
	}
	return info.Size, info.Modified, nil
}

func (s storageBackend) Load() ([]byte, error) {
	return s.storage.Load(context.Background(), storageKey)
}

func (s storageBackend) Store(data []byte) error {
	return s.storage.Store(context.Background(), storageKey, data)
}

func runCommand(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return fmt.Errorf("usage: caddy uauthn %s [--passwd PATH]", uauthn.AddUsage)
	}
	var passwd string
	o, err := uauthn.ParseAddArgs(args[1:], map[string]*string{"passwd": &passwd})
	if err != nil {
		return err
	}
	if passwd == "" {
		dir, err := uauthn.FindDir()
		if err != nil {
			return err
		}
		passwd = filepath.Join(dir, uauthn.PasswdFile)
	}
	o.Passwd = passwd
	return uauthn.RunAdd(o, os.Stdout)
}

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)
