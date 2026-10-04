package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sakilabo/uauthn-go"
)

var version = "dev"

const usage = `uauthn - lightweight passkey and password authentication for reverse proxies

Usage:
  uauthn listen [[ADDR:]PORT]
  uauthn ` + uauthn.AddUsage + `
  uauthn install      (Windows) register the Windows service
  uauthn uninstall    (Windows) remove the Windows service
  uauthn version

Data directory: the executable's directory when it holds config or passwd, otherwise ~/.uauthn
`

func main() {
	if isWindowsService() {
		if err := runService(); err != nil {
			os.Exit(1)
		}
		return
	}
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "listen":
		if len(args) > 2 {
			fmt.Fprint(os.Stderr, usage)
			return 2
		}
		addr := ""
		if len(args) == 2 {
			addr = args[1]
		}
		ctx, stop := signalContext()
		defer stop()
		err = listen(ctx, addr, nil)
	case "add":
		err = add(args[1:])
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usage)
			return 2
		}
	case "install":
		err = installService()
	case "uninstall":
		err = uninstallService()
	case "version", "--version", "-v":
		fmt.Println("uauthn", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "uauthn:", err)
		return 1
	}
	return 0
}

var errUsage = errors.New("usage")

func add(args []string) error {
	o, err := uauthn.ParseAddArgs(args, nil)
	if err != nil {
		if len(args) == 0 {
			return errUsage
		}
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	return uauthn.RunAdd(o, uauthn.FileBackend{Path: cfg.PasswdFile}, os.Stdout)
}

func loadConfig() (uauthn.Config, error) {
	dir, err := uauthn.FindDir()
	if err != nil {
		return uauthn.Config{}, err
	}
	return uauthn.LoadConfig(dir)
}

func listenAddr(cfg uauthn.Config, arg string) (string, error) {
	if arg == "" {
		return net.JoinHostPort(cfg.Bind, strconv.Itoa(cfg.Port)), nil
	}
	if _, err := strconv.Atoi(arg); err == nil {
		return net.JoinHostPort(cfg.Bind, arg), nil
	}
	if _, _, err := net.SplitHostPort(arg); err != nil {
		return "", fmt.Errorf("invalid address %q", arg)
	}
	return arg, nil
}

func listen(ctx context.Context, addrArg string, logf uauthn.Logf) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	addr, err := listenAddr(cfg, addrArg)
	if err != nil {
		return err
	}
	if logf == nil || cfg.Log != "" {
		logf = newLogger(cfg)
	}

	var backend uauthn.Backend
	if cfg.Session == uauthn.SessionFileMode {
		backend = uauthn.FileBackend{Path: cfg.SessionFile()}
	}
	sessions := uauthn.NewSessions(backend, cfg.Flush(), logf)
	defer sessions.Close()

	srv := uauthn.NewServer(uauthn.Options{
		Prefix:         cfg.Prefix,
		Domain:         cfg.Domain,
		Expire:         cfg.Expire(),
		Index:          uauthn.FileBackend{Path: cfg.IndexFile},
		PasskeyPrompt:  cfg.PasskeyPrompt,
		Title:          cfg.Title,
		Users:          uauthn.NewUsers(uauthn.FileBackend{Path: cfg.PasswdFile}),
		Sessions:       sessions,
		Logf:           logf,
		TrustForwarded: true,
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: handler(srv), ReadHeaderTimeout: 10 * time.Second}
	logf("uauthn %s listening on %s (data: %s)", version, ln.Addr(), cfg.Dir)
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err = <-errc:
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err = hs.Shutdown(sctx)
	}
	logf("uauthn stopped")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func handler(srv *uauthn.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if rest, ok := srv.StripPrefix(p); ok {
			p = rest
		}
		if p == "/auth" {
			if user, ok := srv.Authenticate(r); ok {
				w.Header().Set(uauthn.UserHeader, user)
				w.WriteHeader(http.StatusOK)
				return
			}
			srv.Unauthorized(w, r, originalURI(r))
			return
		}
		srv.Handle(w, r, p)
	})
}

func originalURI(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-Uri", "X-Original-URI"} {
		if v := r.Header.Get(h); strings.HasPrefix(v, "/") {
			return v
		}
	}
	return "/"
}
