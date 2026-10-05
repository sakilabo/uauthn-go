package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sakilabo/uauthn-go/internal/uauthn"
)

var version = "dev"

const usage = `uauthn - lightweight passkey and password authentication for reverse proxies

Usage:
  uauthn listen [--data_dir DIR] [[ADDR:]PORT]
  uauthn add [--data_dir DIR] ` + uauthn.AddUsage + `
  uauthn install [--data_dir DIR]   (Windows) register the Windows service
  uauthn uninstall                  (Windows) remove the Windows service
  uauthn index ` + uauthn.IndexUsage + `      write the built-in login page to FILE or standard output
  uauthn version

Data directory: --data_dir; otherwise the executable's directory when it holds config or passwd, otherwise ~/.uauthn
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
	cmd := args[0]
	dir, rest, err := parseDataDir(args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "uauthn:", err)
		return 2
	}
	if dir != "" && cmd != "listen" && cmd != "add" && cmd != "install" {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch cmd {
	case "listen":
		if len(rest) > 1 {
			fmt.Fprint(os.Stderr, usage)
			return 2
		}
		addr := ""
		if len(rest) == 1 {
			addr = rest[0]
		}
		ctx, stop := signalContext()
		defer stop()
		err = listen(ctx, addr, dir, nil)
	case "add":
		err = add(rest, dir)
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usage)
			return 2
		}
	case "install":
		if len(rest) > 0 {
			fmt.Fprint(os.Stderr, usage)
			return 2
		}
		err = installService(dir)
	case "uninstall":
		err = uninstallService()
	case "index":
		err = uauthn.RunIndex(rest, os.Stdout)
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

// The path is made absolute because install hands it to a service that runs in another working directory.
func parseDataDir(args []string) (string, []string, error) {
	var dir string
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(args[i], "=")
		if name != "--data_dir" && name != "-data_dir" {
			rest = append(rest, args[i])
			continue
		}
		if !hasVal {
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("%s needs a value", name)
			}
			i++
			val = args[i]
		}
		if val == "" {
			return "", nil, fmt.Errorf("%s must not be empty", name)
		}
		abs, err := filepath.Abs(val)
		if err != nil {
			return "", nil, err
		}
		dir = abs
	}
	return dir, rest, nil
}

func add(args []string, dataDir string) error {
	o, err := uauthn.ParseAddArgs(args, nil)
	if err != nil {
		if len(args) == 0 {
			return errUsage
		}
		return err
	}
	cfg, err := loadConfig(dataDir)
	if err != nil {
		return err
	}
	return uauthn.RunAdd(o, uauthn.FileBackend{Path: cfg.PasswdFile}, os.Stdout)
}

func loadConfig(dataDir string) (uauthn.Config, error) {
	if dataDir != "" {
		return uauthn.LoadConfig(dataDir)
	}
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

func listen(ctx context.Context, addrArg, dataDir string, logf uauthn.Logf) error {
	cfg, err := loadConfig(dataDir)
	if err != nil {
		return err
	}
	addr, err := listenAddr(cfg, addrArg)
	if err != nil {
		return err
	}
	if logf == nil || cfg.LogFile != "" {
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
