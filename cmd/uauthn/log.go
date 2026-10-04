package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/sakilabo/uauthn-go"
)

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func newLogger(cfg uauthn.Config) uauthn.Logf {
	if cfg.Log == "" {
		return log.New(os.Stdout, "", log.LstdFlags).Printf
	}
	path := cfg.Log
	if !filepath.IsAbs(path) {
		path = filepath.Join(cfg.Dir, path)
	}
	fl := &fileLogger{path: path, max: cfg.LogMaxSize}
	return fl.printf
}

// The file is opened and closed for every line so that external rotation can rename or delete it at any time.
type fileLogger struct {
	mu   sync.Mutex
	path string
	max  int64
}

func (l *fileLogger) printf(format string, args ...any) {
	line := time.Now().Format("2006/01/02 15:04:05 ") + fmt.Sprintf(format, args...) + "\n"
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max > 0 {
		if st, err := os.Stat(l.path); err == nil && st.Size()+int64(len(line)) > l.max {
			os.Remove(l.path + ".old")
			os.Rename(l.path, l.path+".old")
		}
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprint(os.Stderr, line)
		return
	}
	f.WriteString(line)
	f.Close()
}
