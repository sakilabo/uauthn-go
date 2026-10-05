package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/sakilabo/uauthn-go/internal/uauthn"
)

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func newLogger(cfg uauthn.Config) uauthn.Logf {
	if cfg.LogFile == "" {
		return log.New(os.Stdout, "", log.LstdFlags).Printf
	}
	path := cfg.LogFile
	if !filepath.IsAbs(path) {
		path = filepath.Join(cfg.Dir, path)
	}
	fl := &fileLogger{path: path, max: cfg.LogMaxSize, gens: cfg.LogGenerations}
	return fl.printf
}

// The file is opened and closed for every line so that external rotation can rename or delete it at any time.
type fileLogger struct {
	mu   sync.Mutex
	path string
	max  int64
	gens int
}

func (l *fileLogger) printf(format string, args ...any) {
	line := time.Now().Format("2006/01/02 15:04:05 ") + fmt.Sprintf(format, args...) + "\n"
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max > 0 {
		if st, err := os.Stat(l.path); err == nil && st.Size()+int64(len(line)) > l.max {
			l.rotate()
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

func (l *fileLogger) rotate() {
	if l.gens == 0 {
		os.Remove(l.path)
		return
	}
	os.Remove(l.path + "." + strconv.Itoa(l.gens))
	for i := l.gens - 1; i >= 1; i-- {
		os.Rename(l.path+"."+strconv.Itoa(i), l.path+"."+strconv.Itoa(i+1))
	}
	os.Rename(l.path, l.path+".1")
}
