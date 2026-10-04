package uauthn

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	ConfigFile  = "config"
	PasswdFile  = "passwd"
	SessionFile = "session.dat"
	IndexFile   = "index.html"
)

const (
	SessionMemory   = "memory"
	SessionFileMode = "file"
)

const (
	PromptAlways       = "always"
	PromptUnregistered = "unregistered"
	PromptNever        = "never"
)

type Config struct {
	Bind          string
	Port          int
	Prefix        string
	Domain        string
	ExpiredSec    int
	Session       string
	FlushSec      int
	Log           string
	LogMaxSize    int64
	PasskeyPrompt string
}

func DefaultConfig() Config {
	return Config{
		Bind:          "0.0.0.0",
		Port:          10997,
		Prefix:        "/uauthn",
		ExpiredSec:    86400,
		Session:       SessionFileMode,
		FlushSec:      5,
		LogMaxSize:    1 << 20,
		PasskeyPrompt: PromptAlways,
	}
}

func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return c, fmt.Errorf("%s:%d: missing '='", path, n)
		}
		if err := c.set(strings.TrimSpace(key), strings.TrimSpace(val)); err != nil {
			return c, fmt.Errorf("%s:%d: %w", path, n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return c, err
	}
	return c, c.Validate()
}

func (c *Config) set(key, val string) error {
	var err error
	switch key {
	case "bind":
		c.Bind = val
	case "port":
		c.Port, err = strconv.Atoi(val)
	case "prefix":
		c.Prefix = val
	case "domain":
		c.Domain = val
	case "expired_sec":
		c.ExpiredSec, err = strconv.Atoi(val)
	case "session":
		c.Session = val
	case "flush_sec":
		c.FlushSec, err = strconv.Atoi(val)
	case "log":
		c.Log = val
	case "log_max_size":
		c.LogMaxSize, err = strconv.ParseInt(val, 10, 64)
	case "passkey_prompt":
		c.PasskeyPrompt = val
	default:
		return fmt.Errorf("unknown key %q", key)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

func (c *Config) Validate() error {
	var err error
	if c.Prefix, err = NormalizePrefix(c.Prefix); err != nil {
		return err
	}
	if c.Session, err = NormalizeSessionMode(c.Session); err != nil {
		return err
	}
	if c.PasskeyPrompt, err = NormalizePasskeyPrompt(c.PasskeyPrompt); err != nil {
		return err
	}
	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("port: out of range: %d", c.Port)
	}
	if c.ExpiredSec <= 0 {
		return fmt.Errorf("expired_sec: must be positive")
	}
	if c.FlushSec <= 0 {
		return fmt.Errorf("flush_sec: must be positive")
	}
	if c.LogMaxSize < 0 {
		return fmt.Errorf("log_max_size: must not be negative")
	}
	return nil
}

func NormalizePrefix(p string) (string, error) {
	p = strings.TrimRight(strings.TrimSpace(p), "/")
	if p == "" {
		return "", fmt.Errorf("prefix: must not be empty or '/'")
	}
	if p[0] != '/' {
		p = "/" + p
	}
	return p, nil
}

func NormalizeSessionMode(m string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "", "file", "storage":
		return SessionFileMode, nil
	case "memory":
		return SessionMemory, nil
	}
	return "", fmt.Errorf("session: unknown mode %q", m)
}

func (c Config) Expire() time.Duration { return time.Duration(c.ExpiredSec) * time.Second }

func (c Config) Flush() time.Duration { return time.Duration(c.FlushSec) * time.Second }

func FindDir() (string, error) {
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, name := range []string{ConfigFile, PasswdFile} {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return dir, nil
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".uauthn"), nil
}

func NormalizePasskeyPrompt(p string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(p)); v {
	case "":
		return PromptAlways, nil
	case PromptAlways, PromptUnregistered, PromptNever:
		return v, nil
	}
	return "", fmt.Errorf("passkey_prompt: unknown value %q", p)
}
