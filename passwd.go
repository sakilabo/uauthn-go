package uauthn

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var b64url = base64.RawURLEncoding

type Passkey struct {
	ID  []byte
	Alg int
	Key []byte // SubjectPublicKeyInfo (DER)
}

func (p Passkey) String() string {
	return "passkey:" + b64url.EncodeToString(p.ID) + ":" + strconv.Itoa(p.Alg) + ":" + b64url.EncodeToString(p.Key)
}

func parsePasskey(s string) (Passkey, bool) {
	rest, ok := strings.CutPrefix(s, "passkey:")
	if !ok {
		return Passkey{}, false
	}
	f := strings.Split(rest, ":")
	if len(f) != 3 {
		return Passkey{}, false
	}
	id, err1 := b64url.DecodeString(f[0])
	alg, err2 := strconv.Atoi(f[1])
	key, err3 := b64url.DecodeString(f[2])
	if err1 != nil || err2 != nil || err3 != nil || len(id) == 0 {
		return Passkey{}, false
	}
	return Passkey{ID: id, Alg: alg, Key: key}, true
}

// One user per line: the name, then any number of tab-separated credentials in no particular order.
type passwdLine struct {
	raw    string
	name   string
	fields []string
}

func parsePasswd(data []byte) []passwdLine {
	var lines []passwdLine
	for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		l := passwdLine{raw: raw}
		if t := strings.TrimSpace(raw); t != "" && t[0] != '#' {
			f := strings.Split(raw, "\t")
			l.name = f[0]
			for _, v := range f[1:] {
				if v != "" {
					l.fields = append(l.fields, v)
				}
			}
		}
		lines = append(lines, l)
	}
	if n := len(lines); n > 0 && lines[n-1].raw == "" && lines[n-1].name == "" {
		lines = lines[:n-1]
	}
	return lines
}

func formatPasswd(lines []passwdLine) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		if l.name == "" {
			b.WriteString(l.raw)
		} else {
			b.WriteString(strings.Join(append([]string{l.name}, l.fields...), "\t"))
		}
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func ValidUserName(name string) error {
	if name == "" || strings.TrimSpace(name) != name || name[0] == '#' || strings.ContainsAny(name, "\t\r\n") {
		return fmt.Errorf("invalid user name %q", name)
	}
	return nil
}

type Users struct {
	path  string
	mu    sync.Mutex
	size  int64
	mod   time.Time
	lines []passwdLine
}

func NewUsers(path string) *Users { return &Users{path: path, size: -1} }

func (u *Users) Path() string { return u.path }

func (u *Users) load() error {
	st, err := os.Stat(u.path)
	if errors.Is(err, fs.ErrNotExist) {
		u.lines, u.size, u.mod = nil, -1, time.Time{}
		return nil
	}
	if err != nil {
		return err
	}
	if st.Size() == u.size && st.ModTime().Equal(u.mod) {
		return nil
	}
	data, err := os.ReadFile(u.path)
	if err != nil {
		return err
	}
	u.lines, u.size, u.mod = parsePasswd(data), st.Size(), st.ModTime()
	return nil
}

func (u *Users) find(name string) *passwdLine {
	for i := range u.lines {
		if u.lines[i].name == name {
			return &u.lines[i]
		}
	}
	return nil
}

func (u *Users) Exists(name string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.load() != nil {
		return false
	}
	return u.find(name) != nil
}

func (u *Users) VerifyPassword(name, password string) bool {
	u.mu.Lock()
	var hashes []string
	if u.load() == nil {
		if l := u.find(name); l != nil {
			for _, f := range l.fields {
				if isPasswordHash(f) {
					hashes = append(hashes, f)
				}
			}
		}
	}
	u.mu.Unlock()
	for _, h := range hashes {
		if VerifyPassword(h, password) {
			return true
		}
	}
	return false
}

func (u *Users) Passkeys(name string) []Passkey {
	u.mu.Lock()
	defer u.mu.Unlock()
	var keys []Passkey
	if u.load() != nil {
		return nil
	}
	if l := u.find(name); l != nil {
		for _, f := range l.fields {
			if pk, ok := parsePasskey(f); ok {
				keys = append(keys, pk)
			}
		}
	}
	return keys
}

func (u *Users) FindPasskey(id []byte) (string, Passkey, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.load() != nil {
		return "", Passkey{}, false
	}
	for _, l := range u.lines {
		for _, f := range l.fields {
			if pk, ok := parsePasskey(f); ok && bytes.Equal(pk.ID, id) {
				return l.name, pk, true
			}
		}
	}
	return "", Passkey{}, false
}

func (u *Users) AddPasskey(name string, pk Passkey) error {
	return u.update(func(lines []passwdLine) ([]passwdLine, error) {
		for i := range lines {
			if lines[i].name == name {
				lines[i].fields = append(lines[i].fields, pk.String())
				return lines, nil
			}
		}
		return nil, fmt.Errorf("unknown user %q", name)
	})
}

func (u *Users) SetPassword(name, hash string, reset bool) (created bool, err error) {
	err = u.update(func(lines []passwdLine) ([]passwdLine, error) {
		for i := range lines {
			if lines[i].name != name {
				continue
			}
			var keep []string
			if !reset {
				for _, f := range lines[i].fields {
					if !isPasswordHash(f) {
						keep = append(keep, f)
					}
				}
			}
			lines[i].fields = append([]string{hash}, keep...)
			return lines, nil
		}
		created = true
		return append(lines, passwdLine{name: name, fields: []string{hash}}), nil
	})
	return created, err
}

func (u *Users) update(fn func([]passwdLine) ([]passwdLine, error)) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	data, err := os.ReadFile(u.path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	lines, err := fn(parsePasswd(data))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(u.path), 0o700); err != nil {
		return err
	}
	if err := writeInPlace(u.path, formatPasswd(lines), 0o600); err != nil {
		return err
	}
	u.size = -1
	return u.load()
}

// writeInPlace rewrites the existing file instead of replacing it, so a symbolic link keeps pointing to its target.
func writeInPlace(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, perm)
	if err != nil {
		return err
	}
	if _, err = f.WriteAt(data, 0); err == nil {
		err = f.Truncate(int64(len(data)))
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
