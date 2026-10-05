package uauthn

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
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

// One user per line: the UID (8 hex digits), the name, then any number of tab-separated credentials in no particular order.
type passwdLine struct {
	raw    string
	uid    uint32
	name   string
	fields []string
}

func parseUID(s string) (uint32, bool) {
	if len(s) != 8 {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 32)
	return uint32(v), err == nil
}

func parsePasswd(data []byte) ([]passwdLine, error) {
	var lines []passwdLine
	uids := make(map[uint32]bool)
	for n, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		l := passwdLine{raw: raw}
		if t := strings.TrimSpace(raw); t != "" && t[0] != '#' {
			f := strings.Split(raw, "\t")
			uid, ok := parseUID(f[0])
			if !ok || len(f) < 2 {
				return nil, fmt.Errorf("passwd:%d: missing UID", n+1)
			}
			if err := ValidUserName(f[1]); err != nil {
				return nil, fmt.Errorf("passwd:%d: %w", n+1, err)
			}
			if uids[uid] {
				return nil, fmt.Errorf("passwd:%d: duplicate UID %08x", n+1, uid)
			}
			uids[uid] = true
			l.uid, l.name = uid, f[1]
			for _, v := range f[2:] {
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
	return lines, nil
}

func formatPasswd(lines []passwdLine) []byte {
	var b bytes.Buffer
	for _, l := range lines {
		if l.name == "" {
			b.WriteString(l.raw)
		} else {
			b.WriteString(strings.Join(append([]string{fmt.Sprintf("%08x", l.uid), l.name}, l.fields...), "\t"))
		}
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func newUID(lines []passwdLine) (uint32, error) {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		uid := binary.BigEndian.Uint32(b[:])
		taken := false
		for _, l := range lines {
			if l.name != "" && l.uid == uid {
				taken = true
				break
			}
		}
		if !taken {
			return uid, nil
		}
	}
}

func ValidUserName(name string) error {
	if name == "" || strings.TrimSpace(name) != name || name[0] == '#' || strings.ContainsAny(name, "\t\r\n") {
		return fmt.Errorf("invalid user name %q", name)
	}
	return nil
}

type Users struct {
	store Backend
	mu    sync.Mutex
	size  int64
	mod   time.Time
	lines []passwdLine
}

func NewUsers(store Backend) *Users { return &Users{store: store, size: -1} }

func (u *Users) load() error {
	size, mod, err := u.store.Stat()
	if errors.Is(err, fs.ErrNotExist) {
		u.lines, u.size, u.mod = nil, -1, time.Time{}
		return nil
	}
	if err != nil {
		return err
	}
	if size == u.size && mod.Equal(u.mod) {
		return nil
	}
	data, err := u.store.Load()
	if err != nil {
		return err
	}
	lines, err := parsePasswd(data)
	if err != nil {
		return err
	}
	u.lines, u.size, u.mod = lines, size, mod
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

func (u *Users) UID(name string) (uint32, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.load() != nil {
		return 0, false
	}
	if l := u.find(name); l != nil {
		return l.uid, true
	}
	return 0, false
}

func (u *Users) Name(uid uint32) (string, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.load() != nil {
		return "", false
	}
	for _, l := range u.lines {
		if l.name != "" && l.uid == uid {
			return l.name, true
		}
	}
	return "", false
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
		uid, err := newUID(lines)
		if err != nil {
			return nil, err
		}
		created = true
		return append(lines, passwdLine{uid: uid, name: name, fields: []string{hash}}), nil
	})
	return created, err
}

func (u *Users) update(fn func([]passwdLine) ([]passwdLine, error)) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	data, err := u.store.Load()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	lines, err := parsePasswd(data)
	if err != nil {
		return err
	}
	if lines, err = fn(lines); err != nil {
		return err
	}
	if err := u.store.Store(formatPasswd(lines)); err != nil {
		return err
	}
	u.size = -1
	return u.load()
}
