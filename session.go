package uauthn

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Only the last confirmation time is stored; the user and key live in the cookie (record key = SHA-256(user+key)).
const (
	sessionMagic   = "UAUTHN"
	sessionVersion = 1
	sessionHeader  = 8
	sessionRecord  = 40
	sessionBlock   = 16
)

type sessionID [32]byte

func sessionKey(user string, key []byte) sessionID {
	h := sha256.New()
	h.Write([]byte(user))
	h.Write(key)
	var id sessionID
	h.Sum(id[:0])
	return id
}

func encodeSessions(m map[sessionID]int64) []byte {
	ids := make([]sessionID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	n := (len(ids) + sessionBlock - 1) / sessionBlock * sessionBlock
	if n == 0 {
		n = sessionBlock
	}
	buf := make([]byte, sessionHeader+n*sessionRecord)
	copy(buf, sessionMagic)
	binary.LittleEndian.PutUint16(buf[6:], sessionVersion)
	for i, id := range ids {
		r := buf[sessionHeader+i*sessionRecord:]
		copy(r, id[:])
		binary.LittleEndian.PutUint64(r[32:], uint64(m[id]))
	}
	return buf
}

func decodeSessions(data []byte) (map[sessionID]int64, bool) {
	if len(data) < sessionHeader || string(data[:6]) != sessionMagic ||
		binary.LittleEndian.Uint16(data[6:]) != sessionVersion {
		return nil, false
	}
	body := len(data) - sessionHeader
	if body == 0 || body%sessionRecord != 0 || (body/sessionRecord)%sessionBlock != 0 {
		return nil, false
	}
	m := make(map[sessionID]int64)
	for off := sessionHeader; off < len(data); off += sessionRecord {
		var id sessionID
		copy(id[:], data[off:])
		t := int64(binary.LittleEndian.Uint64(data[off+32:]))
		if t == 0 || id == (sessionID{}) {
			continue
		}
		if t > m[id] {
			m[id] = t
		}
	}
	return m, true
}

type SessionBackend interface {
	Stat() (size int64, mod time.Time, err error)
	Load() ([]byte, error)
	Store([]byte) error
}

type FileBackend struct{ Path string }

func (f FileBackend) Stat() (int64, time.Time, error) {
	st, err := os.Stat(f.Path)
	if err != nil {
		return 0, time.Time{}, err
	}
	return st.Size(), st.ModTime(), nil
}

func (f FileBackend) Load() ([]byte, error) { return os.ReadFile(f.Path) }

func (f FileBackend) Store(data []byte) error { return writeInPlace(f.Path, data, 0o600) }

type Sessions struct {
	backend SessionBackend
	logf    Logf

	mu      sync.Mutex
	m       map[sessionID]int64
	deleted map[sessionID]bool
	dirty   bool
	known   bool
	size    int64
	mod     time.Time
	expire  time.Duration

	stop chan struct{}
	done chan struct{}
}

func NewSessions(backend SessionBackend, flush time.Duration, logf Logf) *Sessions {
	s := &Sessions{
		backend: backend,
		logf:    logf,
		m:       make(map[sessionID]int64),
		deleted: make(map[sessionID]bool),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if backend == nil {
		close(s.done)
		return s
	}
	s.Flush()
	go func() {
		defer close(s.done)
		t := time.NewTicker(flush)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.Flush()
			case <-s.stop:
				return
			}
		}
	}()
	return s
}

func (s *Sessions) Close() {
	select {
	case <-s.stop:
		return
	default:
		close(s.stop)
	}
	<-s.done
	if s.backend != nil {
		s.Flush()
	}
}

func (s *Sessions) Create(user string) (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	id := sessionKey(user, key)
	s.mu.Lock()
	s.m[id] = time.Now().Unix()
	delete(s.deleted, id)
	s.dirty = true
	s.mu.Unlock()
	return b64url.EncodeToString([]byte(user)) + "." + b64url.EncodeToString(key), nil
}

func ParseSessionValue(v string) (string, []byte, bool) {
	u, k, ok := strings.Cut(v, ".")
	if !ok {
		return "", nil, false
	}
	user, err1 := b64url.DecodeString(u)
	key, err2 := b64url.DecodeString(k)
	if err1 != nil || err2 != nil || len(key) != 32 || len(user) == 0 {
		return "", nil, false
	}
	return string(user), key, true
}

func (s *Sessions) Check(user string, key []byte, expire time.Duration) bool {
	id := sessionKey(user, key)
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire = expire
	t, ok := s.m[id]
	if !ok {
		return false
	}
	if now-t > int64(expire/time.Second) {
		delete(s.m, id)
		s.deleted[id] = true
		s.dirty = true
		return false
	}
	if t != now {
		s.m[id] = now
		s.dirty = true
	}
	return true
}

func (s *Sessions) Delete(user string, key []byte) {
	id := sessionKey(user, key)
	s.mu.Lock()
	delete(s.m, id)
	s.deleted[id] = true
	s.dirty = true
	s.mu.Unlock()
}

// A file changed elsewhere is merged (newer time wins); an invalid file is overwritten from memory.
func (s *Sessions) Flush() {
	if s.backend == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var current []byte
	size, mod, err := s.backend.Stat()
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		s.logf("session: stat: %v", err)
		return
	case !s.known || size != s.size || !mod.Equal(s.mod):
		data, err := s.backend.Load()
		if err != nil {
			s.logf("session: load: %v", err)
			return
		}
		current = data
		if m, ok := decodeSessions(data); ok {
			for id, t := range m {
				if !s.deleted[id] && t > s.m[id] {
					s.m[id] = t
				}
			}
		} else {
			s.logf("session: discarding invalid file (%d bytes)", len(data))
		}
	default:
		if !s.dirty {
			return
		}
	}

	if s.expire > 0 {
		limit := time.Now().Unix() - int64(s.expire/time.Second)
		for id, t := range s.m {
			if t < limit {
				delete(s.m, id)
			}
		}
	}
	data := encodeSessions(s.m)
	if current != nil && bytes.Equal(current, data) {
		s.size, s.mod, s.known = size, mod, true
		s.dirty = false
		clear(s.deleted)
		return
	}
	if err := s.backend.Store(data); err != nil {
		s.logf("session: store: %v", err)
		return
	}
	if size, mod, err = s.backend.Stat(); err == nil {
		s.size, s.mod, s.known = size, mod, true
	}
	s.dirty = false
	clear(s.deleted)
}
