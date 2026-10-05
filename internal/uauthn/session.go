package uauthn

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io/fs"
	"sort"
	"sync"
	"time"
)

const (
	sessionMagic   = "UAUTHN"
	sessionVersion = 2
	sessionHeader  = 8
	sessionRecord  = 40
	sessionBlock   = 16
)

// A session ID is the user's UID (4 bytes) followed by 28 random bytes, so the ID alone identifies the user.
type sessionID [32]byte

func (id sessionID) uid() uint32 { return binary.BigEndian.Uint32(id[:4]) }

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
	binary.BigEndian.PutUint16(buf[6:], sessionVersion)
	for i, id := range ids {
		r := buf[sessionHeader+i*sessionRecord:]
		copy(r, id[:])
		binary.BigEndian.PutUint64(r[32:], uint64(m[id]))
	}
	return buf
}

func decodeSessions(data []byte) (map[sessionID]int64, bool) {
	if len(data) < sessionHeader || string(data[:6]) != sessionMagic ||
		binary.BigEndian.Uint16(data[6:]) != sessionVersion {
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
		t := int64(binary.BigEndian.Uint64(data[off+32:]))
		if t == 0 || id == (sessionID{}) {
			continue
		}
		if t > m[id] {
			m[id] = t
		}
	}
	return m, true
}

type Sessions struct {
	backend Backend
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

func NewSessions(backend Backend, flush time.Duration, logf Logf) *Sessions {
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

func (s *Sessions) Create(uid uint32) (string, error) {
	var id sessionID
	binary.BigEndian.PutUint32(id[:4], uid)
	if _, err := rand.Read(id[4:]); err != nil {
		return "", err
	}
	s.mu.Lock()
	s.m[id] = time.Now().Unix()
	delete(s.deleted, id)
	s.dirty = true
	s.mu.Unlock()
	return b64url.EncodeToString(id[:]), nil
}

func parseSessionValue(v string) (sessionID, bool) {
	var id sessionID
	b, err := b64url.DecodeString(v)
	if err != nil || len(b) != len(id) {
		return id, false
	}
	copy(id[:], b)
	return id, true
}

func (s *Sessions) Check(id sessionID, expire time.Duration) bool {
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

func (s *Sessions) Delete(id sessionID) {
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
