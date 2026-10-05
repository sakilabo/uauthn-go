package uauthn

import (
	"os"
	"path/filepath"
	"time"
)

// Backend stores one file: a local file for the standalone server, a key in Caddy's storage for the module.
type Backend interface {
	Stat() (size int64, mod time.Time, err error)
	Load() ([]byte, error)
	Store([]byte) error
}

type FileBackend struct{ Path string }

func (f FileBackend) String() string { return f.Path }

func (f FileBackend) Stat() (int64, time.Time, error) {
	st, err := os.Stat(f.Path)
	if err != nil {
		return 0, time.Time{}, err
	}
	return st.Size(), st.ModTime(), nil
}

func (f FileBackend) Load() ([]byte, error) { return os.ReadFile(f.Path) }

func (f FileBackend) Store(data []byte) error {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return err
	}
	return writeInPlace(f.Path, data, 0o600)
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
