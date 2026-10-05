package coreactivation

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"mikrocentauri.local/core/internal/coreconfig"
)

func encodeModel(m coreconfig.Model) ([]byte, error) {
	b, e := json.Marshal(m)
	if e != nil || len(b) > 4<<20 {
		return nil, errors.New("model exceeds registry bounds")
	}
	return b, nil
}
func checkPath(path string) error {
	for {
		st, err := os.Lstat(path)
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink path")
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
func readPrivate(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 4<<20 {
		return nil, errors.New("invalid private file")
	}
	b, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil || len(b) > 4<<20 {
		return nil, errors.New("private file bound")
	}
	return b, nil
}
