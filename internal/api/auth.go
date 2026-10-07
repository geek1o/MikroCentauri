package api

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/config"
)

const passwordIterations = 600000

type credential struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
}
type Auth struct {
	mu       sync.Mutex
	cred     credential
	sessions map[[32]byte]time.Time
	attempts int
	window   time.Time
	now      func() time.Time
	lock     *os.File
}

// PrivateDirectory rejects symlink components and requires the leaf to be 0700.
func PrivateDirectory(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", errors.New("invalid private directory")
	}
	for p := absolute; p != filepath.Dir(p); p = filepath.Dir(p) {
		fi, e := os.Lstat(p)
		if e == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir()) {
			return "", errors.New("unsafe private directory")
		}
		if e != nil && !os.IsNotExist(e) {
			return "", errors.New("private directory unavailable")
		}
	}
	if err = os.MkdirAll(absolute, 0700); err != nil {
		return "", errors.New("private directory unavailable")
	}
	fi, err := os.Lstat(absolute)
	if err != nil || fi.Mode().Perm() != 0700 {
		return "", errors.New("private directory must be 0700")
	}
	return absolute, nil
}
func privateRead(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 || fi.Size() > limit {
		return nil, errors.New("private file must be bounded regular 0600")
	}
	b := make([]byte, fi.Size())
	_, err = f.ReadAt(b, 0)
	return b, err
}
func openAuth(directory string, password []byte) (*Auth, error) {
	dir, err := PrivateDirectory(directory)
	if err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "api.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("auth lock unavailable")
	}
	fi, e := lock.Stat()
	if e != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, errors.New("API state already owned or unsafe")
	}
	fail := func() (*Auth, error) {
		syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		lock.Close()
		return nil, errors.New("authentication state unavailable")
	}
	path := filepath.Join(dir, "auth.json")
	raw, e := privateRead(path, 32768)
	if os.IsNotExist(e) && password != nil {
		if len(password) < 16 || len(password) > 1024 {
			return fail()
		}
		salt := make([]byte, 32)
		if _, e = rand.Read(salt); e != nil {
			return fail()
		}
		key, e := pbkdf2.Key(sha256.New, string(password), salt, passwordIterations, 32)
		if e != nil {
			return fail()
		}
		raw, _ = json.Marshal(credential{1, hex.EncodeToString(salt), hex.EncodeToString(key), passwordIterations})
		if config.WriteAtomic(path, raw) != nil {
			return fail()
		}
	} else if e != nil || password != nil {
		return fail()
	}
	var c credential
	if json.Unmarshal(raw, &c) != nil || c.Version != 1 || c.Iterations != passwordIterations {
		return fail()
	}
	salt, e := hex.DecodeString(c.Salt)
	key, kerr := hex.DecodeString(c.Hash)
	if e != nil || kerr != nil || len(salt) != 32 || len(key) != 32 {
		return fail()
	}
	return &Auth{cred: c, sessions: map[[32]byte]time.Time{}, now: time.Now, lock: lock}, nil
}
func InitializeAuth(directory string, password []byte) error {
	a, e := openAuth(directory, password)
	if e == nil {
		a.Close()
	}
	return e
}
func OpenAuth(directory string) (*Auth, error) { return openAuth(directory, nil) }
func (a *Auth) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions = map[[32]byte]time.Time{}
	if a.lock != nil {
		syscall.Flock(int(a.lock.Fd()), syscall.LOCK_UN)
		a.lock.Close()
		a.lock = nil
	}
}
func (a *Auth) Login(password string) (string, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if a.lock == nil {
		return "", 503
	}
	if now.Sub(a.window) >= time.Minute {
		a.window = now
		a.attempts = 0
	}
	if a.attempts >= 5 {
		return "", 429
	}
	a.attempts++
	if len(password) > 1024 {
		return "", 401
	}
	salt, _ := hex.DecodeString(a.cred.Salt)
	expected, _ := hex.DecodeString(a.cred.Hash)
	key, e := pbkdf2.Key(sha256.New, password, salt, a.cred.Iterations, 32)
	if e != nil || subtle.ConstantTimeCompare(key, expected) != 1 {
		return "", 401
	}
	for k, expires := range a.sessions {
		if !expires.After(now) {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) >= 32 {
		return "", 429
	}
	token := randomToken()
	if token == "" {
		return "", 503
	}
	a.sessions[sha256.Sum256([]byte(token))] = now.Add(30 * time.Minute)
	return token, 200
}
func (a *Auth) Valid(token string) bool {
	if len(token) != 64 {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := sha256.Sum256([]byte(token))
	expires, ok := a.sessions[key]
	if !ok || !expires.After(a.now()) || a.lock == nil {
		delete(a.sessions, key)
		return false
	}
	return true
}
func (a *Auth) Logout(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, sha256.Sum256([]byte(token)))
}
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
