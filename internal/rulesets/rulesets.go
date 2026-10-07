// Package rulesets imports a bounded modern headless-rule subset into immutable,
// verified local artifacts. The engine never downloads remote sets itself.
package rulesets

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/fakeip"
	"mikrocentauri.local/core/internal/singbox"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
)

const MaxBytes = 4 << 20

type Spec struct {
	ID     string `json:"id"`
	URL    string `json:"url,omitempty"`
	Format string `json:"format"`
}
type Artifact struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type Source struct {
	Version int        `json:"version"`
	Rules   []Headless `json:"rules"`
}
type Headless struct {
	Domains     []string `json:"domain,omitempty"`
	Suffixes    []string `json:"domain_suffix,omitempty"`
	CIDRs       []string `json:"ip_cidr,omitempty"`
	SourceCIDRs []string `json:"source_ip_cidr,omitempty"`
	Ports       []uint16 `json:"port,omitempty"`
	Networks    []string `json:"network,omitempty"`
}

var id = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

func (s Spec) Validate() error {
	if !id.MatchString(s.ID) || (s.Format != "source" && s.Format != "binary") {
		return errors.New("invalid rule-set specification")
	}
	if s.URL != "" {
		_, e := validURL(s.URL)
		return e
	}
	return nil
}
func validURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if len(raw) > 8192 || e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("rule-set URL must be credential-free HTTPS")
	}
	return u, nil
}
func unique(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("rule-set nesting limit")
		}
		v, e := d.Token()
		if e != nil {
			return e
		}
		x, ok := v.(json.Delim)
		if !ok {
			return nil
		}
		switch x {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("duplicate rule-set key")
				}
				seen[s] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("invalid rule-set JSON")
		}
		_, e = d.Token()
		return e
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing rule-set JSON")
	}
	return nil
}
func ParseSource(b []byte) (Source, error) {
	var s Source
	if len(b) == 0 || len(b) > MaxBytes || unique(b) != nil {
		return s, errors.New("invalid bounded rule-set JSON")
	}
	// sing-box's listable fields are emitted as scalars by decompile when they
	// contain one item. Normalize that official representation before strict
	// typed decoding; unrecognized keys remain and are rejected below.
	var root map[string]any
	if json.Unmarshal(b, &root) != nil {
		return s, errors.New("invalid rule-set object")
	}
	if rows, ok := root["rules"].([]any); ok {
		for _, row := range rows {
			if r, ok := row.(map[string]any); ok {
				for _, key := range []string{"domain", "domain_suffix", "ip_cidr", "source_ip_cidr", "network"} {
					if v, ok := r[key].(string); ok {
						r[key] = []string{v}
					}
				}
				if v, ok := r["port"].(float64); ok {
					r["port"] = []float64{v}
				}
			}
		}
	}
	b, _ = json.Marshal(root)
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || s.Version < 1 || s.Version > 5 || len(s.Rules) < 1 || len(s.Rules) > 4096 {
		return s, errors.New("unsupported rule-set version or rules")
	}
	for _, r := range s.Rules {
		if len(r.Domains)+len(r.Suffixes)+len(r.CIDRs)+len(r.SourceCIDRs)+len(r.Ports)+len(r.Networks) == 0 {
			return s, errors.New("unconditional rule-set predicate refused")
		}
		for _, list := range [][]string{r.Domains, r.Suffixes} {
			seen := map[string]bool{}
			if len(list) > 4096 {
				return s, errors.New("rule-set bounds")
			}
			for _, n := range list {
				v, e := fakeip.CanonicalDomain(n)
				if e != nil || v != n || seen[n] {
					return s, errors.New("invalid rule-set domain")
				}
				seen[n] = true
			}
		}
		for _, list := range [][]string{r.CIDRs, r.SourceCIDRs} {
			seen := map[string]bool{}
			if len(list) > 4096 {
				return s, errors.New("rule-set bounds")
			}
			for _, n := range list {
				p, e := netip.ParsePrefix(n)
				if e != nil || p != p.Masked() || seen[n] {
					return s, errors.New("invalid rule-set CIDR")
				}
				seen[n] = true
			}
		}
		ports := map[uint16]bool{}
		for _, p := range r.Ports {
			if p == 0 || ports[p] {
				return s, errors.New("invalid rule-set port")
			}
			ports[p] = true
		}
		nets := map[string]bool{}
		for _, n := range r.Networks {
			if (n != "tcp" && n != "udp") || nets[n] {
				return s, errors.New("invalid rule-set network")
			}
			nets[n] = true
		}
	}
	s.Version = 5
	return s, nil
}
func privatePath(path string, directory bool) error {
	for p := path; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			return errors.New("rule-set path unavailable")
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("rule-set symlink refused")
		}
		if p == path {
			if directory {
				if !st.IsDir() || st.Mode().Perm() != 0700 {
					return errors.New("rule-set directory must be private")
				}
			} else if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > MaxBytes {
				return errors.New("rule-set file must be private and bounded")
			}
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func readPrivate(path string) ([]byte, error) {
	if e := privatePath(path, false); e != nil {
		return nil, e
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, errors.New("rule-set read failed")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > MaxBytes {
		return nil, errors.New("rule-set file metadata invalid")
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if e != nil || len(b) > MaxBytes {
		return nil, errors.New("rule-set read failed")
	}
	return b, nil
}
func (a Artifact) Validate() error {
	if !id.MatchString(a.ID) || !filepath.IsAbs(a.Path) || filepath.Clean(a.Path) != a.Path || len(a.SHA256) != 64 || filepath.Base(a.Path) != a.SHA256+".srs" {
		return errors.New("invalid rule-set artifact")
	}
	if e := privatePath(filepath.Dir(a.Path), true); e != nil {
		return e
	}
	b, e := readPrivate(a.Path)
	if e != nil {
		return e
	}
	h := sha256.Sum256(b)
	if hex.EncodeToString(h[:]) != a.SHA256 || len(b) < 4 || string(b[:3]) != "SRS" || (b[3] < 1 || b[3] > 5) {
		return errors.New("rule-set artifact integrity failed")
	}
	return nil
}

type Manager struct {
	directory, binary string
	policy            Policy
	mu                sync.Mutex
	poison            bool
}

func New(directory, binary string, policy Policy) (*Manager, error) {
	abs, e := filepath.Abs(directory)
	if e != nil {
		return nil, e
	}
	for p := abs; ; p = filepath.Dir(p) {
		if st, e := os.Lstat(p); e == nil && st.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("rule-set symlink refused")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	if e = os.MkdirAll(abs, 0700); e != nil {
		return nil, e
	}
	if e = privatePath(abs, true); e != nil {
		return nil, e
	}
	if policy.Timeout == 0 {
		policy.Timeout = 20e9
	}
	if policy.Timeout < 0 || policy.Timeout > 60e9 {
		return nil, errors.New("invalid rule-set timeout")
	}
	policy.AllowedCIDRs = append([]netip.Prefix(nil), policy.AllowedCIDRs...)
	if policy.RootCAs != nil {
		policy.RootCAs = policy.RootCAs.Clone()
	}
	return &Manager{directory: abs, binary: binary, policy: policy}, nil
}
func (m *Manager) Load(identifier string) (Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.load(identifier)
}
func (m *Manager) load(identifier string) (Artifact, error) {
	var a Artifact
	if !id.MatchString(identifier) {
		return a, errors.New("invalid rule-set ID")
	}
	b, e := readPrivate(filepath.Join(m.directory, identifier+".json"))
	if e != nil {
		return a, e
	}
	if unique(b) != nil {
		return a, errors.New("invalid rule-set manifest")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil || a.ID != identifier || filepath.Dir(a.Path) != m.directory {
		return a, errors.New("invalid rule-set manifest")
	}
	return a, a.Validate()
}
func (m *Manager) Refresh(ctx context.Context, s Spec) (Artifact, error) {
	if e := s.Validate(); e != nil {
		return Artifact{}, e
	}
	if s.URL == "" {
		return Artifact{}, errors.New("remote rule-set URL required")
	}
	b, e := m.download(ctx, s.URL)
	if e != nil {
		return Artifact{}, e
	}
	return m.Import(ctx, s.ID, s.Format, b)
}
func (m *Manager) Import(ctx context.Context, identifier, format string, b []byte) (Artifact, error) {
	ctx, cancel := context.WithTimeout(ctx, m.policy.Timeout)
	defer cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.poison {
		return Artifact{}, errors.New("rule-set persistence uncertain; reopen required")
	}
	if e := (Spec{ID: identifier, Format: format}).Validate(); e != nil {
		return Artifact{}, e
	}
	if len(b) == 0 || len(b) > MaxBytes {
		return Artifact{}, errors.New("rule-set candidate size refused")
	}
	fd, e := syscall.Open(filepath.Join(m.directory, "manager.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return Artifact{}, errors.New("rule-set lock unavailable")
	}
	lock := os.NewFile(uintptr(fd), "lock")
	defer lock.Close()
	st, e := lock.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return Artifact{}, errors.New("rule-set lock invalid")
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return Artifact{}, errors.New("rule-set manager already locked")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	v, e := exec.CommandContext(ctx, m.binary, "version").Output()
	if e != nil || !strings.Contains(string(v), "sing-box version "+singbox.Version+"\n") {
		return Artifact{}, errors.New("rule-set compiler version mismatch")
	}
	work, e := os.MkdirTemp(m.directory, ".candidate-")
	if e != nil {
		return Artifact{}, e
	}
	defer os.RemoveAll(work)
	src := filepath.Join(work, "source.json")
	compiled := filepath.Join(work, "compiled.srs")
	if format == "binary" {
		if len(b) < 4 || string(b[:3]) != "SRS" || b[3] > 5 || b[3] < 1 {
			return Artifact{}, errors.New("unsupported SRS header")
		}
		z, e := zlib.NewReader(bytes.NewReader(b[4:]))
		if e != nil {
			return Artifact{}, errors.New("invalid SRS compression")
		}
		expanded, e := io.ReadAll(io.LimitReader(z, 16<<20+1))
		z.Close()
		if e != nil || len(expanded) > 16<<20 {
			return Artifact{}, errors.New("SRS expanded size refused")
		}
		count, e := binary.ReadUvarint(bytes.NewBuffer(expanded))
		if e != nil || count < 1 || count > 4096 {
			return Artifact{}, errors.New("SRS predicate count refused")
		}
		if e = os.WriteFile(compiled, b, 0600); e != nil {
			return Artifact{}, e
		}
		out := exec.CommandContext(ctx, m.binary, "rule-set", "decompile", compiled, "-o", src)
		if out.Run() != nil {
			return Artifact{}, errors.New("rule-set binary invalid")
		}
		info, err := os.Stat(src)
		if err != nil || info.Size() > MaxBytes {
			return Artifact{}, errors.New("decompiled source size refused")
		}
		b, e = os.ReadFile(src)
		if e != nil {
			return Artifact{}, errors.New("rule-set decompile failed")
		}
	}
	s, e := ParseSource(b)
	if e != nil {
		return Artifact{}, e
	}
	canonical, _ := json.Marshal(s)
	if e = os.WriteFile(src, canonical, 0600); e != nil {
		return Artifact{}, e
	}
	if exec.CommandContext(ctx, m.binary, "rule-set", "compile", src, "-o", compiled).Run() != nil {
		return Artifact{}, errors.New("rule-set compile failed")
	}
	b, e = os.ReadFile(compiled)
	if e != nil || len(b) > MaxBytes || len(b) < 4 || string(b[:3]) != "SRS" || (b[3] < 1 || b[3] > 5) {
		return Artifact{}, errors.New("rule-set compiled header invalid")
	}
	h := sha256.Sum256(b)
	digest := hex.EncodeToString(h[:])
	a := Artifact{ID: identifier, Path: filepath.Join(m.directory, digest+".srs"), SHA256: digest}
	if _, e = os.Lstat(a.Path); os.IsNotExist(e) {
		if e = config.WriteAtomic(a.Path, b); e != nil {
			m.poison = true
			return Artifact{}, errors.New("rule-set artifact persistence uncertain")
		}
	} else if e != nil {
		return Artifact{}, errors.New("rule-set artifact unavailable")
	}
	if e = a.Validate(); e != nil {
		return Artifact{}, e
	}
	// Validate actual engine loading before replacing the ID's LKG manifest.
	cfg := map[string]any{"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}}, "route": map[string]any{"rule_set": []map[string]any{{"type": "local", "tag": identifier, "format": "binary", "path": a.Path}}, "rules": []map[string]any{{"rule_set": []string{identifier}, "action": "route", "outbound": "direct"}}, "final": "direct"}}
	cb, _ := json.Marshal(cfg)
	p := filepath.Join(work, "check.json")
	os.WriteFile(p, cb, 0600)
	if e = singbox.Check(ctx, m.binary, p); e != nil {
		return Artifact{}, e
	}
	manifest := filepath.Join(m.directory, identifier+".json")
	if _, e = os.Lstat(manifest); e == nil {
		if _, e = m.load(identifier); e != nil {
			return Artifact{}, e
		}
	} else if !os.IsNotExist(e) {
		return Artifact{}, errors.New("rule-set manifest unavailable")
	}
	ab, _ := json.Marshal(a)
	if e = config.WriteAtomic(manifest, ab); e != nil {
		m.poison = true
		return Artifact{}, errors.New("rule-set manifest persistence uncertain")
	}
	return a, nil
}
