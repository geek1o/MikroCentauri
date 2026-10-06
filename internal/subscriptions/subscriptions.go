// Package subscriptions implements bounded, DNS-pinned downloads and private last-known-good snapshots.
package subscriptions

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mikrocentauri.local/core/internal/endpoints"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Parser interface {
	Parse([]byte) ([]endpoints.Endpoint, error)
}
type URIList struct{}

func (URIList) Parse(data []byte) ([]endpoints.Endpoint, error) {
	if len(data) > 4<<20 {
		return nil, errors.New("subscription exceeds size limit")
	}
	s := strings.TrimSpace(string(data))
	if !strings.Contains(s, "://") {
		var b []byte
		var err error
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			b, err = enc.DecodeString(strings.Join(strings.Fields(s), ""))
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, errors.New("unsupported subscription format")
		}
		s = string(b)
	}
	nodes := []endpoints.Endpoint{}
	seen := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(nodes) >= 4096 {
			return nil, errors.New("subscription node limit")
		}
		e, err := endpoints.ParseURI(line)
		if err != nil {
			return nil, errors.New("subscription contains invalid endpoint")
		}
		if !seen[e.ID] {
			nodes = append(nodes, e)
			seen[e.ID] = true
		}
	}
	if len(nodes) == 0 {
		return nil, errors.New("empty subscription")
	}
	return nodes, nil
}
func Parse(data []byte) ([]endpoints.Endpoint, error) { return (URIList{}).Parse(data) }

type Policy struct {
	// RootCAs is an operator-supplied trust store; TLS verification stays enabled.
	RootCAs      *x509.CertPool
	AllowedCIDRs []netip.Prefix
	Timeout      time.Duration
	MaxBytes     int64
	MaxRedirects int
}
type Spec struct {
	ID      string `json:"id"`
	URL     string `json:"url"`
	Include string `json:"include,omitempty"`
	Exclude string `json:"exclude,omitempty"`
}
type State struct {
	ID            string               `json:"id"`
	LastAttempt   time.Time            `json:"last_attempt"`
	LastSuccess   time.Time            `json:"last_success"`
	Failure       string               `json:"failure,omitempty"`
	ImportedCount int                  `json:"imported_count"`
	Nodes         []endpoints.Endpoint `json:"nodes"`
}
type Manager struct {
	dir    string
	policy Policy
	parser Parser
	mu     sync.Mutex
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func New(directory string, policy Policy) (*Manager, error) {
	return NewWithParser(directory, policy, URIList{})
}
func NewWithParser(directory string, policy Policy, parser Parser) (*Manager, error) {
	if parser == nil {
		return nil, errors.New("subscription parser required")
	}
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, errors.New("invalid subscription directory")
	}
	if err = checkParents(abs); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return nil, errors.New("subscription directory unavailable")
	}
	st, err := os.Lstat(abs)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, errors.New("subscription directory must be private")
	}
	if policy.Timeout == 0 {
		policy.Timeout = 20 * time.Second
	}
	if policy.Timeout < 0 || policy.Timeout > time.Minute {
		return nil, errors.New("invalid download timeout")
	}
	if policy.MaxBytes == 0 {
		policy.MaxBytes = 4 << 20
	}
	if policy.MaxBytes < 1 || policy.MaxBytes > 4<<20 {
		return nil, errors.New("invalid download limit")
	}
	if policy.MaxRedirects == 0 {
		policy.MaxRedirects = 3
	}
	if policy.MaxRedirects < 0 || policy.MaxRedirects > 10 {
		return nil, errors.New("invalid redirect limit")
	}
	if policy.RootCAs != nil {
		policy.RootCAs = policy.RootCAs.Clone()
	}
	return &Manager{dir: abs, policy: policy, parser: parser}, nil
}
func checkParents(p string) error {
	for {
		st, err := os.Lstat(p)
		if err == nil && st.Mode()&os.ModeSymlink != 0 {
			return errors.New("subscription path must not contain symlinks")
		}
		if err != nil && !os.IsNotExist(err) {
			return errors.New("subscription path unavailable")
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}
func (m *Manager) Load(id string) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.lock()
	if err != nil {
		return State{}, err
	}
	defer unlock()
	return m.load(id)
}
func (m *Manager) load(id string) (State, error) {
	if !identifier.MatchString(id) {
		return State{}, errors.New("invalid subscription ID")
	}
	p := filepath.Join(m.dir, id+".json")
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if os.IsNotExist(err) {
		return State{ID: id}, nil
	}
	if err != nil {
		return State{}, errors.New("subscription state unavailable")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 16<<20 {
		return State{}, errors.New("invalid private subscription state")
	}
	b, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if err != nil || len(b) > 16<<20 {
		return State{}, errors.New("subscription state unavailable")
	}
	if strictJSON(b) != nil {
		return State{}, errors.New("invalid subscription state")
	}
	var s State
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil || s.ID != id {
		return State{}, errors.New("invalid subscription state")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return State{}, errors.New("invalid subscription state")
	}
	for _, e := range s.Nodes {
		if e.Validate() != nil || e.ID == "" {
			return State{}, errors.New("invalid subscription state")
		}
	}
	return s, nil
}
func (m *Manager) save(s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return errors.New("subscription state encoding failed")
	}
	p := filepath.Join(m.dir, s.ID+".json")
	if st, err := os.Lstat(p); err == nil && (!st.Mode().IsRegular() || st.Mode().Perm() != 0600) {
		return errors.New("invalid subscription state target")
	}
	f, err := os.CreateTemp(m.dir, ".candidate-")
	if err != nil {
		return errors.New("subscription state persistence failed")
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err == nil {
		err = os.Rename(f.Name(), p)
	}
	if err == nil {
		var d *os.File
		d, err = os.Open(m.dir)
		if err == nil {
			err = d.Sync()
			d.Close()
		}
	}
	if err != nil {
		return errors.New("subscription state persistence failed")
	}
	return nil
}
func (m *Manager) Refresh(ctx context.Context, spec Spec) (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.lock()
	if err != nil {
		return State{}, err
	}
	defer unlock()
	s, err := m.load(spec.ID)
	if err != nil {
		return s, err
	}
	s.LastAttempt = time.Now().UTC()
	fail := func(reason string) (State, error) {
		s.Failure = reason
		if e := m.save(s); e != nil {
			return s, e
		}
		return s, errors.New(reason)
	}
	if len(spec.Include) > 4096 || len(spec.Exclude) > 4096 {
		return fail("subscription filter exceeds size limit")
	}
	var include, exclude *regexp.Regexp
	if spec.Include != "" {
		include, err = regexp.Compile(spec.Include)
		if err != nil {
			return fail("invalid include filter")
		}
	}
	if spec.Exclude != "" {
		exclude, err = regexp.Compile(spec.Exclude)
		if err != nil {
			return fail("invalid exclude filter")
		}
	}
	b, err := m.download(ctx, spec.URL)
	if err != nil {
		return fail("subscription download failed")
	}
	nodes, err := m.parser.Parse(b)
	if err != nil {
		return fail("subscription validation failed")
	}
	if len(nodes) == 0 || len(nodes) > 4096 {
		return fail("subscription node count invalid")
	}
	filtered := []endpoints.Endpoint{}
	seen := map[string]bool{}
	for _, e := range nodes {
		if e.Validate() != nil || e.ID == "" {
			return fail("subscription validation failed")
		}
		if include != nil && !include.MatchString(e.Name) || exclude != nil && exclude.MatchString(e.Name) {
			continue
		}
		if !seen[e.ID] {
			filtered = append(filtered, e)
			seen[e.ID] = true
		}
	}
	if len(filtered) == 0 {
		return fail("subscription selection is empty")
	}
	s.Nodes = filtered
	s.ImportedCount = len(filtered)
	s.LastSuccess = s.LastAttempt
	s.Failure = ""
	if err = m.save(s); err != nil {
		return State{}, err
	}
	return s, nil
}
func (m *Manager) Run(ctx context.Context, specs []Spec, interval time.Duration) error {
	if interval < time.Second {
		return errors.New("refresh interval must be at least one second")
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			for _, spec := range specs {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				_, _ = m.Refresh(ctx, spec)
			}
		}
	}
}
func (m *Manager) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range m.policy.AllowedCIDRs {
		if p.Contains(ip) {
			return true
		}
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	for _, s := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}
func validURL(raw string) (*url.URL, error) {
	if len(raw) > 8192 {
		return nil, errors.New("invalid subscription URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid subscription URL")
	}
	return u, nil
}
func (m *Manager) download(ctx context.Context, raw string) ([]byte, error) {
	u, err := validURL(raw)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, m.policy.Timeout)
	defer cancel()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: m.policy.RootCAs}, Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: m.policy.Timeout, MaxResponseHeaderBytes: 64 << 10}
	defer transport.CloseIdleConnections()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("invalid destination")
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("destination unavailable")
		}
		for _, ip := range ips {
			if !m.allowed(ip) {
				return nil, errors.New("destination refused")
			}
		}
		var conn net.Conn
		for _, ip := range ips {
			conn, err = (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
		}
		return nil, errors.New("destination unavailable")
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > m.policy.MaxRedirects {
			return errors.New("redirect limit")
		}
		_, err := validURL(req.URL.String())
		if err != nil {
			return err
		}
		if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("TLS downgrade refused")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid request")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("subscription request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("subscription HTTP failure")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, m.policy.MaxBytes+1))
	if err != nil || int64(len(b)) > m.policy.MaxBytes {
		return nil, errors.New("subscription body invalid")
	}
	return b, nil
}

func (m *Manager) lock() (func(), error) {
	if checkParents(m.dir) != nil {
		return nil, errors.New("unsafe subscription directory")
	}
	f, err := os.OpenFile(filepath.Join(m.dir, "state.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, errors.New("subscription lock unavailable")
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("invalid subscription lock")
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, errors.New("subscription state busy")
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
func strictJSON(b []byte) error {
	d := json.NewDecoder(strings.NewReader(string(b)))
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON depth")
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := k.(string)
				if !ok || keys[s] {
					return errors.New("duplicate JSON key")
				}
				keys[s] = true
				if err = visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
