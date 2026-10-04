//go:build linux || darwin

// Package fakeip implements the laboratory publication barrier for pinned IPv4
// mappings. It does not expire mappings, recycle aliases, or follow DNS churn.
package fakeip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const maxCapacity = 4096
const maxJournalBytes = 2 << 20
const MaxTTL = 30 * time.Second

var ErrCapacity = errors.New("fakeip alias capacity exhausted")
var ErrClosed = errors.New("fakeip publisher closed")

type Mapping struct {
	Domain string     `json:"domain"`
	Fake   netip.Addr `json:"fake"`
	Real   netip.Addr `json:"real"`
}

type Resolver interface {
	ResolveA(context.Context, string) ([]netip.Addr, time.Duration, error)
}
type Backend interface {
	Ensure(context.Context, Mapping) error
	Verify(context.Context, Mapping) error
}
type Config struct {
	Directory string
	Prefix    netip.Prefix
	Capacity  uint32
}
type record struct {
	Mapping    Mapping `json:"mapping"`
	TTLSeconds uint32  `json:"ttl_seconds"`
	Ready      bool    `json:"ready"`
}
type journal struct {
	Version  int          `json:"version"`
	Prefix   netip.Prefix `json:"prefix"`
	Capacity uint32       `json:"capacity"`
	Records  []record     `json:"records"`
}
type Publisher struct {
	mu       sync.Mutex
	config   Config
	resolver Resolver
	backend  Backend
	lock     *os.File
	state    journal
	closed   bool
	// A failed durable write leaves uncertainty about rename/fsync completion.
	// Refuse further allocations until a new process reloads the journal.
	poisoned bool
}

// CanonicalDomain accepts exact ASCII DNS host names only, lowercases them,
// and removes one optional terminal root dot.
func CanonicalDomain(domain string) (string, error) {
	domain = strings.TrimSuffix(domain, ".")
	if len(domain) == 0 || len(domain) > 253 {
		return "", errors.New("invalid DNS name length")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("DNS names must be ASCII host names")
			}
		}
	}
	return strings.ToLower(domain), nil
}

func New(config Config, resolver Resolver, backend Backend) (*Publisher, error) {
	if resolver == nil || backend == nil {
		return nil, errors.New("resolver and backend required")
	}
	if config.Directory == "" {
		return nil, errors.New("private journal directory required")
	}
	if !config.Prefix.IsValid() {
		config.Prefix = netip.MustParsePrefix("198.18.0.0/15")
	}
	pool := netip.MustParsePrefix("198.18.0.0/15")
	if !config.Prefix.Addr().Is4() || config.Prefix != config.Prefix.Masked() || config.Prefix.Bits() < 15 || !pool.Contains(config.Prefix.Addr()) {
		return nil, errors.New("prefix must be a canonical IPv4 subnet of 198.18.0.0/15")
	}
	if config.Capacity == 0 || config.Capacity > maxCapacity {
		return nil, errors.New("capacity must be between 1 and 4096")
	}
	last := config.Prefix.Addr()
	for i := uint32(0); i < config.Capacity; i++ {
		last = last.Next()
		if !config.Prefix.Contains(last) {
			return nil, errors.New("capacity exceeds prefix")
		}
	}
	if err := os.MkdirAll(config.Directory, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(config.Directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("journal directory must be a real directory with mode 0700")
	}
	// Persist any newly created directory entries before a backend mutation can
	// depend on the journal. Syncing only the final directory misses its parent.
	absolute, err := filepath.Abs(config.Directory)
	if err != nil {
		return nil, err
	}
	for directory := absolute; ; directory = filepath.Dir(directory) {
		f, err := os.Open(directory)
		if err != nil {
			return nil, err
		}
		err = f.Sync()
		f.Close()
		if err != nil {
			return nil, err
		}
		if filepath.Dir(directory) == directory {
			break
		}
	}
	fd, err := syscall.Open(filepath.Join(config.Directory, "publisher.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), "publisher.lock")
	fail := func(err error) (*Publisher, error) { lock.Close(); return nil, err }
	if info, err := lock.Stat(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fail(errors.New("invalid private lock file"))
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(fmt.Errorf("publisher already locked: %w", err))
	}
	p := &Publisher{config: config, resolver: resolver, backend: backend, lock: lock, state: journal{Version: 1, Prefix: config.Prefix, Capacity: config.Capacity, Records: []record{}}}
	if err := p.load(); err != nil {
		return fail(err)
	}
	return p, nil
}

func (p *Publisher) load() error {
	fd, err := syscall.Open(filepath.Join(p.config.Directory, "mappings.json"), syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "mappings.json")
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxJournalBytes {
		return errors.New("invalid private journal file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxJournalBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxJournalBytes {
		return errors.New("journal size limit exceeded")
	}
	if err := uniqueJSONKeys(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return fmt.Errorf("invalid journal structure: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state journal
	if err := decoder.Decode(&state); err != nil {
		return fmt.Errorf("invalid journal: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("journal contains trailing data")
	}
	if state.Version != 1 || state.Prefix != p.config.Prefix || state.Capacity != p.config.Capacity || len(state.Records) > int(state.Capacity) || state.Records == nil {
		return errors.New("journal configuration mismatch")
	}
	domains := map[string]bool{}
	aliases := map[netip.Addr]bool{}
	for _, r := range state.Records {
		domain, err := CanonicalDomain(r.Mapping.Domain)
		if err != nil || domain != r.Mapping.Domain || domains[domain] || !r.Mapping.Fake.Is4() || !state.Prefix.Contains(r.Mapping.Fake) || aliases[r.Mapping.Fake] || !validReal(r.Mapping.Real) || r.TTLSeconds == 0 || r.TTLSeconds > 30 {
			return errors.New("journal contains invalid or duplicate mappings")
		}
		domains[domain] = true
		aliases[r.Mapping.Fake] = true
	}
	p.state = state
	return nil
}

// encoding/json normally accepts duplicate object members with last-value wins.
// A recovery journal must instead reject ambiguous representations.
func uniqueJSONKeys(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || keys[key] {
				return errors.New("duplicate JSON object member")
			}
			keys[key] = true
			if err := uniqueJSONKeys(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueJSONKeys(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func validReal(addr netip.Addr) bool {
	return addr.Is4() && !addr.IsUnspecified() && !addr.IsMulticast() && !netip.MustParsePrefix("198.18.0.0/15").Contains(addr)
}

func (p *Publisher) save() (err error) {
	data, err := json.Marshal(p.state)
	if err != nil {
		return err
	}
	if len(data) > maxJournalBytes {
		return errors.New("journal size limit exceeded")
	}
	f, err := os.CreateTemp(p.config.Directory, ".mappings-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(p.config.Directory, "mappings.json")); err != nil {
		return err
	}
	directory, err := os.Open(p.config.Directory)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// Publish serializes resolution and publication. A mapping is pinned for the
// lifetime of the journal, including pending reservations after backend errors.
// Backend state is freshly verified on EVERY call, even for a ready record.
func (p *Publisher) Publish(ctx context.Context, domain string) (Mapping, time.Duration, error) {
	return p.publish(ctx, domain, netip.Addr{})
}

// PublishAlias reserves an alias issued by a proxy engine. Changing an existing
// domain alias or assigning any reserved alias to another domain fails closed.
func (p *Publisher) PublishAlias(ctx context.Context, domain string, alias netip.Addr) (Mapping, time.Duration, error) {
	if !alias.Is4() || !p.config.Prefix.Contains(alias) {
		return Mapping{}, 0, errors.New("alias outside configured IPv4 prefix")
	}
	return p.publish(ctx, domain, alias)
}

func (p *Publisher) publish(ctx context.Context, domain string, alias netip.Addr) (Mapping, time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	empty := Mapping{}
	if p.closed {
		return empty, 0, ErrClosed
	}
	if p.poisoned {
		return empty, 0, errors.New("journal write failed; reopen publisher before continuing")
	}
	if err := ctx.Err(); err != nil {
		return empty, 0, err
	}
	domain, err := CanonicalDomain(domain)
	if err != nil {
		return empty, 0, err
	}
	index := -1
	for i, r := range p.state.Records {
		if r.Mapping.Domain == domain {
			index = i
			break
		}
	}
	if index >= 0 && alias.IsValid() && p.state.Records[index].Mapping.Fake != alias {
		return empty, 0, errors.New("domain alias is immutable")
	}
	if index < 0 {
		used := map[netip.Addr]bool{}
		for _, r := range p.state.Records {
			used[r.Mapping.Fake] = true
		}
		if alias.IsValid() && used[alias] {
			return empty, 0, errors.New("alias already reserved for another domain")
		}
		if len(p.state.Records) >= int(p.config.Capacity) {
			return empty, 0, ErrCapacity
		}
		addresses, ttl, err := p.resolver.ResolveA(ctx, domain)
		if err != nil {
			return empty, 0, fmt.Errorf("resolve A: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return empty, 0, err
		}
		var candidates []netip.Addr
		for _, addr := range addresses {
			if validReal(addr) {
				candidates = append(candidates, addr)
			}
		}
		if len(candidates) == 0 {
			return empty, 0, errors.New("resolver returned no usable IPv4 A address")
		}
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].Less(candidates[j]) })
		if ttl <= 0 || ttl > MaxTTL {
			ttl = MaxTTL
		}
		seconds := uint32(ttl / time.Second)
		if seconds == 0 {
			seconds = 1
		}
		fake := alias
		if !fake.IsValid() {
			fake = p.state.Prefix.Addr().Next()
			for used[fake] && p.state.Prefix.Contains(fake) {
				fake = fake.Next()
			}
			if !p.state.Prefix.Contains(fake) {
				return empty, 0, ErrCapacity
			}
		}
		p.state.Records = append(p.state.Records, record{Mapping: Mapping{domain, fake, candidates[0]}, TTLSeconds: seconds})
		index = len(p.state.Records) - 1
		if err := p.save(); err != nil {
			p.poisoned = true
			return empty, 0, fmt.Errorf("persist reservation: %w", err)
		}
	}
	if err := p.ensureReady(ctx, index); err != nil {
		return empty, 0, err
	}
	r := p.state.Records[index]
	return r.Mapping, time.Duration(r.TTLSeconds) * time.Second, nil
}

func (p *Publisher) ensureReady(ctx context.Context, index int) error {
	r := &p.state.Records[index]
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.backend.Ensure(ctx, r.Mapping); err != nil {
		return fmt.Errorf("ensure mapping: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.backend.Verify(ctx, r.Mapping); err != nil {
		return fmt.Errorf("verify mapping: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !r.Ready {
		r.Ready = true
		if err := p.save(); err != nil {
			p.poisoned = true
			return fmt.Errorf("persist ready mapping: %w", err)
		}
	}
	return ctx.Err()
}

// Reconcile re-establishes and freshly verifies every reserved mapping, including
// pending reservations. The caller must independently check the proxy engine's
// alias cache before using this result as a readiness signal.
func (p *Publisher) Reconcile(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	if p.poisoned {
		return errors.New("journal write failed; reopen publisher before continuing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for i := range p.state.Records {
		if err := p.ensureReady(ctx, i); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Mappings returns an independent snapshot of all immutable reservations,
// including pending ones; its presence is not evidence of backend readiness.
func (p *Publisher) Mappings() []Mapping {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Mapping, len(p.state.Records))
	for i, r := range p.state.Records {
		out[i] = r.Mapping
	}
	return out
}

func (p *Publisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.lock.Close()
}
