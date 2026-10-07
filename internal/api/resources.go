package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/platform/routeros"
	"mikrocentauri.local/core/internal/subscriptions"
)

type RouterClient interface {
	Capabilities(context.Context) (routeros.Capabilities, error)
	Discover(context.Context) ([]routeros.Object, error)
}
type RouterSnapshot struct {
	Capabilities  routeros.Capabilities `json:"capabilities"`
	OwnedCounts   map[string]int        `json:"owned_counts"`
	OwnedDisabled map[string]int        `json:"owned_disabled"`
}
type RouterResources struct {
	Client   RouterClient
	Instance string
}

func (r *RouterResources) Snapshot(ctx context.Context) (RouterSnapshot, error) {
	result := RouterSnapshot{OwnedCounts: map[string]int{}, OwnedDisabled: map[string]int{}}
	if r == nil || r.Client == nil || !regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(r.Instance) {
		return result, errors.New("RouterOS adapter unavailable")
	}
	caps, e := r.Client.Capabilities(ctx)
	if e != nil {
		return result, e
	}
	rows, e := r.Client.Discover(ctx)
	if e != nil {
		return result, e
	}
	result.Capabilities = caps
	for _, o := range rows {
		if routeros.Owned(r.Instance, o) {
			result.OwnedCounts[o.Path]++
			if o.Fields["disabled"] == "true" {
				result.OwnedDisabled[o.Path]++
			}
		}
	}
	return result, nil
}

type SubscriptionManager interface {
	Load(string) (subscriptions.State, error)
	Refresh(context.Context, subscriptions.Spec) (subscriptions.State, error)
}
type SubscriptionView struct {
	NodeCount     int                 `json:"node_count"`
	Offset        int                 `json:"offset"`
	HasMore       bool                `json:"has_more"`
	ID            string              `json:"id"`
	LastAttempt   time.Time           `json:"last_attempt"`
	LastSuccess   time.Time           `json:"last_success"`
	Failed        bool                `json:"failed"`
	ImportedCount int                 `json:"imported_count"`
	Nodes         []endpoints.Preview `json:"nodes"`
}
type SubscriptionResources struct {
	lock           *os.File
	mu             sync.Mutex
	refreshMu      sync.Mutex
	running        bool
	eventsMu       sync.Mutex
	events         []Event
	dir            string
	manager        SubscriptionManager
	specs          []subscriptions.Spec
	poisoned       bool
	schedule       *SubscriptionSchedule
	scheduleNotify chan struct{}
}

var subscriptionID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func validateSpec(s subscriptions.Spec) error {
	u, e := url.Parse(s.URL)
	if !subscriptionID.MatchString(s.ID) || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || len(s.URL) > 8192 || len(s.Include) > 4096 || len(s.Exclude) > 4096 {
		return errors.New("invalid subscription specification")
	}
	for _, filter := range []string{s.Include, s.Exclude} {
		if _, e = regexp.Compile(filter); e != nil {
			return errors.New("invalid subscription filter")
		}
	}
	return nil
}
func NewSubscriptionResources(directory string, m SubscriptionManager) (*SubscriptionResources, error) {
	if m == nil {
		return nil, errors.New("subscription manager required")
	}
	dir, e := PrivateDirectory(directory)
	if e != nil {
		return nil, e
	}
	s := &SubscriptionResources{dir: dir, manager: m, specs: []subscriptions.Spec{}}
	lock, e := os.OpenFile(filepath.Join(dir, "subscription-registry.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, errors.New("subscription registry lock unavailable")
	}
	fi, e := lock.Stat()
	if e != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, errors.New("subscription registry already owned or unsafe")
	}
	s.lock = lock
	ready := false
	defer func() {
		if !ready {
			s.Close()
		}
	}()
	raw, e := privateRead(filepath.Join(dir, "subscription-specs.json"), 2<<20)
	if e == nil {
		if decode(raw, &s.specs) != nil || len(s.specs) > 64 {
			return nil, errors.New("invalid private subscription specs")
		}
		seen := map[string]bool{}
		for _, v := range s.specs {
			if seen[v.ID] || validateSpec(v) != nil {
				return nil, errors.New("invalid private subscription spec")
			}
			seen[v.ID] = true
		}
	} else if !os.IsNotExist(e) {
		return nil, errors.New("private subscription specs unavailable")
	}
	ready = true
	return s, nil
}
func (s *SubscriptionResources) Configure(spec subscriptions.Spec) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned || s.lock == nil {
		return errors.New("subscription registry requires reopen")
	}
	if validateSpec(spec) != nil {
		return errors.New("invalid subscription specification")
	}
	next := append([]subscriptions.Spec(nil), s.specs...)
	found := false
	for i, v := range next {
		if v.ID == spec.ID {
			next[i] = spec
			found = true
			break
		}
	}
	if !found {
		if len(next) >= 64 {
			return errors.New("subscription limit")
		}
		next = append(next, spec)
	}
	b, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if config.WriteAtomic(filepath.Join(s.dir, "subscription-specs.json"), b) != nil {
		s.poisoned = true
		return errors.New("subscription specification persistence failed")
	}
	s.specs = next
	s.recordEvent("subscription_configured")
	return nil
}
func subscriptionPreview(state subscriptions.State) SubscriptionView {
	return subscriptionPage(state, 0, 128)
}
func subscriptionPage(state subscriptions.State, offset, limit int) SubscriptionView {
	v := SubscriptionView{ID: state.ID, LastAttempt: state.LastAttempt, LastSuccess: state.LastSuccess, Failed: state.Failure != "", ImportedCount: state.ImportedCount, Nodes: []endpoints.Preview{}, NodeCount: len(state.Nodes), Offset: offset}
	end := min(offset+limit, len(state.Nodes))
	v.HasMore = end < len(state.Nodes)
	for _, node := range state.Nodes[offset:end] {
		v.Nodes = append(v.Nodes, node.Preview())
	}
	return v
}
func (s *SubscriptionResources) Inspect(id string, offset, limit int) (SubscriptionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned || s.lock == nil || offset < 0 || limit < 1 || limit > 128 {
		return SubscriptionView{}, errors.New("invalid subscription page")
	}
	for _, spec := range s.specs {
		if spec.ID == id {
			state, e := s.manager.Load(id)
			if e != nil || offset > len(state.Nodes) {
				return SubscriptionView{}, errors.New("subscription page unavailable")
			}
			return subscriptionPage(state, offset, limit), nil
		}
	}
	return SubscriptionView{}, errors.New("subscription not configured")
}
func (s *SubscriptionResources) List() ([]SubscriptionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := []SubscriptionView{}
	if s.poisoned || s.lock == nil {
		return nil, errors.New("subscription registry requires reopen")
	}
	for _, spec := range s.specs {
		state, e := s.manager.Load(spec.ID)
		if e != nil {
			return nil, errors.New("subscription state unavailable")
		}
		result = append(result, subscriptionPreview(state))
	}
	return result, nil
}
func (s *SubscriptionResources) Refresh(ctx context.Context, id string) (SubscriptionView, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	s.mu.Lock()
	if s.poisoned || s.lock == nil {
		s.mu.Unlock()
		return SubscriptionView{}, errors.New("subscription registry requires reopen")
	}
	var selected *subscriptions.Spec
	for _, spec := range s.specs {
		if spec.ID == id {
			copy := spec
			selected = &copy
			break
		}
	}
	s.mu.Unlock()
	if selected == nil {
		return SubscriptionView{}, errors.New("subscription not configured")
	}
	state, e := s.manager.Refresh(ctx, *selected)
	if e != nil {
		s.recordEvent("subscription_refresh_failed")
	} else {
		s.recordEvent("subscription_refreshed")
	}
	return subscriptionPreview(state), e
}

func (s *SubscriptionResources) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock != nil {
		syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		s.lock.Close()
		s.lock = nil
	}
}
