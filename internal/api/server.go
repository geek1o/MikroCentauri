// Package api implements the authenticated v1 application boundary. Network
// mutations are delegated exclusively to the accepted transition owner.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"mikrocentauri.local/core/internal/coreactivation"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/subscriptions"
	"mikrocentauri.local/core/internal/trafficlists"
	"mikrocentauri.local/core/internal/webui"
)

type Options struct {
	Engine                 EngineControl
	SimulatedSubscriptions bool
	SimulatedRuntime       bool
	TrafficLists           *trafficlists.Manager
	Directory              string
	Auth                   *Auth
	Model                  coreconfig.Model
	Runtime                Runtime
	Router                 *RouterResources
	Subscriptions          *SubscriptionResources
	Validate               func(context.Context, coreconfig.Model) error
	Origin                 string
	Clients                []netip.Prefix
}
type draft struct {
	Version      int              `json:"version"`
	Sequence     uint64           `json:"sequence"`
	BaseRevision uint64           `json:"base_revision"`
	Model        coreconfig.Model `json:"model"`
	Restore      *RestoreSettings `json:"restore,omitempty"`
}
type plan struct {
	ID                 string
	Sequence, Revision uint64
	Fingerprint        string
	Digest             [32]byte
	Expires            time.Time
}
type Event struct {
	Timestamp      time.Time `json:"timestamp"`
	Level          string    `json:"level"`
	Component      string    `json:"component"`
	Event          string    `json:"event"`
	RequestID      string    `json:"request_id"`
	ConfigRevision uint64    `json:"config_revision"`
}
type Server struct {
	poisoned bool
	mu       sync.Mutex
	opts     Options
	dir      string
	draft    *draft
	plan     *plan
	events   []Event
	slots    chan struct{}
	now      func() time.Time
}

func New(o Options) (*Server, error) {
	if o.Auth == nil {
		return nil, errors.New("auth and exact HTTPS origin required")
	}
	origin, e := CanonicalOrigin(o.Origin)
	if e != nil {
		return nil, errors.New("invalid HTTPS origin")
	}
	o.Origin = origin
	dir, e := PrivateDirectory(o.Directory)
	if e != nil {
		return nil, e
	}
	if o.TrafficLists == nil {
		o.TrafficLists, e = trafficlists.New(filepath.Join(dir, "traffic-lists"), subscriptions.Policy{})
		if e != nil {
			return nil, e
		}
	}
	m, e := o.Model.Clone()
	if e != nil {
		return nil, e
	}
	o.Model = m
	if len(o.Clients) == 0 {
		o.Clients = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	}
	// Freeze the validated socket admission policy rather than retaining caller authority.
	o.Clients = append([]netip.Prefix(nil), o.Clients...)
	for _, p := range o.Clients {
		if !p.IsValid() || p.Bits() == 0 {
			return nil, errors.New("invalid API client network")
		}
	}
	s := &Server{opts: o, dir: dir, slots: make(chan struct{}, 8), now: time.Now, events: []Event{}}
	raw, e := privateRead(filepath.Join(dir, "draft.json"), 4<<20)
	if e == nil {
		var d draft
		if decode(raw, &d) != nil || d.Version != 1 || d.Sequence == 0 || d.Model.Validate() != nil {
			return nil, errors.New("invalid durable draft")
		}
		s.draft = &d
	} else if !os.IsNotExist(e) {
		return nil, errors.New("durable draft unavailable")
	}
	if e := s.validateRestoreSettings(func() *RestoreSettings {
		if s.draft != nil {
			return s.draft.Restore
		}
		return nil
	}()); e != nil {
		return nil, e
	}
	if e := s.recoverRestoreSettings(); e != nil {
		return nil, e
	}
	return s, nil
}
func decode(raw []byte, v any) error {
	if uniqueKeys(raw) != nil {
		return errors.New("ambiguous JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid request")
	}
	return nil
}
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return nil, errors.New("JSON required")
	}
	return io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func reject(w http.ResponseWriter, status int, code string) {
	reply(w, status, map[string]string{"error": code})
}
func (s *Server) view() RuntimeView {
	if s.opts.Runtime == nil {
		return RuntimeView{}
	}
	return s.opts.Runtime.View()
}
func (s *Server) model() (coreconfig.Model, error) {
	if s.opts.Runtime != nil {
		return s.opts.Runtime.Model()
	}
	return s.opts.Model.Clone()
}
func (s *Server) validate(ctx context.Context, rev uint64, m coreconfig.Model) error {
	if s.opts.Runtime != nil {
		return s.opts.Runtime.Validate(ctx, rev, m)
	}
	if s.opts.Validate == nil {
		return errors.New("validator unavailable")
	}
	return s.opts.Validate(ctx, m)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	id := randomToken()
	w.Header().Set("X-Request-ID", id)
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	addr, err := netip.ParseAddr(host)
	allowed := false
	if e == nil && err == nil {
		for _, p := range s.opts.Clients {
			allowed = allowed || p.Contains(addr.Unmap())
		}
	}
	if !allowed {
		reject(w, 403, "client_denied")
		return
	}
	if r.TLS == nil || r.Host != strings.TrimPrefix(s.opts.Origin, "https://") || r.URL.RawQuery != "" || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != s.opts.Origin) {
		reject(w, 403, "origin_denied")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		reject(w, 503, "busy")
		return
	}
	if webui.Serve(w, r) {
		return
	}
	if r.URL.Path == "/api/v1/health/live" && r.Method == "GET" {
		reply(w, 200, map[string]bool{"live": true})
		return
	}
	// Only presentation settings are public, so the login page can use them
	// without retaining authentication or operator settings in browser storage.
	if r.URL.Path == "/api/v1/appearance" && r.Method == "GET" {
		s.mu.Lock()
		defer s.mu.Unlock()
		p, e := s.preferences()
		if e != nil {
			reject(w, 503, "preferences_unavailable")
			return
		}
		reply(w, 200, p.Appearance())
		return
	}
	if r.URL.Path == "/api/v1/auth/login" && r.Method == "POST" {
		raw, e := readBody(w, r, 2048)
		var input struct {
			Password string `json:"password"`
		}
		if e != nil || decode(raw, &input) != nil {
			reject(w, 400, "invalid_request")
			return
		}
		token, status := s.opts.Auth.Login(input.Password)
		if status != 200 {
			reject(w, status, "login_denied")
			return
		}
		reply(w, 200, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 1800})
		return
	}
	auth := r.Header.Get("Authorization")
	token := strings.TrimPrefix(auth, "Bearer ")
	if token == auth || !s.opts.Auth.Valid(token) {
		reject(w, 401, "unauthorized")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == "GET" {
		s.get(w, r)
		return
	}
	if r.Method == "POST" {
		s.post(w, r, token, id)
		return
	}
	reject(w, 405, "method_not_allowed")
}
func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	if s.recoverRestoreSettings() != nil {
		reject(w, 503, "restore_settings_pending")
		return
	}
	if s.backupGet(w, r) {
		return
	}
	if s.networkGet(w, r) {
		return
	}
	if s.scheduleGet(w, r) {
		return
	}
	if s.systemInfoGet(w, r) {
		return
	}
	v := s.view()
	if r.URL.Path == "/api/v1/health/ready" {
		status := 200
		if !v.Ready {
			status = 503
		}
		reply(w, status, map[string]bool{"ready": v.Ready})
		return
	}
	if r.URL.Path == "/api/v1/openapi.json" {
		reply(w, 200, OpenAPI())
		return
	}
	if r.URL.Path == "/api/v1/diagnostics/bundle" {
		s.downloadBundle(w, r)
		return
	}
	if r.URL.Path == "/api/v1/logs" {
		reply(w, 200, s.logEvents())
		return
	}
	if r.URL.Path == "/api/v1/routeros" {
		if s.opts.Router == nil {
			reject(w, 501, "adapter_not_connected")
			return
		}
		snapshot, e := s.opts.Router.Snapshot(r.Context())
		if e != nil {
			reject(w, 503, "routeros_unavailable")
			return
		}
		reply(w, 200, snapshot)
		return
	}
	if r.URL.Path == "/api/v1/subscriptions" {
		if s.opts.Subscriptions == nil {
			reject(w, 501, "adapter_not_connected")
			return
		}
		result, e := s.opts.Subscriptions.List()
		if e != nil {
			reject(w, 503, "subscriptions_unavailable")
			return
		}
		reply(w, 200, result)
		return
	}
	m, e := s.model()
	if e != nil {
		reject(w, 503, "model_unavailable")
		return
	}
	switch r.URL.Path {
	case "/api/v1/engine":
		if s.opts.Engine == nil {
			reject(w, 501, "engine_not_connected")
			return
		}
		state, err := s.engineState(r.Context())
		if err != nil {
			reject(w, 503, "engine_unavailable")
			return
		}
		reply(w, 200, state)
	case "/api/v1/traffic-lists/catalog":
		reply(w, 200, trafficlists.Catalog())
	case "/api/v1/traffic-lists":
		views, err := s.opts.TrafficLists.Views()
		if err != nil {
			reject(w, 503, "list_state_invalid")
			return
		}
		reply(w, 200, views)
	case "/api/v1/system":
		reply(w, 200, map[string]any{"api_version": "v1", "core_schema": 2, "runtime_connected": s.opts.Runtime != nil, "status": v, "ipv6_fakeip": false, "engine_connected": s.opts.Engine != nil, "runtime_simulated": s.opts.SimulatedRuntime, "subscriptions_simulated": s.opts.SimulatedSubscriptions})
	case "/api/v1/config":
		reply(w, 200, map[string]any{"revision": v.Revision, "model": m.Preview(), "policy": policyPreview(m)})
	case "/api/v1/proxies":
		reply(w, 200, map[string]any{"endpoints": m.Preview().Endpoints, "wireguard": m.Preview().WireGuard})
	case "/api/v1/groups":
		reply(w, 200, m.Preview().Groups)
	case "/api/v1/rules":
		reply(w, 200, map[string]any{"rules": m.OrderedRules(), "services": m.Services})
	case "/api/v1/devices":
		reply(w, 200, map[string]any{"source_direct": m.SourceDirect, "source_proxy": m.SourceProxy})
	case "/api/v1/dns":
		reply(w, 200, map[string]any{"bootstrap": m.DNS.Bootstrap, "fakeip_range": m.DNS.FakeIPRange, "selected_domains": m.DNS.SelectedDomains, "ipv6_fakeip": false})
	case "/api/v1/diagnostics":
		reply(w, 200, map[string]any{"status": v, "model": m.Preview(), "events": s.logEvents(), "runtime_connected": s.opts.Runtime != nil})
	case "/api/v1/config/draft":
		if s.draft == nil {
			reject(w, 404, "draft_absent")
		} else {
			reply(w, 200, map[string]any{"draft_revision": s.draft.Sequence, "base_revision": s.draft.BaseRevision, "model": s.draft.Model.Preview(), "policy": policyPreview(s.draft.Model)})
		}
	default:
		reject(w, 404, "not_found")
	}
}
func (s *Server) saveDraft(m coreconfig.Model) error {
	return s.saveDraftWithRestore(m, nil)
}
func (s *Server) event(code, id string) {
	s.events = append(s.events, Event{s.now().UTC(), "info", "api", code, id, s.view().Revision})
	if len(s.events) > 128 {
		s.events = s.events[len(s.events)-128:]
	}
}
func (s *Server) post(w http.ResponseWriter, r *http.Request, token, id string) {
	if r.URL.Path == "/api/v1/auth/logout" {
		s.opts.Auth.Logout(token)
		reply(w, 200, map[string]bool{"logged_out": true})
		return
	}
	if s.poisoned {
		reject(w, 503, "persistence_requires_reopen")
		return
	}
	raw, e := readBody(w, r, 4<<20)
	if e != nil {
		reject(w, 400, "invalid_request")
		return
	}
	if s.sectionsPost(w, r, raw, id) || s.enginePost(w, r, raw, id) || s.trafficListsPost(w, r, raw, id) || s.backupPost(w, r, raw, id) || s.subscriptionWorkflow(w, r, raw, id) || s.policyWorkflow(w, r, raw, id) || s.diagnosticsPost(w, r, raw, id) || s.schedulePost(w, r, raw, id) || s.nodeProbePost(w, r, raw, id) {
		return
	}
	switch r.URL.Path {
	case "/api/v1/subscriptions":
		if s.opts.Subscriptions == nil {
			reject(w, 501, "adapter_not_connected")
			return
		}
		var spec subscriptions.Spec
		if decode(raw, &spec) != nil || validateSpec(spec) != nil {
			reject(w, 400, "invalid_subscription")
			return
		}
		if s.opts.Subscriptions.Configure(spec) != nil {
			reject(w, 503, "subscription_persistence_failed")
			return
		}
		s.event("subscription_configured", id)
		reply(w, 200, map[string]string{"id": spec.ID})
	case "/api/v1/subscriptions/inspect":
		if s.opts.Subscriptions == nil {
			reject(w, 501, "adapter_not_connected")
			return
		}
		var input struct {
			ID     string `json:"id"`
			Offset int    `json:"offset"`
			Limit  int    `json:"limit"`
		}
		if decode(raw, &input) != nil || !subscriptionID.MatchString(input.ID) || input.Offset < 0 || input.Limit < 1 || input.Limit > 128 {
			reject(w, 400, "invalid_request")
			return
		}
		result, e := s.opts.Subscriptions.Inspect(input.ID, input.Offset, input.Limit)
		if e != nil {
			reject(w, 503, "subscription_page_unavailable")
			return
		}
		reply(w, 200, result)
	case "/api/v1/subscriptions/refresh":
		if s.opts.Subscriptions == nil {
			reject(w, 501, "adapter_not_connected")
			return
		}
		var input struct {
			ID string `json:"id"`
		}
		if decode(raw, &input) != nil || !subscriptionID.MatchString(input.ID) {
			reject(w, 400, "invalid_request")
			return
		}
		result, e := s.opts.Subscriptions.Refresh(r.Context(), input.ID)
		if e != nil {
			s.event("subscription_refresh_failed", id)
			reply(w, 503, map[string]any{"error": "subscription_refresh_failed", "subscription": result})
			return
		}
		s.event("subscription_refreshed", id)
		reply(w, 200, result)
	case "/api/v1/system/recover":
		var input struct{}
		if decode(raw, &input) != nil {
			reject(w, 400, "invalid_request")
			return
		}
		host, ok := s.opts.Runtime.(interface{ Recover(context.Context) error })
		if !ok {
			reject(w, 503, "runtime_not_connected")
			return
		}
		if host.Recover(r.Context()) != nil {
			s.event("recovery_failed", id)
			reject(w, 503, "recovery_failed")
			return
		}
		if s.recoverRestoreSettings() != nil {
			reject(w, 503, "restore_settings_pending")
			return
		}
		s.event("recovered", id)
		reply(w, 200, s.view())
	case "/api/v1/config/draft":
		m, e := coreconfig.Decode(raw)
		if e != nil {
			reject(w, 400, "invalid_model")
			return
		}
		if s.saveDraft(m) != nil {
			reject(w, 503, "draft_persistence_failed")
			return
		}
		s.event("draft_saved", id)
		reply(w, 200, map[string]uint64{"draft_revision": s.draft.Sequence, "base_revision": s.draft.BaseRevision})
	case "/api/v1/config/validate", "/api/v1/config/plan":
		var input struct {
			DraftRevision uint64 `json:"draft_revision"`
		}
		if decode(raw, &input) != nil {
			reject(w, 400, "invalid_request")
			return
		}
		if s.draft == nil || s.draft.Sequence != input.DraftRevision || s.draft.BaseRevision != s.view().Revision || s.view().Pending {
			reject(w, 409, "stale_draft")
			return
		}
		if s.validateRestoreSettings(s.draft.Restore) != nil {
			reject(w, 409, "restore_metadata_changed")
			return
		}
		if s.validate(r.Context(), s.draft.BaseRevision, s.draft.Model) != nil {
			reject(w, 422, "validation_failed")
			return
		}
		if r.URL.Path == "/api/v1/config/validate" {
			reply(w, 200, map[string]bool{"valid": true})
			return
		}
		current, e := s.model()
		if e != nil {
			reject(w, 503, "model_unavailable")
			return
		}
		key := randomToken()
		if key == "" {
			reject(w, 503, "plan_unavailable")
			return
		}
		b, _ := json.Marshal(s.draft.Model)
		fingerprint := ""
		if runtime, ok := s.opts.Runtime.(PreparedRuntime); ok {
			var err error
			fingerprint, err = runtime.CandidateFingerprint(r.Context(), s.draft.BaseRevision, s.draft.Model)
			if err != nil || len(fingerprint) != 64 {
				reject(w, 422, "candidate_unavailable")
				return
			}
		} else if s.opts.Runtime != nil && len(s.draft.Model.RuleSets) > 0 {
			reject(w, 422, "prepared_runtime_required")
			return
		}
		s.plan = &plan{ID: key, Sequence: s.draft.Sequence, Revision: s.draft.BaseRevision, Digest: sha256.Sum256(b), Fingerprint: fingerprint, Expires: s.now().Add(5 * time.Minute)}
		reply(w, 200, map[string]any{"plan_id": key, "draft_revision": s.draft.Sequence, "base_revision": s.draft.BaseRevision, "expires_at": s.plan.Expires, "model": s.draft.Model.Preview(), "policy": policyPreview(s.draft.Model), "apply_available": s.opts.Runtime != nil, "changed_sections": planChanges(current, s.draft.Model, s.draft.Restore)})
	case "/api/v1/config/apply":
		var input struct {
			PlanID string `json:"plan_id"`
		}
		if decode(raw, &input) != nil {
			reject(w, 400, "invalid_request")
			return
		}
		p := s.plan
		if p == nil || p.ID != input.PlanID || !p.Expires.After(s.now()) || s.draft == nil || p.Sequence != s.draft.Sequence || p.Revision != s.view().Revision || s.view().Pending {
			reject(w, 409, "stale_plan")
			return
		}
		b, _ := json.Marshal(s.draft.Model)
		if sha256.Sum256(b) != p.Digest {
			reject(w, 409, "stale_plan")
			return
		}
		if s.opts.Runtime == nil {
			reject(w, 503, "runtime_not_connected")
			return
		}
		if s.validateRestoreSettings(s.draft.Restore) != nil {
			reject(w, 409, "restore_metadata_changed")
			return
		}
		s.plan = nil
		var applyErr error
		if runtime, ok := s.opts.Runtime.(PreparedRuntime); ok {
			applyErr = runtime.ApplyPrepared(r.Context(), p.Revision, s.draft.Model, p.Fingerprint)
		} else {
			applyErr = s.opts.Runtime.Apply(r.Context(), p.Revision, s.draft.Model)
		}
		if errors.Is(applyErr, coreactivation.ErrCandidateChanged) {
			s.event("candidate_changed", id)
			reject(w, 409, "candidate_changed")
			return
		}
		if applyErr != nil {
			s.event("apply_failed", id)
			reject(w, 503, "apply_failed")
			return
		}
		if s.recoverRestoreSettings() != nil {
			s.event("restore_settings_pending", id)
			reject(w, 503, "restore_settings_pending")
			return
		}
		s.event("apply_committed", id)
		reply(w, 200, s.view())
	default:
		reject(w, 404, "not_found")
	}
}
