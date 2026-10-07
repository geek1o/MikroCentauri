package routeros

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"mikrocentauri.local/core/internal/config"
)

func fixture(t *testing.T) []Object {
	t.Helper()
	b, e := os.ReadFile("../../../lab/configs/hybrid.json")
	if e != nil {
		t.Fatal(e)
	}
	c, e := config.Decode(b)
	if e != nil {
		t.Fatal(e)
	}
	d, e := Desired(c)
	if e != nil {
		t.Fatal(e)
	}
	return d
}
func TestOwnershipAndPlan(t *testing.T) {
	d := fixture(t)
	user := Object{Path: "ip/route", ID: "*A", Fields: map[string]string{"comment": "user route"}}
	malicious := []Object{{Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:lab-other:route:fakeip"}}, {Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:lab:route:fakeip:other"}}, {Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:lab:nat:dns"}}}
	for _, o := range malicious {
		if Owned("lab", o) {
			t.Fatal("loose ownership match")
		}
	}
	p, e := Plan("lab", append(malicious, user), d)
	if e != nil || len(p.Changes) != 3 {
		t.Fatalf("plan %v", e)
	}
	current := []Object{user}
	for i, o := range d {
		o.ID = fmt.Sprintf("*%d", i)
		o.Fields["dynamic"] = "false"
		current = append(current, o)
	}
	p, e = Plan("lab", current, d)
	if e != nil || len(p.Changes) != 0 {
		t.Fatalf("not idempotent: %v", e)
	}
	p, e = Plan("lab", current, nil)
	if e != nil || len(p.Changes) != 3 {
		t.Fatal("cleanup scope")
	}
	for _, c := range p.Changes {
		if c.Before.ID == "*A" {
			t.Fatal("deleted user object")
		}
	}
}

// This models string-valued RouterOS REST responses, independent state and injected mutation failure.
type mockRouter struct {
	mu                      sync.Mutex
	objects                 []Object
	next, mutations, failAt int
}

func (m *mockRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, p, ok := r.BasicAuth(); !ok || u != "lab" || p != "test-password" {
		w.WriteHeader(401)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/rest/"), "/")
	id := ""
	if strings.HasPrefix(parts[len(parts)-1], "*") {
		id = parts[len(parts)-1]
		parts = parts[:len(parts)-1]
	}
	path := strings.Join(parts, "/")
	if r.Method != "GET" {
		m.mutations++
		if m.failAt == m.mutations {
			http.Error(w, "test-password must never leak", 500)
			return
		}
	}
	switch r.Method {
	case "GET":
		rows := []map[string]string{}
		for _, o := range m.objects {
			if o.Path == path {
				row := map[string]string{".id": o.ID}
				for k, v := range o.Fields {
					row[k] = v
				}
				rows = append(rows, row)
			}
		}
		json.NewEncoder(w).Encode(rows)
	case "PUT":
		var f map[string]string
		json.NewDecoder(r.Body).Decode(&f)
		m.next++
		o := Object{Path: path, ID: fmt.Sprintf("*%X", m.next), Fields: f}
		m.objects = append(m.objects, o)
		json.NewEncoder(w).Encode(map[string]string{".id": o.ID})
	case "PATCH", "DELETE":
		for i, o := range m.objects {
			if o.Path == path && o.ID == id {
				if r.Method == "DELETE" {
					m.objects = append(m.objects[:i], m.objects[i+1:]...)
				} else {
					var f map[string]string
					json.NewDecoder(r.Body).Decode(&f)
					for k, v := range f {
						o.Fields[k] = v
					}
				}
				w.WriteHeader(200)
				return
			}
		}
		w.WriteHeader(404)
	default:
		w.WriteHeader(405)
	}
}
func TestRESTIdempotenceRollbackAndStalePlan(t *testing.T) {
	m := &mockRouter{objects: []Object{{Path: "ip/route", ID: "*USER", Fields: map[string]string{"comment": "unrelated"}}}}
	server := httptest.NewServer(m)
	defer server.Close()
	c, e := NewLabClient(server.URL+"/rest", "lab", "test-password", server.Client())
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	d := fixture(t)
	current, e := c.Discover(ctx)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := Plan("lab", current, d)
	m.failAt = 2
	if e = c.ApplyLab(ctx, p); e == nil || strings.Contains(e.Error(), "test-password") {
		t.Fatal("failure missing or secret leak")
	}
	current, e = c.Discover(ctx)
	if e != nil || len(current) != 1 || current[0].ID != "*USER" {
		t.Fatal("rollback did not preserve user state")
	}
	m.failAt = 0
	p, _ = Plan("lab", current, d)
	if e = c.ApplyLab(ctx, p); e != nil {
		t.Fatal(e)
	}
	current, _ = c.Discover(ctx)
	p, _ = Plan("lab", current, d)
	if len(p.Changes) != 0 {
		t.Fatal("second apply not empty")
	}
	// Inject a failure after a successful update; compensate touched fields back to their prior values.
	d2 := fixture(t)
	for i := range d2 {
		d2[i].Fields["disabled"] = "false"
	}
	p, _ = Plan("lab", current, d2)
	m.failAt = m.mutations + 2
	if e = c.ApplyLab(ctx, p); e == nil {
		t.Fatal("injected update failure not detected")
	}
	m.failAt = 0
	after, _ := c.Discover(ctx)
	p, _ = Plan("lab", after, d)
	if len(p.Changes) != 0 {
		t.Fatal("update rollback failed")
	}
	cleanup, _ := Plan("lab", after, nil)
	after[1].Fields["comment"] = "user took ownership" // mock keeps its own fields; explicitly mutate mock to simulate external edits
	m.mu.Lock()
	for i := range m.objects {
		if Owned("lab", m.objects[i]) {
			m.objects[i].Fields["comment"] = "user took ownership"
			break
		}
	}
	m.mu.Unlock()
	count := m.mutations
	if e = c.ApplyLab(ctx, cleanup); e == nil {
		t.Fatal("stale plan accepted")
	}
	if count != m.mutations {
		t.Fatal("stale plan mutated RouterOS")
	}
}
func TestRESTRedirectAndTLS(t *testing.T) {
	if _, e := NewClient("http://router/rest", "u", "p", nil); e == nil {
		t.Fatal("cleartext permitted")
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://example.com/", 302) }))
	defer s.Close()
	c, _ := NewLabClient(s.URL+"/rest", "u", "p", s.Client())
	if _, e := c.Discover(context.Background()); e == nil {
		t.Fatal("management redirect accepted")
	}
}
