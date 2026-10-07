//go:build linux || darwin

package routeros

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func orderedFirewall(t *testing.T) (*mockRouter, *LabController, *Client) {
	t.Helper()
	makeRule := func(id, comment string) Object {
		return Object{Path: "ip/firewall/filter", ID: id, Fields: map[string]string{"comment": comment, "chain": "forward", "action": "accept", "disabled": "true"}}
	}
	m := &mockRouter{objects: []Object{makeRule("*U", "user first"), makeRule("*A", "mikrocentauri:lab:filter:a"), makeRule("*B", "mikrocentauri:lab:filter:b"), makeRule("*Z", "user last")}}
	wrapper := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "PUT" {
				h.ServeHTTP(w, r)
				return
			}
			var f map[string]string
			if json.NewDecoder(r.Body).Decode(&f) != nil {
				w.WriteHeader(400)
				return
			}
			anchor := f["place-before"]
			delete(f, "place-before")
			b, _ := json.Marshal(f)
			r.Body = io.NopCloser(bytes.NewReader(b))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code == 200 && anchor != "" {
				m.mu.Lock()
				last := m.objects[len(m.objects)-1]
				m.objects = m.objects[:len(m.objects)-1]
				pos := -1
				for i, o := range m.objects {
					if o.ID == anchor {
						pos = i
						break
					}
				}
				if pos < 0 {
					m.mu.Unlock()
					w.WriteHeader(400)
					return
				}
				m.objects = append(m.objects, Object{})
				copy(m.objects[pos+1:], m.objects[pos:])
				m.objects[pos] = last
				m.mu.Unlock()
			}
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			w.Write(rec.Body.Bytes())
		})
	}
	ctrl, c, _ := newControllerFixture(t, m, wrapper)
	return m, ctrl, c
}
func firewallComments(m *mockRouter) []string {
	r := []string{}
	for _, o := range m.objects {
		r = append(r, o.Fields["comment"])
	}
	return r
}
func TestOrderedFirewallMultipleDeleteCrashRestoresExactOrder(t *testing.T) {
	m, ctrl, c := orderedFirewall(t)
	before := firewallComments(m)
	count := 0
	ctrl.fault = func(b string) error {
		if b == "after-mutation" {
			count++
			if count == 2 {
				return errors.New("crash")
			}
		}
		return nil
	}
	if ctrl.Apply(context.Background(), controllerPlan(t, c, nil)) == nil {
		t.Fatal("missing crash")
	}
	if len(m.objects) != 2 {
		t.Fatal("deletions not reached")
	}
	if e := ctrl.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, firewallComments(m)) {
		t.Fatalf("wrong restored order %v", firewallComments(m))
	}
	if m.objects[0].ID != "*U" || m.objects[3].ID != "*Z" {
		t.Fatal("user anchors replaced")
	}
	if e := ctrl.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
}
func TestOrderedFirewallRecoveryRefusesChangedAnchorOrOrder(t *testing.T) {
	for _, edit := range []string{"config", "order", "insert", "remove"} {
		t.Run(edit, func(t *testing.T) {
			m, ctrl, c := orderedFirewall(t)
			ctrl.fault = func(b string) error {
				if b == "after-mutation" {
					return errors.New("crash")
				}
				return nil
			}
			if ctrl.Apply(context.Background(), controllerPlan(t, c, nil)) == nil {
				t.Fatal("missing crash")
			}
			switch edit {
			case "config":
				m.objects[0].Fields["action"] = "drop"
			case "order":
				m.objects[0], m.objects[1] = m.objects[1], m.objects[0]
			case "insert":
				m.objects = append(m.objects, Object{Path: "ip/firewall/filter", ID: "*NEW", Fields: map[string]string{"comment": "new user", "disabled": "true"}})
			case "remove":
				m.objects = m.objects[1:]
			}
			mutations := m.mutations
			if ctrl.Recover(context.Background()) == nil {
				t.Fatal("accepted anchor drift")
			}
			if mutations != m.mutations {
				t.Fatal("mutated drifted firewall")
			}
		})
	}
}
func TestOrderedFirewallLastRowRestoresAtVerifiedEnd(t *testing.T) {
	m, ctrl, c := orderedFirewall(t)
	m.objects = m.objects[:2]
	before := firewallComments(m)
	ctrl.fault = func(b string) error {
		if b == "after-mutation" {
			return errors.New("crash")
		}
		return nil
	}
	if ctrl.Apply(context.Background(), controllerPlan(t, c, nil)) == nil {
		t.Fatal("missing crash")
	}
	if e := ctrl.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, firewallComments(m)) {
		t.Fatal("end not restored")
	}
}
func TestOrderedFirewallRecoveryRejectsRecreatedWrongPosition(t *testing.T) {
	m, ctrl, c := orderedFirewall(t)
	original := m.objects[1]
	ctrl.fault = func(b string) error {
		if b == "after-mutation" {
			return errors.New("crash")
		}
		return nil
	}
	if ctrl.Apply(context.Background(), controllerPlan(t, c, nil)) == nil {
		t.Fatal("missing crash")
	}
	original.ID = "*CLONE"
	m.objects = append(m.objects, original)
	if ctrl.Recover(context.Background()) == nil {
		t.Fatal("accepted incorrect restored placement")
	}
}

type placementLostReply struct {
	base    http.RoundTripper
	dropped bool
}

func (r *placementLostReply) RoundTrip(req *http.Request) (*http.Response, error) {
	res, e := r.base.RoundTrip(req)
	if e == nil && req.Method == "PUT" && !r.dropped {
		r.dropped = true
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		return nil, errors.New("lost undo reply")
	}
	return res, e
}
func TestOrderedFirewallLostRollbackReplyDoesNotDuplicate(t *testing.T) {
	m, ctrl, c := orderedFirewall(t)
	before := firewallComments(m)
	ctrl.fault = func(b string) error {
		if b == "after-mutation" {
			return errors.New("crash")
		}
		return nil
	}
	if ctrl.Apply(context.Background(), controllerPlan(t, c, nil)) == nil {
		t.Fatal("missing crash")
	}
	transport := c.http.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	c.http.Transport = &placementLostReply{base: transport}
	if e := ctrl.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, firewallComments(m)) {
		t.Fatal("lost undo reply changed order")
	}
	if e := ctrl.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(m.objects) != 4 {
		t.Fatal("duplicated undo")
	}
}
func TestOrderedFirewallMalformedPlacementJournalRefused(t *testing.T) {
	for _, corrupt := range []string{"missing", "index", "digest", "duplicate"} {
		t.Run(corrupt, func(t *testing.T) {
			m, ctrl, c := orderedFirewall(t)
			ctrl.fault = func(b string) error {
				if b == "after-mutation" {
					return errors.New("crash")
				}
				return nil
			}
			if ctrl.Apply(context.Background(), controllerPlan(t, c, nil)) == nil {
				t.Fatal("missing crash")
			}
			j, e := ctrl.read()
			if e != nil {
				t.Fatal(e)
			}
			p := j.Changes[0].Placement
			switch corrupt {
			case "missing":
				j.Changes[0].Placement = nil
			case "index":
				p.Index = -1
			case "digest":
				p.Rows[p.Index].Digest = "bad"
			case "duplicate":
				p.Rows[0].ID = p.Rows[1].ID
			}
			if e := ctrl.persist(*j); e != nil {
				t.Fatal(e)
			}
			mutations := m.mutations
			if ctrl.Recover(context.Background()) == nil {
				t.Fatal("accepted corrupt placement journal")
			}
			if m.mutations != mutations {
				t.Fatal("corrupt journal mutated router")
			}
		})
	}
}

func TestDesiredPlacementCreateAndStaleOrderRefusal(t *testing.T) {
	m, c, client := orderedFirewall(t)
	desired := []Object{{Path: "ip/firewall/filter", PlaceBefore: "*Z", Fields: map[string]string{"comment": "mikrocentauri:lab:filter:new", "disabled": "true", "chain": "forward", "action": "accept"}}}
	// Keep existing owned rows unchanged in the complete desired set.
	for _, row := range m.objects {
		if Owned("lab", row) {
			o := controllerProjection(row)
			o.ID = ""
			desired = append(desired, o)
		}
	}
	if err := c.Apply(context.Background(), controllerPlan(t, client, desired)); err != nil {
		t.Fatal(err)
	}
	if m.objects[len(m.objects)-2].Fields["comment"] != "mikrocentauri:lab:filter:new" {
		t.Fatal("incorrect initial placement")
	}
	if p := controllerPlan(t, client, desired); len(p.Changes) != 0 {
		t.Fatal("not idempotent")
	}
	m.objects[len(m.objects)-1], m.objects[len(m.objects)-2] = m.objects[len(m.objects)-2], m.objects[len(m.objects)-1]
	rows, err := client.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	before := m.mutations
	if _, err = Plan("lab", rows, desired); err == nil {
		t.Fatal("accepted stale placement")
	}
	if m.mutations != before {
		t.Fatal("touched user placement")
	}
}
