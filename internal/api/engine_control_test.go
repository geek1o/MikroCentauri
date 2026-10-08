package api

import (
	"context"
	"errors"
	"mikrocentauri.local/core/internal/enginecontrol"
	"testing"
	"time"
)

type controlFixture struct {
	proxies map[string]enginecontrol.Proxy
	calls   int
	fail    bool
}

func (c *controlFixture) EngineSnapshot(context.Context) (map[string]enginecontrol.Proxy, error) {
	return c.proxies, nil
}
func (c *controlFixture) EngineSelect(_ context.Context, g, n string, _ uint64) error {
	c.calls++
	if c.fail {
		return errors.New("private controller secret")
	}
	p := c.proxies[g]
	p.Now = n
	c.proxies[g] = p
	return nil
}
func (c *controlFixture) EngineDelay(context.Context, string) (int64, error) { return 25, nil }
func TestLiveSelectorRevisionMembershipAndNoDraftMutation(t *testing.T) {
	s, _, token := setup(t, nil)
	m, e := s.model()
	if e != nil || len(m.Groups) == 0 {
		t.Fatal(e)
	}
	g := m.Groups[0]
	c := &controlFixture{proxies: map[string]enginecontrol.Proxy{g.ID: {Type: "Selector", Now: g.Members[0], All: g.Members}}}
	for _, n := range g.Members {
		c.proxies[n] = enginecontrol.Proxy{Type: "Trojan", History: []enginecontrol.History{{Time: time.Now(), Delay: 10}}}
	}
	s.opts.Engine = c
	rev := s.view().Revision
	w := call(s, "POST", "/api/v1/engine/select", token, EngineSelectRequest{Group: g.ID, Node: g.Members[0], Revision: rev})
	if w.Code != 200 || c.calls != 1 || s.draft != nil || s.view().Revision != rev {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, in := range []EngineSelectRequest{{Group: g.ID, Node: g.Members[0], Revision: rev + 1}, {Group: g.ID, Node: "missing", Revision: rev}, {Group: "missing", Node: g.Members[0], Revision: rev}} {
		w = call(s, "POST", "/api/v1/engine/select", token, in)
		if w.Code != 400 && w.Code != 409 {
			t.Fatal(w.Code)
		}
	}
	if c.calls != 1 {
		t.Fatal("invalid selection reached engine")
	}
	c.fail = true
	w = call(s, "POST", "/api/v1/engine/select", token, EngineSelectRequest{Group: g.ID, Node: g.Members[0], Revision: rev})
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
}
