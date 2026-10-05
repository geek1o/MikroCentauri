package subscriptions

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const node = "trojan://super-secret@example.com:443#first"

func privateDir(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, 0700)
	return p
}
func TestURIList(t *testing.T) {
	for _, s := range []string{node, base64.StdEncoding.EncodeToString([]byte(node + "\n" + node))} {
		n, e := Parse([]byte(s))
		if e != nil || len(n) != 1 {
			t.Fatal(e)
		}
	}
	for _, s := range []string{"", node + "\nbad", "unknown://super-secret@example.com:443"} {
		_, e := Parse([]byte(s))
		if e == nil || strings.Contains(e.Error(), "super-secret") {
			t.Fatal("invalid input or leaked credential")
		}
	}
}
func TestRefreshLKGAndRename(t *testing.T) {
	body := node
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer srv.Close()
	m, e := New(privateDir(t), Policy{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if e != nil {
		t.Fatal(e)
	}
	spec := Spec{ID: "test", URL: srv.URL}
	a, e := m.Refresh(context.Background(), spec)
	if e != nil {
		t.Fatal(e)
	}
	body = strings.Replace(node, "first", "renamed", 1)
	b, e := m.Refresh(context.Background(), spec)
	if e != nil || a.Nodes[0].ID != b.Nodes[0].ID || b.Nodes[0].Name != "renamed" {
		t.Fatal("rename")
	}
	body = ""
	c, e := m.Refresh(context.Background(), spec)
	if e == nil || len(c.Nodes) != 1 || c.Nodes[0].Name != "renamed" || c.LastSuccess != b.LastSuccess || c.Failure == "" {
		t.Fatal("LKG lost")
	}
	loaded, e := m.Load("test")
	if e != nil || loaded.Failure == "" {
		t.Fatal(e)
	}
	spec.Include = "does-not-match"
	body = node
	d, e := m.Refresh(context.Background(), spec)
	if e == nil || d.Nodes[0].Name != "renamed" {
		t.Fatal("filter destroyed LKG")
	}
	st, _ := os.Stat(filepath.Join(m.dir, "test.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("state not private")
	}
}
func TestDefaultSSRFAndRedirect(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.Write([]byte(node)) }))
	defer srv.Close()
	m, _ := New(privateDir(t), Policy{})
	s, e := m.Refresh(context.Background(), Spec{ID: "blocked", URL: srv.URL + "/secret-token"})
	if e == nil || hits != 0 || strings.Contains(e.Error(), "secret-token") || s.Failure == "" {
		t.Fatal("SSRF or redaction")
	}
	for _, ip := range []string{"127.0.0.1", "::1", "169.254.169.254", "10.0.0.1", "172.30.0.1", "100.64.0.1", "::ffff:127.0.0.1", "fe80::1", "198.18.0.1"} {
		if m.allowed(netip.MustParseAddr(ip)) {
			t.Fatal("allowed " + ip)
		}
	}
	if !m.allowed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public blocked")
	}
}
func TestDownloadBoundsAndTimeout(t *testing.T) {
	for _, slow := range []bool{false, true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if slow {
				time.Sleep(80 * time.Millisecond)
			}
			w.Write([]byte(strings.Repeat("x", 256)))
		}))
		m, _ := New(privateDir(t), Policy{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, MaxBytes: 16, Timeout: 10 * time.Millisecond})
		_, e := m.Refresh(context.Background(), Spec{ID: "bounds", URL: srv.URL})
		srv.Close()
		if e == nil {
			t.Fatal("bounds accepted")
		}
	}
}
func TestUnsafeStateAndURL(t *testing.T) {
	m, _ := New(privateDir(t), Policy{})
	os.Symlink("/etc/passwd", filepath.Join(m.dir, "link.json"))
	if _, e := m.Load("link"); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e := m.Load("../secret"); e == nil {
		t.Fatal("traversal")
	}
	for _, u := range []string{"file:///etc/passwd", "http://secret:password@example.com", "http://example.com/#secret"} {
		if _, e := validURL(u); e == nil {
			t.Fatal("unsafe url")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := m.Run(ctx, nil, time.Second); e != context.Canceled {
		t.Fatal(e)
	}
}
func TestPrivateLockAndDuplicateState(t *testing.T) {
	dir := privateDir(t)
	m, _ := New(dir, Policy{})
	other, _ := New(dir, Policy{})
	unlock, e := m.lock()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = other.Load("node"); e == nil {
		t.Fatal("concurrent state accepted")
	}
	unlock()
	os.WriteFile(filepath.Join(dir, "node.json"), []byte(`{"id":"node","id":"node","nodes":[]}`), 0600)
	if _, e = other.Load("node"); e == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestRedirectLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/again", http.StatusFound) }))
	defer srv.Close()
	m, _ := New(privateDir(t), Policy{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, MaxRedirects: 1})
	if _, e := m.Refresh(context.Background(), Spec{ID: "redirect", URL: srv.URL}); e == nil {
		t.Fatal("redirect chain accepted")
	}
}
