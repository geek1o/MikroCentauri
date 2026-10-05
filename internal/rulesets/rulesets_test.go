package rulesets

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestParseRejectsUnknownPredicates(t *testing.T) {
	for _, b := range []string{`{"version":5,"rules":[{"geosite":["x"]}]}`, `{"version":5,"rules":[{}]}`, `{"version":6,"rules":[{"domain":["x.example"]}]}`, `{"version":5,"version":5,"rules":[]}`, `{"version":5,"rules":[{"domain_suffix":["*.example"]}]}`} {
		if _, e := ParseSource([]byte(b)); e == nil {
			t.Fatal("unsafe source accepted")
		}
	}
}
func TestCompiledCandidateLKGAndTLSDownload(t *testing.T) {
	binary := os.Getenv("SING_BOX_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_BINARY")
	}
	dir := t.TempDir()
	dir, _ = filepath.EvalSymlinks(dir)
	dir = filepath.Join(dir, "sets")
	m, e := New(dir, binary, Policy{})
	if e != nil {
		t.Fatal(e)
	}
	good := []byte(`{"version":5,"rules":[{"domain":["selected.example"]}]}`)
	a, e := m.Import(context.Background(), "example", "source", good)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Validate(); e != nil {
		t.Fatal(e)
	}
	old, e := m.Load("example")
	if e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{[]byte(`{"version":5,"rules":[]}`), []byte(`{"version":5,"rules":[{"domain_regex":[".*"]}]}`), []byte("SRS\x05bad")} {
		format := "source"
		if string(bad[:3]) == "SRS" {
			format = "binary"
		}
		if _, e = m.Import(context.Background(), "example", format, bad); e == nil {
			t.Fatal("bad candidate accepted")
		}
		now, e := m.Load("example")
		if e != nil || now != old {
			t.Fatal("bad candidate changed LKG")
		}
	}
	b, e := os.ReadFile(a.Path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Import(context.Background(), "binary", "binary", b); e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(good) }))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	remoteDir := filepath.Join(dir, "remote")
	trusted, e := New(remoteDir, binary, Policy{AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, RootCAs: roots})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = trusted.Refresh(context.Background(), Spec{ID: "remote", URL: server.URL, Format: "source"}); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Refresh(context.Background(), Spec{ID: "blocked", URL: server.URL, Format: "source"}); e == nil {
		t.Fatal("private remote address allowed")
	}
	if _, e = trusted.Refresh(context.Background(), Spec{ID: "plain", URL: "http://127.0.0.1/", Format: "source"}); e == nil {
		t.Fatal("unencrypted URL allowed")
	}
	if e = os.WriteFile(a.Path, []byte("SRS\x05tampered"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Load("example"); e == nil {
		t.Fatal("tampered artifact accepted")
	}
}
