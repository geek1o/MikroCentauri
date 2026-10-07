package main

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func privateFixture(t *testing.T, data string) string {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, "private.json")
	if e = os.WriteFile(p, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestPrivateInputs(t *testing.T) {
	for _, s := range []string{`{"base_url":"a","base_url":"b"}`, `{"extra":"x"}`, `{} {}`, `{"password":1}`} {
		var c routerConnection
		if e := privateJSON(privateFixture(t, s), &c, 64<<10); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	p := privateFixture(t, `{"username":"u"}`)
	var c routerConnection
	if e := os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if e := privateJSON(p, &c, 64<<10); e == nil {
		t.Fatal("public file accepted")
	}
	if e := os.Chmod(p, 0600); e != nil {
		t.Fatal(e)
	}
	link := p + "-link"
	if e := os.Symlink(p, link); e != nil {
		t.Fatal(e)
	}
	if e := privateJSON(link, &c, 64<<10); e == nil {
		t.Fatal("symlink accepted")
	}
	if e := privateJSON(p, &c, 2); e == nil {
		t.Fatal("oversize accepted")
	}
}
func TestConnectionTrustAndTransport(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) }))
	defer srv.Close()
	ca := filepath.Join(filepath.Dir(privateFixture(t, `{}`)), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0644); e != nil {
		t.Fatal(e)
	}
	data := `{"base_url":"` + srv.URL + `/rest","username":"fixture","password":"FixtureOnly","ca_file":"` + ca + `"}`
	_, url, e := connectRouter(privateFixture(t, data))
	if e != nil || url != srv.URL+"/rest" {
		t.Fatal(url, e)
	}
	for _, data := range []string{
		`{"base_url":"http://127.0.0.1/rest","username":"u","password":"p"}`,
		`{"base_url":"https://user:secret@127.0.0.1/rest","username":"u","password":"p"}`,
		`{"base_url":"https://127.0.0.1/rest","username":"u"}`,
	} {
		if _, _, e := connectRouter(privateFixture(t, data)); e == nil {
			t.Fatal("invalid connection accepted")
		}
	}
}

func TestRouterControlDoesNotInheritDefaultProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) }))
	defer srv.Close()
	original := http.DefaultTransport
	inherited := original.(*http.Transport).Clone()
	proxyCalls := 0
	inherited.Proxy = func(r *http.Request) (*url.URL, error) { proxyCalls++; return nil, nil }
	http.DefaultTransport = inherited
	defer func() { http.DefaultTransport = original; inherited.CloseIdleConnections() }()
	ca := filepath.Join(filepath.Dir(privateFixture(t, `{}`)), "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0644); e != nil {
		t.Fatal(e)
	}
	client, _, e := connectRouter(privateFixture(t, `{"base_url":"`+srv.URL+`/rest","username":"fixture","password":"FixtureOnly","ca_file":"`+ca+`"}`))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = client.Discover(context.Background()); e != nil {
		t.Fatal(e)
	}
	if proxyCalls != 0 {
		t.Fatal("control connection inherited an unreviewed proxy")
	}
}
