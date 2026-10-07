package routeros

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAppInstallationSeparateReadOnlyProjection(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		path := strings.TrimPrefix(r.URL.Path, "/rest/")
		if r.Method != "GET" {
			t.Error("installation sent mutation", r.Method)
		}
		fields, ok := appInstallationFields[path]
		if !ok || r.URL.Query().Get(".proplist") != strings.Join(fields, ",") {
			t.Error("unbounded installation projection", r.URL.String())
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != "fixture" || password != "protected-fixture" {
			t.Error("HTTPS connection identity not reused")
		}
		if path == "system/resource" {
			json.NewEncoder(w).Encode(map[string]string{"version": "7.24.5 (stable)", "architecture-name": "x86_64", "board-name": "CHR fixture"})
		} else {
			json.NewEncoder(w).Encode([]map[string]string{{".id": "*1", "name": "fixture"}})
		}
	}))
	defer srv.Close()
	client, e := NewLabClient(srv.URL+"/rest", "fixture", "protected-fixture", srv.Client())
	if e != nil {
		t.Fatal(e)
	}
	view, e := client.InspectAppInstallation(context.Background())
	if e != nil || requests != 4 || len(view.Apps) != 1 || view.Resource["version"] != "7.24.5 (stable)" {
		t.Fatal("bad read-only installation inventory", view, e)
	}
	for _, path := range []string{"app", "container", "interface/veth"} {
		if _, e := client.request(context.Background(), "PATCH", path, "*1", map[string]string{"privileged": "true"}); e == nil {
			t.Fatal("installation widened controller mutations", path)
		}
	}
	if requests != 4 {
		t.Fatal("rejected mutations contacted server")
	}
	if _, e := client.appInstallationGET(context.Background(), "container/envs"); e == nil {
		t.Fatal("secret resource accepted")
	}
}

func TestAppInstallationMalformedUnavailableAndSecretProjectionsDenied(t *testing.T) {
	for _, data := range []string{`{"version":"a","version":"b"}`, `{"version":7}`, `{"version":null}`, `{"yaml":"private-secret"}`, `{"version":"7.24.5"} {}`, `[]`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(data)) }))
		client, e := NewLabClient(srv.URL+"/rest", "fixture", "private-secret", srv.Client())
		if e != nil {
			t.Fatal(e)
		}
		if _, e := client.InspectAppInstallation(context.Background()); e == nil || strings.Contains(e.Error(), "private-secret") {
			t.Fatal("unsafe projection escaped", e)
		}
		srv.Close()
	}
	for _, status := range []int{301, 401, 404, 503} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "http://127.0.0.1:1/private-secret")
			w.WriteHeader(status)
			w.Write([]byte("private-secret"))
		}))
		client, e := NewLabClient(srv.URL+"/rest", "fixture", "private-secret", srv.Client())
		if e != nil {
			t.Fatal(e)
		}
		if _, e := client.InspectAppInstallation(context.Background()); e == nil || strings.Contains(e.Error(), "private-secret") {
			t.Fatal("failed read accepted or leaked body", e)
		}
		srv.Close()
	}
}
