package routeros

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func capabilityFixture() map[string]string {
	return map[string]string{
		"system/resource": `[{"version":"7.24.5 (stable)","architecture-name":"x86_64","board-name":"CHR","platform":"MikroTik"}]`,
		"system/package":  `[{"name":"routeros","version":"7.24.5","disabled":"false"},{"name":"container","version":"7.24.5","disabled":"true"}]`,
		"interface":       `[{"name":"ether1","type":"ether","disabled":"false","running":"true"}]`,
		"ip/route":        `[]`, "ip/firewall/nat": `[]`, "ip/firewall/mangle": `[]`, "ip/firewall/filter": `[]`, "tool/netwatch": `[]`, "system/scheduler": `[]`,
	}
}
func capabilityClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	c, e := NewClient(s.URL+"/rest", "fixture-user", "fixture-secret", s.Client())
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestCapabilitiesReadOnlyTLS(t *testing.T) {
	fixture := capabilityFixture()
	var calls atomic.Int32
	c := capabilityClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "GET" {
			t.Errorf("mutation %s", r.Method)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "fixture-user" || pass != "fixture-secret" {
			t.Error("missing authentication")
		}
		path := strings.TrimPrefix(r.URL.Path, "/rest/")
		body, ok := fixture[path]
		if !ok {
			t.Errorf("unexpected path %s", path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	result, e := c.Capabilities(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if !result.VersionSupported || result.Board != "CHR" || len(result.Resources) != 6 || len(result.Packages) != 2 || !result.Packages[1].Disabled || !result.Interfaces[0].Running || calls.Load() != 9 {
		t.Fatalf("unexpected capability result: %#v, calls %d", result, calls.Load())
	}
	if _, e = c.request(context.Background(), "PATCH", "system/resource", "", nil); e == nil {
		t.Fatal("capability discovery widened mutation allowlist")
	}
	if calls.Load() != 9 {
		t.Fatal("forbidden mutation sent request")
	}
}
func TestCapabilitiesUnavailableAndRedacted(t *testing.T) {
	for _, status := range []int{404, 401, 403, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fixture := capabilityFixture()
			c := capabilityClient(t, func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/rest/")
				if path == "tool/netwatch" {
					w.WriteHeader(status)
					_, _ = w.Write([]byte("fixture-secret malicious-device-output"))
					return
				}
				_, _ = w.Write([]byte(fixture[path]))
			})
			result, e := c.Capabilities(context.Background())
			if status == 404 {
				if e != nil || result.Resources["tool/netwatch"] {
					t.Fatalf("404 discovery: %#v %v", result, e)
				}
				return
			}
			if e == nil || strings.Contains(e.Error(), "fixture-secret") || strings.Contains(e.Error(), "malicious") {
				t.Fatalf("unredacted status: %v", e)
			}
		})
	}
}
func TestCapabilitiesRejectMalformedAndMissing(t *testing.T) {
	for _, change := range []struct{ path, body string }{
		{"system/resource", `[]`}, {"system/resource", `[{"version":"7.24.5"},{"version":"7.24.5"}]`},
		{"system/resource", `{"version":"unknown","architecture-name":"x86_64","board-name":"CHR","platform":"MikroTik"}`},
		{"system/resource", `{"version":"7.24.5","architecture-name":{},"board-name":"CHR","platform":"MikroTik"}`},
		{"system/package", `[{"name":"routeros","version":"7.24.5"}]`},
		{"interface", `[{"name":"ether1","type":"ether","disabled":"false","running":"maybe"}]`},
		{"ip/route", `[{"gateway":["secret"]}]`},
		{"ip/route", `[{"comment":"a","comment":"b"}]`},
		{"ip/route", `[] {}`}, {"ip/route", `null`},
	} {
		t.Run(change.path+change.body, func(t *testing.T) {
			fixture := capabilityFixture()
			fixture[change.path] = change.body
			c := capabilityClient(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(fixture[strings.TrimPrefix(r.URL.Path, "/rest/")]))
			})
			if _, e := c.Capabilities(context.Background()); e == nil {
				t.Fatal("malformed capability accepted")
			}
		})
	}
}
func TestCapabilitiesProfileAndObjectVariant(t *testing.T) {
	for _, version := range []string{"7.24.5", "7.24.6", "7.24.5rc1", "7.24.5 (testing)"} {
		t.Run(version, func(t *testing.T) {
			fixture := capabilityFixture()
			fixture["system/resource"] = `{"version":"` + version + `","architecture-name":"x86_64","board-name":"CHR","platform":"MikroTik"}`
			c := capabilityClient(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(fixture[strings.TrimPrefix(r.URL.Path, "/rest/")]))
			})
			result, e := c.Capabilities(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if result.VersionSupported != (version == "7.24.5") {
				t.Fatalf("invalid version support: %#v", result)
			}
		})
	}
	fixture := capabilityFixture()
	fixture["system/resource"] = strings.Replace(fixture["system/resource"], `"CHR"`, `"CCR2004"`, 1)
	c := capabilityClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fixture[strings.TrimPrefix(r.URL.Path, "/rest/")]))
	})
	result, e := c.Capabilities(context.Background())
	if e != nil || result.VersionSupported {
		t.Fatalf("hardware claimed supported: %#v %v", result, e)
	}
}
func TestCapabilitiesContextAndRedirect(t *testing.T) {
	c := capabilityClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/fixture-secret", http.StatusFound)
	})
	if _, e := c.Capabilities(context.Background()); e == nil || strings.Contains(e.Error(), "fixture-secret") {
		t.Fatalf("redirect not rejected/redacted: %v", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := c.Capabilities(ctx); !errors.Is(e, context.Canceled) {
		t.Fatalf("context cancellation lost: %v", e)
	}
}
func TestCapabilitiesResponseBound(t *testing.T) {
	c := capabilityClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", (4<<20)+1))) })
	if _, e := c.Capabilities(context.Background()); e == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestCapabilityScalarLimits(t *testing.T) {
	for _, body := range []string{
		`[{"name":"` + strings.Repeat("x", 4097) + `"}]`,
		`[{"` + strings.Repeat("x", 257) + `":"value"}]`,
		"[" + strings.Repeat("{},", 4096) + "{}]",
	} {
		if _, e := scalarRows([]byte(body), false); e == nil {
			t.Fatal("unbounded scalar/record accepted")
		}
	}
}
func TestRequiredCapability404(t *testing.T) {
	c := capabilityClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) })
	if _, e := c.Capabilities(context.Background()); e == nil {
		t.Fatal("missing required resource accepted")
	}
}
func TestCapabilitiesCanceledDuringRead(t *testing.T) {
	entered := make(chan struct{})
	c := capabilityClient(t, func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := c.Capabilities(ctx); done <- e }()
	<-entered
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatalf("in-flight cancellation lost: %v", e)
	}
}

func TestCapabilitiesNativeCHRBoardDescription(t *testing.T) {
	fixture := capabilityFixture()
	fixture["system/resource"] = strings.Replace(fixture["system/resource"], `"board-name":"CHR"`, `"board-name":"CHR QEMU Standard PC (i440FX + PIIX, 1996)"`, 1)
	c := capabilityClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fixture[strings.TrimPrefix(r.URL.Path, "/rest/")]))
	})
	caps, err := c.Capabilities(context.Background())
	if err != nil || !caps.VersionSupported {
		t.Fatal(caps, err)
	}
}
