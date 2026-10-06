package routeros

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type unavailableTransport struct{}

func (unavailableTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("private transport detail")
}

func TestReadUnavailableIsDistinctFromTLSVerificationFailure(t *testing.T) {
	c, err := NewClient("https://router.example/rest", "user", "private-password", &http.Client{Transport: unavailableTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Capabilities(context.Background()); !errors.Is(err, ErrReadUnavailable) {
		t.Fatal(err)
	}
	_, err = c.request(context.Background(), http.MethodGet, "ip/route", "", nil)
	if !errors.Is(err, ErrReadUnavailable) {
		t.Fatal(err)
	}
	_, err = c.request(context.Background(), http.MethodPut, "ip/route", "", map[string]string{})
	if errors.Is(err, ErrReadUnavailable) {
		t.Fatal("mutation classified as retryable read")
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`[]`)) }))
	defer server.Close()
	c, err = NewClient(server.URL+"/rest", "user", "private-password", &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Capabilities(context.Background()); err == nil || errors.Is(err, ErrReadUnavailable) {
		t.Fatal("TLS trust failure made retryable", err)
	}
}

type deniedProfileTransport struct{ started chan struct{} }

func (d deniedProfileTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == "/rest/ip/firewall/nat" {
		close(d.started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	}
	<-d.started
	return &http.Response{StatusCode: 403, Body: http.NoBody, Header: make(http.Header)}, nil
}
func TestProfileSnapshotDoesNotHideDeniedReadBehindCancelledPeer(t *testing.T) {
	c, err := NewClient("https://router.example/rest", "user", "password", &http.Client{Transport: deniedProfileTransport{started: make(chan struct{})}})
	if err != nil {
		t.Fatal(err)
	}
	b := &LabMappingBackend{client: c, barrier: &CoreNativeBarrier{client: c}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = b.profileDiscover(ctx, []string{"ip/firewall/nat", "tool/netwatch"})
	if err == nil || errors.Is(err, ErrReadUnavailable) || !strings.Contains(err.Error(), "403") {
		t.Fatal("denial became retryable", err)
	}
}
