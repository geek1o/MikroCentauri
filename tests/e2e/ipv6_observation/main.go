// Disposable loopback CHR observation only; never changes IPv6/router state.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"mikrocentauri.local/core/internal/platform/routeros"
)

type reads struct {
	transport http.RoundTripper
	Paths     []string
}

func (r *reads) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet {
		return nil, errors.New("observation refuses mutations")
	}
	r.Paths = append(r.Paths, req.URL.Path)
	return r.transport.RoundTrip(req)
}
func main() {
	endpoint := flag.String("lab-url", "", "explicit disposable loopback HTTP REST endpoint")
	flag.Parse()
	u, e := url.Parse(*endpoint)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/rest" {
		log.Fatal("explicit loopback lab endpoint required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()
	recording := &reads{transport: transport}
	c, e := routeros.NewLabClient(*endpoint, "admin", "", &http.Client{Transport: recording, Timeout: 10 * time.Second})
	if e != nil {
		log.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	capability, e := c.Capabilities(ctx)
	if e != nil {
		log.Fatal("capability observation: ", e)
	}
	network, e := c.Network(ctx)
	if e != nil {
		log.Fatal("network observation: ", e)
	}
	result := struct {
		FastTrackUnknown int                      `json:"fasttrack_unknown"`
		FastTrackEnabled int                      `json:"fasttrack_enabled"`
		Scope            string                   `json:"scope"`
		Version          string                   `json:"version"`
		Architecture     string                   `json:"architecture"`
		IPv6             routeros.IPv6Observation `json:"ipv6"`
		Available        map[string]bool          `json:"available"`
		Requests         []string                 `json:"get_requests"`
	}{network.FastTrackUnknown, network.FastTrackEnabled, "disposable CHR read-only configuration; no packet isolation proof", capability.Version, capability.Architecture, network.IPv6, network.Available, recording.Paths}
	if e = json.NewEncoder(os.Stdout).Encode(result); e != nil {
		log.Fatal(e)
	}
}
