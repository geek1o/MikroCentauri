//go:build linux

package main

import (
	"encoding/json"
	"mikrocentauri.local/core/internal/dnsgate"
	"net/http"
	"sync"
)

type dnsDiagnostic struct {
	Stage     string `json:"stage"`
	Reason    string `json:"reason"`
	Domain    string `json:"domain,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

var dnsStats = struct {
	sync.Mutex
	Counts   map[string]uint64
	Failures []dnsDiagnostic
}{Counts: make(map[string]uint64), Failures: []dnsDiagnostic{}}

// The lab retains bounded categories and the last32 failures in memory only.
// No packet, credential, arbitrary query name, or raw error enters diagnostics.
func observeDNS(e dnsgate.Event) {
	dnsStats.Lock()
	defer dnsStats.Unlock()
	dnsStats.Counts[e.Stage+"/"+e.Reason]++
	if e.Reason == "selected_published" || e.Reason == "selected_aaaa_empty" || e.Reason == "unselected_forwarded" {
		return
	}
	dnsStats.Failures = append(dnsStats.Failures, dnsDiagnostic{e.Stage, e.Reason, e.Domain, e.Duration.Milliseconds()})
	if len(dnsStats.Failures) > 32 {
		dnsStats.Failures = dnsStats.Failures[len(dnsStats.Failures)-32:]
	}
}
func dnsDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	dnsStats.Lock()
	defer dnsStats.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Counts   map[string]uint64 `json:"counts"`
		Failures []dnsDiagnostic   `json:"last_failures"`
	}{dnsStats.Counts, dnsStats.Failures})
}
