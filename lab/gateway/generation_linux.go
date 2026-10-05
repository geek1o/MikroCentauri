//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"mikrocentauri.local/core/internal/engineguard"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// Quarantine precedes engine execution. A native watchdog delay can lose a
// packet, but cannot expose an unadmitted engine to cached forwarded aliases.
func quarantine() error {
	iface := os.Getenv("MC_INTERFACE")
	if iface == "" {
		iface = "mc-probe"
	}
	if e := ip("route", "replace", "blackhole", "default", "table", "100"); e != nil {
		return errors.New("cannot install ingress quarantine")
	}
	rules, e := exec.Command("/sbin/ip", "rule", "show").Output()
	if e != nil {
		return errors.New("cannot inspect ingress policy")
	}
	count := 0
	for _, line := range strings.Split(string(rules), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "10000:" {
			continue
		}
		if strings.Join(fields[1:], " ") != "from all iif "+iface+" lookup 100" {
			return errors.New("conflicting ingress policy")
		}
		count++
	}
	if count > 1 {
		return errors.New("duplicate ingress policy")
	}
	if count == 0 {
		if e := ip("rule", "add", "priority", "10000", "iif", iface, "lookup", "100"); e != nil {
			return errors.New("cannot enforce ingress quarantine")
		}
	}
	return nil
}
func generationPreflight() error {
	data, err := os.ReadFile("/data/singbox.json")
	if err != nil {
		return errors.New("engine configuration unavailable")
	}
	if err = engineguard.Validate(data, engineguard.Config{Selected: selectedNames}); err != nil {
		return err
	}
	reserved := len(publisher.Mappings()) > 0
	if !reserved {
		if _, e := os.Lstat(engineguard.CachePath); !os.IsNotExist(e) {
			return errors.New("cache without alias ledger is not admitted")
		}
	} else {
		st, e := os.Lstat("/data/publication/mappings.json")
		if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() == 0 {
			return errors.New("alias ledger unavailable")
		}
	}
	return engineguard.CheckCache(engineguard.CachePath, reserved)
}
func generationDiagnostics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	if admission == nil {
		http.Error(w, "dynamic admission disabled", 404)
		return
	}
	routes, _ := exec.Command("/sbin/ip", "route", "show", "table", "100").Output()
	mu.Lock()
	running := child != nil
	setupError := lastError
	mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"admission": admission.Snapshot(), "engine_running": running, "setup_error": setupError, "ingress_route": string(routes)})
}
