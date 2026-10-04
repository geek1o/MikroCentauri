//go:build linux

// Standalone lab capability probe, not the application dataplane or readiness server.
package main

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func probe() map[string]any {
	r := map[string]any{"status": "NOT TESTED", "tun_open": false, "tun_create": false}
	status, _ := os.ReadFile("/proc/self/status")
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			r["cap_eff"] = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		}
	}
	f, e := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if e != nil {
		r["status"] = "FAILED"
		r["error"] = e.Error()
		return r
	}
	defer f.Close()
	r["tun_open"] = true
	var st syscall.Stat_t
	if syscall.Stat("/dev/net/tun", &st) == nil {
		r["tun_device_rdev"] = st.Rdev
	}
	version, _ := os.ReadFile("/proc/version")
	r["kernel"] = strings.TrimSpace(string(version))
	devices, _ := os.ReadFile("/proc/net/dev")
	r["interfaces"] = string(devices)
	var features uint32
	_, _, featureErr := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0x800454cf, uintptr(unsafe.Pointer(&features)))
	r["tun_features"] = features
	r["tun_features_errno"] = int(featureErr)
	var req [40]byte
	copy(req[:16], "mc-tun-probe")
	binary.NativeEndian.PutUint16(req[16:18], 0x1001)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0x400454ca, uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		r["status"] = "FAILED"
		r["error"] = errno.Error()
		return r
	}
	r["tun_create"] = true
	r["status"] = "TESTED"
	return r
}
func main() {
	json.NewEncoder(os.Stdout).Encode(probe())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(probe())
	})
	if e := http.ListenAndServe(":9099", nil); e != nil {
		panic(e)
	}
}
