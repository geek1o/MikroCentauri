package main

// These bounded endpoints exist only inside disposable Linux test VMs.
import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func hardeningHandlers(mux *http.ServeMux, mode string) {
	if mode == "serve" {
		mux.HandleFunc("/proxy-control", func(w http.ResponseWriter, r *http.Request) {
			var q struct {
				Action string `json:"action"`
			}
			dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
			dec.DisallowUnknownFields()
			if r.Method != "POST" || dec.Decode(&q) != nil || (q.Action != "stop" && q.Action != "resume") {
				http.Error(w, "invalid proxy fixture action", 400)
				return
			}
			signal := syscall.SIGSTOP
			if q.Action == "resume" {
				signal = syscall.SIGCONT
			}
			processes, _ := os.ReadDir("/proc")
			changed := []int{}
			for _, process := range processes {
				pid, e := strconv.Atoi(process.Name())
				if e != nil {
					continue
				}
				comm, e := os.ReadFile("/proc/" + process.Name() + "/comm")
				if e == nil && strings.TrimSpace(string(comm)) == "sing-box" {
					if syscall.Kill(pid, signal) == nil {
						changed = append(changed, pid)
					}
				}
			}
			writeJSON(w, map[string]any{"action": q.Action, "pids": changed})
		})
	}
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Domain string `json:"domain"`
			Type   uint16 `json:"type"`
			Server string `json:"server"`
			TCP    bool   `json:"tcp"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
		dec.DisallowUnknownFields()
		if r.Method != "POST" || dec.Decode(&q) != nil || (q.Domain != "selected.test" && q.Domain != "unselected.test") || (q.Type != 1 && q.Type != 28 && q.Type != 64 && q.Type != 65) || (q.Server != "192.168.88.1" && q.Server != "10.77.0.20") {
			http.Error(w, "invalid disposable DNS probe", 400)
			return
		}
		query := []byte{0x71, 0x07, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, label := range strings.Split(q.Domain, ".") {
			query = append(query, byte(len(label)))
			query = append(query, label...)
		}
		query = append(query, 0, byte(q.Type>>8), byte(q.Type), 0, 1)
		network := "udp4"
		if q.TCP {
			network = "tcp4"
		}
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		conn, e := (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(q.Server, "53"))
		if e != nil {
			writeJSON(w, map[string]string{"error": "DNS connection failed"})
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		var response []byte
		if q.TCP {
			packet := make([]byte, 2, len(query)+2)
			binary.BigEndian.PutUint16(packet, uint16(len(query)))
			packet = append(packet, query...)
			_, e = conn.Write(packet)
			prefix := make([]byte, 2)
			if e == nil {
				_, e = io.ReadFull(conn, prefix)
			}
			if e == nil {
				response = make([]byte, int(binary.BigEndian.Uint16(prefix)))
				_, e = io.ReadFull(conn, response)
			}
		} else {
			_, e = conn.Write(query)
			response = make([]byte, 4096)
			if e == nil {
				var n int
				n, e = conn.Read(response)
				response = response[:n]
			}
		}
		if e != nil || len(response) < 12 || binary.BigEndian.Uint16(response[:2]) != 0x7107 {
			writeJSON(w, map[string]string{"error": "DNS response failed"})
			return
		}
		writeJSON(w, map[string]any{"rcode": binary.BigEndian.Uint16(response[2:4]) & 15, "answers": binary.BigEndian.Uint16(response[6:8]), "response_hex": fmt.Sprintf("%x", response), "type": q.Type, "server": q.Server, "tcp": q.TCP})
	})
	mux.HandleFunc("/ipv6-request", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Source string `json:"source"`
			Path   string `json:"path"`
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
		dec.DisallowUnknownFields()
		if r.Method != "POST" || dec.Decode(&q) != nil || (q.Source != "fd7a:7:1::10" && q.Source != "fd7a:7:1::30") || !strings.HasPrefix(q.Path, "/phase7-v6-") || len(q.Path) > 128 {
			http.Error(w, "invalid disposable IPv6 probe", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(q.Source)}}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp6", "[fd7a:7:2::20]:8087")
		}}
		defer transport.CloseIdleConnections()
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://selected.test:8087"+q.Path, nil)
		resp, e := (&http.Client{Transport: transport}).Do(req)
		if e != nil {
			writeJSON(w, map[string]string{"error": "IPv6 connection failed"})
			return
		}
		defer resp.Body.Close()
		body, e := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if e != nil {
			writeJSON(w, map[string]string{"error": "IPv6 body failed"})
			return
		}
		var value map[string]string
		if json.Unmarshal(body, &value) != nil {
			writeJSON(w, map[string]string{"error": "IPv6 response failed"})
			return
		}
		writeJSON(w, value)
	})
}
