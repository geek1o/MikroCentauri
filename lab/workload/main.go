// mc-lab is an isolated-network workload for the MikroCentauri CHR laboratory.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var requestSequence atomic.Uint64

// A disposable server-only fixture for endpoint churn. It cannot change the
// upstream listener or the canary domain; only second.test has an override.
type dnsOverride struct {
	Target     string `json:"target"`
	TTL        uint32 `json:"ttl"`
	Fail       bool   `json:"fail"`
	AllTTL     uint32 `json:"all_ttl,omitempty"`
	IPv6Target string `json:"ipv6_target,omitempty"`
}

var dnsFixture atomic.Pointer[dnsOverride]

type workloadRequest struct {
	Domain    string `json:"domain"`
	Host      string `json:"host"`
	TimeoutMS int    `json:"timeout_ms"`
	Address   string `json:"address"`
	SkipDNS   bool   `json:"skip_dns"`
	DNSTCP    bool   `json:"dns_tcp"`
	Port      int    `json:"port"`
	Source    string `json:"source"`
	Path      string `json:"path"`
	Payload   string `json:"payload"`
}
type workloadResult struct {
	RequestID    uint64 `json:"request_id"`
	ResolvedIPv4 string `json:"resolved_ipv4,omitempty"`
	Target       any    `json:"target,omitempty"`
	Body         string `json:"body,omitempty"`
	Payload      string `json:"payload,omitempty"`
	ProxySeenIP  string `json:"proxy_seen_ip,omitempty"`
	Error        string `json:"error,omitempty"`
	Bytes        int64  `json:"bytes,omitempty"`
	ElapsedMS    int64  `json:"elapsed_ms"`
}

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "serve" && os.Args[1] != "client") {
		log.Fatal("usage: mc-lab serve|client")
	}
	mode := os.Args[1]
	dns := os.Getenv("MC_DNS_SERVER")
	if dns == "" {
		dns = "192.168.88.1"
		if mode == "serve" {
			dns = "10.77.0.20"
		}
	}
	if _, _, err := net.SplitHostPort(dns); err != nil {
		dns = net.JoinHostPort(dns, "53")
	}
	target := os.Getenv("MC_TARGET_IP")
	if target == "" {
		target = "10.77.0.20"
	}
	if net.ParseIP(target).To4() == nil {
		log.Fatal("MC_TARGET_IP must be IPv4")
	}
	failures := make(chan error, 4)
	if mode == "serve" {
		go func() { failures <- serveDNS(net.JoinHostPort(target, "53"), target) }()
		// Bind each target explicitly: a wildcard UDP WriteTo may choose the
		// primary interface address, which would not match a native DNAT reply.
		go func() { failures <- serveUDPEcho(net.JoinHostPort(target, "9000")) }()
		if target != "10.77.0.21" {
			go func() { failures <- serveUDPEcho("10.77.0.21:9000") }()
		}
		go func() { failures <- http.ListenAndServe("0.0.0.0:8080", http.HandlerFunc(targetHTTP)) }()
		go func() { failures <- http.ListenAndServe("[::]:8087", http.HandlerFunc(targetHTTP)) }()
	}
	mux := http.NewServeMux()
	hardeningHandlers(mux, mode)
	mux.HandleFunc("/request", controlHandler(dns, false))
	mux.HandleFunc("/udp", controlHandler(dns, true))
	if mode == "serve" {
		mux.HandleFunc("/dns-fixture", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				writeJSON(w, dnsFixture.Load())
				return
			}
			if r.Method != http.MethodPost {
				w.WriteHeader(405)
				return
			}
			var next dnsOverride
			dec := json.NewDecoder(io.LimitReader(r.Body, 1024))
			dec.DisallowUnknownFields()
			if dec.Decode(&next) != nil || (next.Target != "10.77.0.20" && next.Target != "10.77.0.21") || next.TTL < 1 || next.TTL > 30 || next.AllTTL > 30 || (next.IPv6Target != "" && next.IPv6Target != "fd7a:7:2::20") {
				http.Error(w, "invalid disposable DNS fixture", 400)
				return
			}
			dnsFixture.Store(&next)
			writeJSON(w, next)
		})
	}
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok", "mode": mode, "dns_server": dns})
	})
	go func() { failures <- http.ListenAndServe("0.0.0.0:8089", mux) }()
	log.Printf("mc-lab mode=%s dns=%s control=:8089", mode, dns)
	log.Fatal(<-failures)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func hostOnly(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}
func targetHTTP(w http.ResponseWriter, r *http.Request) {
	local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	localIP := ""
	if local != nil {
		localIP = hostOnly(local.String())
	}
	if r.URL.Path == "/bench" {
		n, err := strconv.Atoi(r.URL.Query().Get("bytes"))
		if err != nil || n < 1 || n > 8*1024*1024 {
			http.Error(w, "bytes outside lab limit", 400)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.Header().Set("X-Lab-Remote-IP", hostOnly(r.RemoteAddr))
		_, _ = io.WriteString(w, strings.Repeat("x", n))
		return
	}
	log.Printf("target request remote=%s path=%q", hostOnly(r.RemoteAddr), r.URL.Path)
	writeJSON(w, map[string]string{"remote_ip": hostOnly(r.RemoteAddr), "local_ip": localIP, "path": r.URL.RequestURI()})
}
func controlHandler(dns string, udp bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req workloadRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		if req.Domain == "" || (req.Source != "" && net.ParseIP(req.Source).To4() == nil) {
			http.Error(w, "domain and valid IPv4 source required", 400)
			return
		}
		if req.Port == 0 {
			req.Port = 8080
			if udp {
				req.Port = 9000
			}
		}
		if req.Port < 1 || req.Port > 65535 {
			http.Error(w, "invalid port", 400)
			return
		}
		if req.Path == "" {
			req.Path = "/"
		}
		if !strings.HasPrefix(req.Path, "/") {
			http.Error(w, "path must start with /", 400)
			return
		}
		id := requestSequence.Add(1)
		start := time.Now()
		log.Printf("control request_id=%d domain=%q source=%q udp=%t path=%q", id, req.Domain, req.Source, udp, req.Path)
		timeout := 12 * time.Second
		if req.TimeoutMS != 0 {
			if req.TimeoutMS < 100 || req.TimeoutMS > 12000 {
				http.Error(w, "timeout outside lab bounds", 400)
				return
			}
			timeout = time.Duration(req.TimeoutMS) * time.Millisecond
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		result := runWorkload(ctx, dns, req, udp)
		result.RequestID = id
		result.ElapsedMS = time.Since(start).Milliseconds()
		writeJSON(w, result)
	}
}
func sourceAddr(source, network string) net.Addr {
	if source == "" {
		return nil
	}
	ip := net.ParseIP(source)
	if strings.HasPrefix(network, "udp") {
		return &net.UDPAddr{IP: ip}
	}
	return &net.TCPAddr{IP: ip}
}
func labResolver(dns, source string) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 4 * time.Second, LocalAddr: sourceAddr(source, network)}
		return d.DialContext(ctx, network, dns)
	}}
}
func runWorkload(ctx context.Context, dns string, req workloadRequest, udp bool) (out workloadResult) {
	fail := func(err error) workloadResult { out.Error = err.Error(); return out }
	resolver := labResolver(dns, req.Source)
	if req.DNSTCP {
		dial := resolver.Dial
		resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) { return dial(ctx, "tcp", address) }
	}
	if !req.SkipDNS {
		ips, err := resolver.LookupIP(ctx, "ip4", req.Domain)
		if err != nil {
			return fail(fmt.Errorf("resolve: %w", err))
		}
		if len(ips) == 0 {
			return fail(errors.New("resolve: no IPv4 address"))
		}
		out.ResolvedIPv4 = ips[0].String()
	} else if net.ParseIP(req.Address).To4() == nil {
		return fail(errors.New("skip_dns requires an explicit IPv4 address"))
	}
	if req.Address != "" {
		if net.ParseIP(req.Address).To4() == nil {
			return fail(errors.New("address must be IPv4"))
		}
		out.ResolvedIPv4 = req.Address
	}
	addr := net.JoinHostPort(out.ResolvedIPv4, strconv.Itoa(req.Port))
	if udp {
		d := net.Dialer{LocalAddr: sourceAddr(req.Source, "udp"), Timeout: 4 * time.Second}
		c, err := d.DialContext(ctx, "udp4", addr)
		if err != nil {
			return fail(err)
		}
		defer c.Close()
		deadline := time.Now().Add(5 * time.Second)
		if v, ok := ctx.Deadline(); ok && v.Before(deadline) {
			deadline = v
		}
		_ = c.SetDeadline(deadline)
		payload := req.Payload
		if payload == "" {
			payload = "mikrocentauri-udp-probe"
		}
		if _, err = c.Write([]byte(payload)); err != nil {
			return fail(err)
		}
		b := make([]byte, 65535)
		n, err := c.Read(b)
		if err != nil {
			return fail(err)
		}
		out.Payload = string(b[:n])
		if out.Payload != payload {
			return fail(errors.New("UDP echo payload mismatch"))
		}
		return out
	}
	d := net.Dialer{LocalAddr: sourceAddr(req.Source, "tcp"), Timeout: 5 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return d.DialContext(ctx, "tcp4", addr)
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(req.Domain, strconv.Itoa(req.Port))+req.Path, nil)
	if err != nil {
		return fail(err)
	}
	if req.Host != "" {
		request.Host = req.Host
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return fail(err)
	}
	defer response.Body.Close()
	if response.Header.Get("X-Lab-Remote-IP") != "" {
		out.ProxySeenIP = response.Header.Get("X-Lab-Remote-IP")
		out.Bytes, err = io.Copy(io.Discard, io.LimitReader(response.Body, 8*1024*1024+1))
		if err != nil {
			return fail(err)
		}
		if response.StatusCode != 200 || out.Bytes != response.ContentLength {
			return fail(errors.New("incomplete benchmark transfer"))
		}
		return out
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return fail(err)
	}
	out.Body = string(body)
	var parsed map[string]any
	if json.Unmarshal(body, &parsed) == nil {
		out.Target = parsed
		if s, ok := parsed["remote_ip"].(string); ok {
			out.ProxySeenIP = s
		}
	}
	if response.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("target returned HTTP %d", response.StatusCode))
	}
	return out
}

// dnsName accepts compression while bounding jumps, labels, and message offsets.
func dnsName(packet []byte, start int) (string, int, error) {
	pos := start
	next := -1
	labels := []string{}
	seen := map[int]bool{}
	total := 0
	for steps := 0; steps < 128; steps++ {
		if pos >= len(packet) || seen[pos] {
			return "", 0, errors.New("invalid DNS name")
		}
		seen[pos] = true
		size := int(packet[pos])
		pos++
		if size == 0 {
			if next < 0 {
				next = pos
			}
			return strings.ToLower(strings.Join(labels, ".")), next, nil
		}
		if size&0xc0 == 0xc0 {
			if pos >= len(packet) {
				return "", 0, errors.New("truncated DNS pointer")
			}
			offset := (size&0x3f)<<8 | int(packet[pos])
			pos++
			if next < 0 {
				next = pos
			}
			pos = offset
			continue
		}
		if size&0xc0 != 0 || size > 63 || pos+size > len(packet) {
			return "", 0, errors.New("invalid DNS label")
		}
		total += size + 1
		if total > 255 {
			return "", 0, errors.New("DNS name too long")
		}
		labels = append(labels, string(packet[pos:pos+size]))
		pos += size
	}
	return "", 0, errors.New("DNS name exceeds jump limit")
}
func dnsReply(query []byte, target string) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("short DNS query")
	}
	if binary.BigEndian.Uint16(query[4:6]) != 1 || query[2]&0x80 != 0 {
		return nil, errors.New("expected one DNS question")
	}
	name, end, err := dnsName(query, 12)
	if err != nil {
		return nil, err
	}
	if end+4 > len(query) {
		return nil, errors.New("short DNS question")
	}
	typ := binary.BigEndian.Uint16(query[end : end+2])
	class := binary.BigEndian.Uint16(query[end+2 : end+4])
	// Copy the question only; never copy client-supplied answer or EDNS sections.
	reply := append([]byte(nil), query[:end+4]...)
	flags := uint16(0x8400) | (binary.BigEndian.Uint16(query[2:4]) & 0x0100)
	known := name == "selected.test" || name == "unselected.test" || name == "second.test" || name == "third.test" || name == "fourth.test" || name == "fifth.test" || name == "sixth.test"
	ttl := uint32(5)
	if override := dnsFixture.Load(); override != nil && override.AllTTL > 0 {
		ttl = override.AllTTL
	}
	if override := dnsFixture.Load(); name == "second.test" && override != nil {
		target, ttl = override.Target, override.TTL
		if override.Fail {
			flags |= 2
			known = false
		}
	}
	if !known {
		if flags&15 == 0 {
			flags |= 3
		}
	}
	binary.BigEndian.PutUint16(reply[2:4], flags)
	for i := 6; i < 12; i++ {
		reply[i] = 0
	}
	if known && typ == 1 && class == 1 {
		ip := net.ParseIP(target).To4()
		if ip == nil {
			return nil, errors.New("invalid target IPv4")
		}
		binary.BigEndian.PutUint16(reply[6:8], 1)
		reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4)
		binary.BigEndian.PutUint32(reply[len(reply)-6:len(reply)-2], ttl)
		reply = append(reply, ip...)
	}
	if known && typ == 28 && class == 1 {
		if fixture := dnsFixture.Load(); fixture != nil && fixture.IPv6Target != "" {
			binary.BigEndian.PutUint16(reply[6:8], 1)
			reply = append(reply, 0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 5, 0, 16)
			reply = append(reply, net.ParseIP(fixture.IPv6Target).To16()...)
		}
	}
	return reply, nil
}
func serveDNS(addr, target string) error {
	udp, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return err
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp4", addr)
	if err != nil {
		return err
	}
	defer tcp.Close()
	failures := make(chan error, 2)
	go func() {
		b := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFrom(b)
			if err != nil {
				failures <- err
				return
			}
			reply, err := dnsReply(b[:n], target)
			if err == nil {
				_, _ = udp.WriteTo(reply, peer)
			}
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				failures <- err
				return
			}
			go handleDNSTCP(conn, target)
		}
	}()
	return <-failures
}
func handleDNSTCP(conn net.Conn, target string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	for {
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if n < 12 {
			return
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		reply, err := dnsReply(b, target)
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(length[:], uint16(len(reply)))
		framed := append(length[:], reply...)
		if _, err := io.Copy(conn, strings.NewReader(string(framed))); err != nil {
			return
		}
	}
}
func serveUDPEcho(addr string) error {
	c, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	b := make([]byte, 65535)
	for {
		n, peer, err := c.ReadFrom(b)
		if err != nil {
			return err
		}
		if _, err = c.WriteTo(b[:n], peer); err != nil {
			return err
		}
	}
}
