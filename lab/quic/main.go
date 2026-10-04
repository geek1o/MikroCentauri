// mc-quic is a LOCAL laboratory HTTP/3 workload. Its certificate key is public
// fixture material and must never be reused by a deployed service.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type request struct {
	Domain  string `json:"domain"`
	Address string `json:"address"`
	Source  string `json:"source"`
	Path    string `json:"path"`
}
type result struct {
	Protocol  string `json:"protocol,omitempty"`
	Target    any    `json:"target,omitempty"`
	RemoteIP  string `json:"remote_ip,omitempty"`
	Error     string `json:"error,omitempty"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

func fixtureCertificate() (tls.Certificate, *x509.CertPool, error) {
	seed := sha256.Sum256([]byte("MikroCentauri LOCAL QUIC test fixture publicly known key v1"))
	key := ed25519.NewKeyFromSeed(seed[:])
	cert := &x509.Certificate{SerialNumber: big.NewInt(777001), Subject: pkix.Name{CommonName: "MikroCentauri LOCAL laboratory"}, NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC), DNSNames: []string{"selected.test", "unselected.test", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.77.0.20")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, roots, nil
}
func jsonResponse(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
func targetHandler(w http.ResponseWriter, r *http.Request) {
	remote, _, _ := net.SplitHostPort(r.RemoteAddr)
	log.Printf("HTTP3 target remote=%s protocol=%s path=%q", remote, r.Proto, r.URL.Path)
	jsonResponse(w, map[string]string{"remote_ip": remote, "path": r.URL.RequestURI(), "protocol": r.Proto})
}
func serve(addr string) error {
	cert, _, err := fixtureCertificate()
	if err != nil {
		return err
	}
	conn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, Handler: http.HandlerFunc(targetHandler)}
	log.Printf("HTTP3 server listening=%s", addr)
	return server.Serve(conn)
}
func perform(ctx context.Context, req request) (out result) {
	started := time.Now()
	defer func() { out.ElapsedMS = time.Since(started).Milliseconds() }()
	fail := func(err error) result { out.Error = err.Error(); return out }
	if req.Domain == "" || net.ParseIP(req.Address).To4() == nil {
		return fail(errors.New("domain and IPv4 address required"))
	}
	if req.Source != "" && net.ParseIP(req.Source).To4() == nil {
		return fail(errors.New("invalid source IPv4"))
	}
	if req.Path == "" {
		req.Path = "/quic"
	}
	if !strings.HasPrefix(req.Path, "/") {
		return fail(errors.New("path must start with /"))
	}
	_, roots, err := fixtureCertificate()
	if err != nil {
		return fail(err)
	}
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(req.Source)})
	if err != nil {
		return fail(err)
	}
	defer pc.Close()
	remote := &net.UDPAddr{IP: net.ParseIP(req.Address), Port: 9443}
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: req.Domain, MinVersion: tls.VersionTLS13}, QUICConfig: &quic.Config{HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 8 * time.Second}, Dial: func(ctx context.Context, addr string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
		return quic.Dial(ctx, pc, remote, tc, qc)
	}}
	defer transport.Close()
	client := &http.Client{Transport: transport, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := http.NewRequestWithContext(ctx, "GET", "https://"+net.JoinHostPort(req.Domain, "9443")+req.Path, nil)
	if err != nil {
		return fail(err)
	}
	response, err := client.Do(r)
	if err != nil {
		return fail(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil {
		return fail(err)
	}
	out.Protocol = response.Proto
	var target map[string]any
	if err := json.Unmarshal(body, &target); err != nil {
		return fail(err)
	}
	out.Target = target
	out.RemoteIP, _ = target["remote_ip"].(string)
	if response.StatusCode != 200 {
		return fail(fmt.Errorf("target returned HTTP%d", response.StatusCode))
	}
	if response.ProtoMajor != 3 {
		return fail(errors.New("response is not HTTP/3"))
	}
	return out
}
func control(addr, source string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]string{"status": "ok", "protocol": "HTTP/3"})
	})
	mux.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		var req request
		if json.NewDecoder(io.LimitReader(r.Body, 65536)).Decode(&req) != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		if req.Source == "" {
			req.Source = source
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		jsonResponse(w, perform(ctx, req))
	})
	log.Printf("HTTP3 control listening=%s source=%s", addr, source)
	return http.ListenAndServe(addr, mux)
}
func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: mc-quic serve|client|control")
	}
	args := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	switch os.Args[1] {
	case "serve":
		listen := args.String("listen", "10.77.0.20:9443", "UDP listen address")
		_ = args.Parse(os.Args[2:])
		log.Fatal(serve(*listen))
	case "control":
		listen := args.String("listen", "0.0.0.0:8090", "HTTP control listen address")
		source := args.String("source", "192.168.88.10", "UDP source IPv4")
		_ = args.Parse(os.Args[2:])
		log.Fatal(control(*listen, *source))
	case "client":
		source := args.String("source", "192.168.88.10", "UDP source IPv4")
		_ = args.Parse(os.Args[2:])
		if args.NArg() != 2 {
			log.Fatal("usage: mc-quic client [-source IP] DOMAIN IPv4")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		out := perform(ctx, request{Domain: args.Arg(0), Address: args.Arg(1), Source: *source})
		_ = json.NewEncoder(os.Stdout).Encode(out)
		if out.Error != "" {
			os.Exit(1)
		}
	default:
		log.Fatal("unknown mode")
	}
}
