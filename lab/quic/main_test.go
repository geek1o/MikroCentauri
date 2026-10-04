package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestFixtureTLSVerification(t *testing.T) {
	cert, roots, err := fixtureCertificate()
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"selected.test", "unselected.test"} {
		if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "unknown.test"}); err == nil {
		t.Fatal("unknown hostname accepted")
	}
	again, _, err := fixtureCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if string(cert.Certificate[0]) != string(again.Certificate[0]) {
		t.Fatal("fixture certificate changes between invocations")
	}
}
func TestActualHTTP3(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:9443")
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := fixtureCertificate()
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, Handler: http.HandlerFunc(targetHandler)}
	done := make(chan error, 1)
	go func() { done <- server.Serve(pc) }()
	defer func() { _ = server.Close(); _ = pc.Close(); <-done }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out := perform(ctx, request{Domain: "selected.test", Address: "127.0.0.1", Source: "127.0.0.1", Path: "/actual-http3?probe=1"})
	if out.Error != "" || out.Protocol != "HTTP/3.0" || out.RemoteIP != "127.0.0.1" {
		t.Fatalf("unexpected HTTP3 result: %+v", out)
	}
	if out.Target.(map[string]any)["path"] != "/actual-http3?probe=1" {
		t.Fatalf("path lost: %+v", out)
	}
	out = perform(ctx, request{Domain: "unknown.test", Address: "127.0.0.1", Source: "127.0.0.1"})
	if !strings.Contains(out.Error, "failed to verify certificate") {
		t.Fatalf("TLS hostname verification absent: %+v", out)
	}
}
