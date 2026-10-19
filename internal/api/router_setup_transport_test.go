package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRouterSetupTransportVerifiesCertificateIPAndNeverRedirectsCredentials(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("192.168.88.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Location", "https://192.168.88.2/foreign")
		w.WriteHeader(302)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	in := RouterSetupInput{BaseURL: "https://192.168.88.1/rest", Username: "reader", Password: "private-fixture"}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	client := routerSetupHTTPClient(in)
	transport := client.Transport.(*http.Transport)
	transport.DialContext = dial
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("proxy or TLS bypass enabled")
	}
	if response, e := client.Get(in.BaseURL); e == nil {
		response.Body.Close()
		t.Fatal("unknown certificate accepted")
	}
	in.CertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	client = routerSetupHTTPClient(in)
	transport = client.Transport.(*http.Transport)
	transport.DialContext = dial
	defer client.CloseIdleConnections()
	response, e := client.Get(in.BaseURL)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 302 || calls != 1 {
		t.Fatal("redirect followed", response.StatusCode, calls)
	}
	if response, e := client.Get("https://192.168.88.2/rest"); e == nil {
		response.Body.Close()
		t.Fatal("certificate IP mismatch accepted")
	}
	in.CertificatePEM += "\n-----BEGIN PRIVATE KEY-----\nZm9v\n-----END PRIVATE KEY-----\n"
	if validateRouterSetup(in) == nil {
		t.Fatal("private key upload accepted")
	}
}
