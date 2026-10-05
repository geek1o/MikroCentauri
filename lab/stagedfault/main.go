// Disposable fixed-loopback HTTPS fault proof; absent from the product CLI.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"time"

	"mikrocentauri.local/core/internal/platform/routeros"
)

type disconnected struct {
	base   http.RoundTripper
	failed bool
}

func (t *disconnected) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.failed {
		return nil, errors.New("disposable transport disconnected")
	}
	response, err := t.base.RoundTrip(r)
	if err == nil && r.Method == "PUT" && response.StatusCode >= 200 && response.StatusCode < 300 {
		t.failed = true
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return nil, errors.New("disposable successful reply lost")
	}
	return response, err
}
func run() error {
	ca := flag.String("ca", "", "public native fixture certificate")
	journal := flag.String("journal", "", "private fault journal")
	flag.Parse()
	if *ca == "" || *journal == "" {
		return errors.New("ca and journal required")
	}
	data, err := os.ReadFile(*ca)
	if err != nil {
		return errors.New("fixture CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return errors.New("invalid fixture CA")
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	client, err := routeros.NewClient("https://127.0.0.1:18443/rest", "mc-lab", "DisposableLabOnly-2026", &http.Client{Transport: &disconnected{base: base}, Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	caps, err := client.Capabilities(ctx)
	if err != nil || !caps.VersionSupported {
		return errors.New("accepted disposable CHR fixture required")
	}
	controller, err := routeros.NewController(client, *journal)
	if err != nil {
		return err
	}
	desired := []routeros.Object{{Path: "ip/route", Fields: map[string]string{"comment": "mikrocentauri:stage2tls:route:canary", "disabled": "true", "dst-address": "203.0.113.125/32", "gateway": "172.30.0.2", "routing-table": "main", "distance": "1"}}}
	return controller.Reconcile(ctx, "stage2tls", desired)
}
func main() {
	if err := run(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}
