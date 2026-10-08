package subscriptions

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestProductionDownloaderImportsTwentyNodesAndReportsUnsupported(t *testing.T) {
	var rows []string
	for i := 0; i < 20; i++ {
		rows = append(rows, fmt.Sprintf("trojan://private-password@server-%d.example:443#Node-%d", i, i))
	}
	rows = append(rows, "vless://bf000d23-0752-40b4-affe-68f7707a9661@example.com:443?security=tls&type=xhttp")
	body := base64.StdEncoding.EncodeToString([]byte("# provider metadata\n" + strings.Join(rows, "\n")))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	manager, e := New(privateDir(t), Policy{RootCAs: roots, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if e != nil {
		t.Fatal(e)
	}
	state, e := manager.Refresh(context.Background(), Spec{ID: "provider", URL: srv.URL})
	if e != nil || len(state.Nodes) != 20 || state.SourceCount != 21 || len(state.Issues) != 1 {
		t.Fatal("multi-node source not preserved", len(state.Nodes), state.SourceCount, e)
	}
	if state.Issues[0].Code != "unsupported_transport" {
		t.Fatal(state.Issues)
	}
	body = "unsupported source"
	after, e := manager.Refresh(context.Background(), Spec{ID: "provider", URL: srv.URL})
	if e == nil || len(after.Nodes) != 20 || after.LastSuccess != state.LastSuccess {
		t.Fatal("bad response destroyed LKG")
	}
}
