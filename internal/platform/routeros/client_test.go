package routeros

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLiteralRouterOSObjectID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// RouterOS distinguishes '*ID' from '%2AID' even though Go decodes both.
		if r.RequestURI != "/rest/ip/route/*80000008" {
			t.Errorf("RouterOS object ID escaped: %s", r.RequestURI)
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	client, err := NewLabClient(server.URL+"/rest", "lab", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"PATCH", "DELETE"} {
		if _, err := client.request(context.Background(), method, "ip/route", "*80000008", nil); err != nil {
			t.Fatal(err)
		}
	}
}
