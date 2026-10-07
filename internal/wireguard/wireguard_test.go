package wireguard

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func key(v byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = v
	}
	return base64.StdEncoding.EncodeToString(b)
}
func fixture() Endpoint {
	return Endpoint{Name: "fixture", Enabled: true, Address: []string{"10.77.0.1/24"}, PrivateKey: key(1), Peers: []Peer{{Address: "127.0.0.1", Port: 12345, PublicKey: key(2), AllowedIPs: []string{"0.0.0.0/0"}}}}
}
func TestModernEndpointStableIdentity(t *testing.T) {
	e, err := fixture().Normalize()
	if err != nil {
		t.Fatal(err)
	}
	renamed := e
	renamed.Name = "newname"
	renamed.Enabled = false
	id, _ := renamed.StableID()
	if id != e.ID {
		t.Fatal("name affected ID")
	}
	m, err := e.Build(e.ID)
	if err != nil || m["type"] != "wireguard" || m["system"] != false || m["peers"] == nil {
		t.Fatal("modern endpoint")
	}
	e.PrivateKey = key(3)
	if e.Validate() == nil {
		t.Fatal("changed credentials accepted old identity")
	}
}
func TestStrictValidationRedacts(t *testing.T) {
	for _, change := range []func(*Endpoint){func(e *Endpoint) { e.PrivateKey = "SECRET" }, func(e *Endpoint) { e.Address = []string{"8.8.8.8/24"} }, func(e *Endpoint) { e.Address = []string{"10.0.0.1/7"} }, func(e *Endpoint) { e.Peers[0].AllowedIPs = []string{"10.0.0.1/8"} }, func(e *Endpoint) {
		e.Peers = append(e.Peers, Peer{PublicKey: key(4), AllowedIPs: []string{"10.0.0.0/8"}})
	}, func(e *Endpoint) { e.Peers[0].PublicKey = key(0) }} {
		e := fixture()
		change(&e)
		if err := e.Validate(); err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatal("invalid endpoint accepted or leaked")
		}
	}
}

func TestLowOrderSelfPeerAndPrivateIPv6(t *testing.T) {
	e := fixture()
	bytes := make([]byte, 32)
	bytes[0] = 1
	e.Peers[0].PublicKey = base64.StdEncoding.EncodeToString(bytes)
	if e.Validate() == nil {
		t.Fatal("low-order peer key accepted")
	}
	e = fixture()
	raw, _ := base64.StdEncoding.DecodeString(e.PrivateKey)
	priv, _ := ecdh.X25519().NewPrivateKey(raw)
	e.Peers[0].PublicKey = base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	if e.Validate() == nil {
		t.Fatal("self peer accepted")
	}
	e = fixture()
	e.Address = []string{"fd77::1/64"}
	e.Peers[0].AllowedIPs = []string{"::/0"}
	if e.Validate() != nil {
		t.Fatal("private IPv6 rejected")
	}
	e.Address = []string{"2001:db8::1/64"}
	if e.Validate() == nil {
		t.Fatal("non-private tunnel accepted")
	}
}
func TestRedactedPreview(t *testing.T) {
	e, _ := fixture().Normalize()
	b, _ := json.Marshal(e.Preview())
	if strings.Contains(string(b), e.PrivateKey) || strings.Contains(string(b), e.Peers[0].PublicKey) {
		t.Fatal("preview leaked key material")
	}
}
