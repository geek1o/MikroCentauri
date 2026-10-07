// The fixtures run pinned local client/server processes and actual application
// payloads. Fixture CA injection changes only test configurations, never TLS
// verification or the endpoint importer policy.
package protocols

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"mikrocentauri.local/core/internal/endpoints"
	"mikrocentauri.local/core/internal/singbox"
	"mikrocentauri.local/core/internal/wireguard"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type object = map[string]any

const uuid = "bf000d23-0752-40b4-affe-68f7707a9661"
const badUUID = "bf000d23-0752-40b4-affe-68f7707a9662"

func pinned(t *testing.T) string {
	t.Helper()
	b := os.Getenv("SING_BOX_BINARY")
	if b == "" {
		t.Skip("set SING_BOX_BINARY for protocol process integration")
	}
	b, e := filepath.Abs(b)
	if e != nil {
		t.Fatal("invalid executable")
	}
	return b
}
func privateDir(t *testing.T) string {
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(p, 0700)
	return p
}
func port(t *testing.T, udp bool) uint16 {
	t.Helper()
	if udp {
		c, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		return uint16(c.LocalAddr().(*net.UDPAddr).Port)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}
func run(t *testing.T, binary string, cfg object, tcpPort uint16) func() {
	t.Helper()
	dir := privateDir(t)
	path := filepath.Join(dir, "config.json")
	if debug := os.Getenv("PROTOCOL_LOG_DIR"); debug != "" {
		cfg["log"] = object{"level": "debug"}
	}
	b, _ := json.Marshal(cfg)
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("fixture persistence")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if e := singbox.Check(ctx, binary, path); e != nil {
		t.Fatal("fixture check failed", e)
	}
	cmd := exec.Command(binary, "run", "-c", path)
	attributes(cmd)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if debug := os.Getenv("PROTOCOL_LOG_DIR"); debug != "" {
		os.MkdirAll(debug, 0700)
		f, e := os.CreateTemp(debug, "native-*.log")
		if e != nil {
			t.Fatal(e)
		}
		cmd.Stderr = f
		t.Cleanup(func() { f.Close() })
	}
	if cmd.Start() != nil {
		t.Fatal("fixture launch")
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			select {
			case <-done:
				return
			default:
			}
			syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(time.Second):
				syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
		})
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			t.Fatal("fixture exited")
		default:
		}
		if tcpPort == 0 {
			time.Sleep(60 * time.Millisecond)
			return stop
		}
		c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(tcpPort))), 20*time.Millisecond)
		if e == nil {
			c.Close()
			return stop
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	t.Fatal("fixture not ready")
	return stop
}
func serverConfig(in object) object {
	return object{"log": object{"disabled": true}, "inbounds": []any{in}, "outbounds": []any{object{"type": "direct", "tag": "direct"}}, "route": object{"final": "direct"}}
}
func clientConfig(out object, p uint16) object {
	return object{"log": object{"disabled": true}, "inbounds": []any{object{"type": "mixed", "listen": "127.0.0.1", "listen_port": p}}, "outbounds": []any{out}, "route": object{"final": "proxy"}}
}
func fetch(p uint16, target string) bool {
	proxy := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p)))}
	tr := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := http.Client{Transport: tr, Timeout: 2 * time.Second}
	r, e := client.Get(target)
	if e != nil {
		return false
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 1024))
	return e == nil && r.StatusCode == 200 && string(b) == "protocol-data"
}
func certFixture(t *testing.T) (certPath, keyPath string, cert tls.Certificate) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture.test"}, DNSNames: []string{"fixture.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	k, _ := x509.MarshalECPrivateKey(key)
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	priv := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: k})
	dir := privateDir(t)
	certPath = filepath.Join(dir, "ca.pem")
	keyPath = filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, c, 0600)
	os.WriteFile(keyPath, priv, 0600)
	cert, e = tls.X509KeyPair(c, priv)
	if e != nil {
		t.Fatal(e)
	}
	return
}
func udpEcho(t *testing.T) *net.UDPAddr {
	c, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 1024)
		for {
			n, a, e := c.ReadFromUDP(b)
			if e != nil {
				return
			}
			c.WriteToUDP(b[:n], a)
		}
	}()
	t.Cleanup(func() { c.Close(); <-done })
	return c.LocalAddr().(*net.UDPAddr)
}
func socksUDP(p uint16, target *net.UDPAddr) bool {
	c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(p))), time.Second)
	if e != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte{5, 1, 0})
	reply := make([]byte, 2)
	if _, e = io.ReadFull(c, reply); e != nil || reply[1] != 0 {
		return false
	}
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	header := make([]byte, 4)
	if _, e = io.ReadFull(c, header); e != nil || header[1] != 0 {
		return false
	}
	var addr []byte
	switch header[3] {
	case 1:
		addr = make([]byte, 6)
	case 4:
		addr = make([]byte, 18)
	default:
		return false
	}
	if _, e = io.ReadFull(c, addr); e != nil {
		return false
	}
	relay := &net.UDPAddr{IP: net.IP(addr[:len(addr)-2]), Port: int(binary.BigEndian.Uint16(addr[len(addr)-2:]))}
	if relay.IP.IsUnspecified() {
		relay.IP = net.ParseIP("127.0.0.1")
	}
	u, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		return false
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(2 * time.Second))
	packet := []byte{0, 0, 0, 1}
	packet = append(packet, target.IP.To4()...)
	packet = binary.BigEndian.AppendUint16(packet, uint16(target.Port))
	packet = append(packet, []byte("protocol-packet")...)
	if _, e = u.WriteToUDP(packet, relay); e != nil {
		return false
	}
	b := make([]byte, 1024)
	n, _, e := u.ReadFromUDP(b)
	return e == nil && n >= 10 && string(b[10:n]) == "protocol-packet"
}
func TestPinnedTLSProtocols(t *testing.T) {
	binary := pinned(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "protocol-data") }))
	defer target.Close()
	udp := udpEcho(t)
	certPath, keyPath, _ := certFixture(t)
	for _, protocol := range []string{"vless", "vless-vision", "trojan", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			sp := port(t, protocol == "hysteria2")
			actualProtocol := protocol
			if strings.HasPrefix(protocol, "vless") {
				actualProtocol = "vless"
			}
			user := object{"password": "public-fixture-secret"}
			auth := "public-fixture-secret"
			if actualProtocol == "vless" {
				user = object{"uuid": uuid}
				if protocol == "vless-vision" {
					user["flow"] = "xtls-rprx-vision"
				}
				auth = uuid
			}
			in := object{"type": actualProtocol, "listen": "127.0.0.1", "listen_port": sp, "users": []any{user}, "tls": object{"enabled": true, "certificate_path": certPath, "key_path": keyPath}}
			ready := sp
			if protocol == "hysteria2" {
				ready = 0
			}
			run(t, binary, serverConfig(in), ready)
			uri := actualProtocol + "://" + auth + "@127.0.0.1:" + strconv.Itoa(int(sp)) + "?sni=fixture.test"
			if actualProtocol == "vless" {
				uri += "&security=tls"
				if protocol == "vless-vision" {
					uri += "&flow=xtls-rprx-vision"
				}
			}
			ep, e := endpoints.ParseURI(uri)
			if e != nil {
				t.Fatal(e)
			}
			good := ep.Outbound("proxy")
			good["tls"].(map[string]any)["certificate_path"] = certPath
			cp := port(t, false)
			run(t, binary, clientConfig(good, cp), cp)
			if !fetch(cp, target.URL) {
				t.Fatal("trusted TLS TCP data failed")
			}
			if !socksUDP(cp, udp) {
				t.Fatal("UDP payload failed")
			}
			untrusted := ep.Outbound("proxy")
			up := port(t, false)
			run(t, binary, clientConfig(untrusted, up), up)
			if fetch(up, target.URL) {
				t.Fatal("untrusted TLS accepted")
			}
			bad := ep
			if actualProtocol == "vless" {
				bad.UUID = badUUID
			} else {
				bad.Password = "wrong-fixture-secret"
			}
			badout := bad.Outbound("proxy")
			badout["tls"].(map[string]any)["certificate_path"] = certPath
			bp := port(t, false)
			run(t, binary, clientConfig(badout, bp), bp)
			if fetch(bp, target.URL) {
				t.Fatal("bad credentials accepted")
			}
			wrongSNI := ep.Outbound("proxy")
			wrongSNI["tls"].(map[string]any)["certificate_path"] = certPath
			wrongSNI["tls"].(map[string]any)["server_name"] = "wrong.test"
			wp := port(t, false)
			run(t, binary, clientConfig(wrongSNI, wp), wp)
			if fetch(wp, target.URL) {
				t.Fatal("wrong TLS name accepted")
			}
		})
	}
}
func xkey(t *testing.T) (priv, pub string) {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.RawURLEncoding.EncodeToString(k.Bytes()), base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes())
}
func TestPinnedVLESSReality(t *testing.T) {
	binary := pinned(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "protocol-data") }))
	defer target.Close()
	udp := udpEcho(t)
	_, _, cert := certFixture(t)
	handshake := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "handshake-fixture") }))
	handshake.Config.ErrorLog = log.New(io.Discard, "", 0)
	handshake.EnableHTTP2 = true
	handshake.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	handshake.StartTLS()
	defer handshake.Close()
	hu, _ := url.Parse(handshake.URL)
	hp, _ := strconv.Atoi(hu.Port())
	priv, pub := xkey(t)
	sp := port(t, false)
	in := object{"type": "vless", "listen": "127.0.0.1", "listen_port": sp, "users": []any{object{"uuid": uuid}}, "tls": object{"enabled": true, "server_name": "fixture.test", "reality": object{"enabled": true, "handshake": object{"server": "127.0.0.1", "server_port": hp}, "private_key": priv, "short_id": []string{"0123456789abcdef"}}}}
	run(t, binary, serverConfig(in), sp)
	ep, e := endpoints.ParseURI("vless://" + uuid + "@127.0.0.1:" + strconv.Itoa(int(sp)) + "?security=reality&sni=fixture.test&pbk=" + pub + "&sid=0123456789abcdef&fp=chrome")
	if e != nil {
		t.Fatal(e)
	}
	cp := port(t, false)
	run(t, binary, clientConfig(ep.Outbound("proxy"), cp), cp)
	if !fetch(cp, target.URL) || !socksUDP(cp, udp) {
		t.Fatal("Reality data failed")
	}
	bad := ep
	_, bad.RealityKey = xkey(t)
	bp := port(t, false)
	run(t, binary, clientConfig(bad.Outbound("proxy"), bp), bp)
	if fetch(bp, target.URL) {
		t.Fatal("wrong Reality key accepted")
	}
	bad = ep
	bad.UUID = badUUID
	bp = port(t, false)
	run(t, binary, clientConfig(bad.Outbound("proxy"), bp), bp)
	if fetch(bp, target.URL) {
		t.Fatal("wrong Reality UUID accepted")
	}
	bad = ep
	bad.RealityShortID = "fedcba9876543210"
	bp = port(t, false)
	run(t, binary, clientConfig(bad.Outbound("proxy"), bp), bp)
	if fetch(bp, target.URL) {
		t.Fatal("wrong Reality short ID accepted")
	}

}
func wgKeys(t *testing.T) (priv, pub string) {
	k, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}
func TestPinnedModernWireGuard(t *testing.T) {
	binary := pinned(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "protocol-data") }))
	defer target.Close()
	udp := udpEcho(t)
	ap, ak := wgKeys(t)
	bp, bk := wgKeys(t)
	serverPort, clientPort := port(t, true), port(t, true)
	pskBytes := make([]byte, 32)
	if _, e := rand.Read(pskBytes); e != nil {
		t.Fatal(e)
	}
	psk := base64.StdEncoding.EncodeToString(pskBytes)
	server := wireguard.Endpoint{Name: "server", Enabled: true, Address: []string{"10.77.0.2/24"}, PrivateKey: bp, ListenPort: serverPort, Peers: []wireguard.Peer{{PublicKey: ak, PreSharedKey: psk, AllowedIPs: []string{"10.77.0.1/32"}}}}
	se, e := server.Build("wg-server")
	if e != nil {
		t.Fatal(e)
	}
	run(t, binary, object{"log": object{"disabled": true}, "endpoints": []any{se}, "outbounds": []any{object{"type": "direct", "tag": "direct"}}, "route": object{"final": "direct", "rules": []any{object{"action": "route", "outbound": "direct", "override_address": "127.0.0.1"}}}}, 0)
	client := wireguard.Endpoint{Name: "client", Enabled: true, Address: []string{"10.77.0.1/24"}, PrivateKey: ap, ListenPort: clientPort, Peers: []wireguard.Peer{{Address: "127.0.0.1", Port: serverPort, PublicKey: bk, PreSharedKey: psk, AllowedIPs: []string{"0.0.0.0/0"}}}}
	ce, e := client.Build("wg-client")
	if e != nil {
		t.Fatal(e)
	}
	cp := port(t, false)
	cfg := object{"log": object{"disabled": true}, "endpoints": []any{ce}, "inbounds": []any{object{"type": "mixed", "listen": "127.0.0.1", "listen_port": cp}}, "route": object{"final": "wg-client"}}
	run(t, binary, cfg, cp)
	targetURL, _ := url.Parse(target.URL)
	targetURL.Host = net.JoinHostPort("203.0.113.9", targetURL.Port())
	remoteUDP := *udp
	remoteUDP.IP = net.ParseIP("203.0.113.9")
	if !fetch(cp, targetURL.String()) || !socksUDP(cp, &remoteUDP) {
		t.Fatal("modern WireGuard handshake/application data failed")
	}
	_, wrong := wgKeys(t)
	client.Peers[0].PublicKey = wrong
	bad, e := client.Build("wg-bad")
	if e != nil {
		t.Fatal(e)
	}
	bad["listen_port"] = port(t, true)
	bpPort := port(t, false)
	cfg = object{"log": object{"disabled": true}, "endpoints": []any{bad}, "inbounds": []any{object{"type": "mixed", "listen": "127.0.0.1", "listen_port": bpPort}}, "route": object{"final": "wg-bad"}}
	run(t, binary, cfg, bpPort)
	if fetch(bpPort, targetURL.String()) {
		t.Fatal("wrong WireGuard peer key accepted")
	}
	client.Peers[0].PublicKey = bk
	client.Peers[0].PreSharedKey = wrong
	client.ListenPort = port(t, true)
	bad, e = client.Build("wg-bad-psk")
	if e != nil {
		t.Fatal(e)
	}
	bpPort = port(t, false)
	cfg = object{"log": object{"disabled": true}, "endpoints": []any{bad}, "inbounds": []any{object{"type": "mixed", "listen": "127.0.0.1", "listen_port": bpPort}}, "route": object{"final": "wg-bad-psk"}}
	run(t, binary, cfg, bpPort)
	if fetch(bpPort, targetURL.String()) {
		t.Fatal("wrong WireGuard pre-shared key accepted")
	}

}
func TestPinnedShadowsocksUDP(t *testing.T) {
	binary := pinned(t)
	udp := udpEcho(t)
	sp := port(t, false)
	run(t, binary, serverConfig(object{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": sp, "method": "aes-256-gcm", "password": "public-fixture-secret"}), sp)
	ep, e := endpoints.ParseURI("ss://aes-256-gcm:public-fixture-secret@127.0.0.1:" + strconv.Itoa(int(sp)))
	if e != nil {
		t.Fatal(e)
	}
	cp := port(t, false)
	run(t, binary, clientConfig(ep.Outbound("proxy"), cp), cp)
	if !socksUDP(cp, udp) {
		t.Fatal("Shadowsocks UDP data failed")
	}
}
