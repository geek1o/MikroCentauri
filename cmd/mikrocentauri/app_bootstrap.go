package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/api"
	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/endpoints"
)

// bootstrapRouterOSApp uses the explicitly mapped TLS port rather than RouterOS
// Cloud's optional web URL. Existing protected installations keep their state and
// credentials; only a stale RouterOS-App container listener address is reconciled.
func bootstrapRouterOSApp(directory, secretFile string) error {
	if _, err := os.Lstat(filepath.Join(directory, "bootstrap/app.json")); err == nil {
		return reconcileAppListener(directory)
	}
	host, port := os.Getenv("MC_ACCESS_IP"), os.Getenv("MC_ACCESS_PORT")
	if os.Getenv("MC_DIRECT_HTTPS") != "0" {
		var err error
		mappedPort := os.Getenv("MC_DIRECT_ACCESS_PORT")
		if mappedPort == "" {
			mappedPort = "8443"
		} // Published api-secure mapping, including older manifests.
		host, port, err = directAppAccess(os.Getenv("MC_CONTAINER_IP"), host, mappedPort)
		if err != nil {
			return err
		}
	}
	return bootstrapApp(directory, os.Getenv("MC_CONTAINER_IP"), host, port, secretFile)
}

// api-secure is a TCP mapping, not a RouterOS Cloud reverse proxy. Its public
// port is specified by the manifest; [accessPort] may be absent or describe HTTP.
func directAppAccess(containerIP, accessHost, mappedPort string) (string, string, error) {
	container, err := netip.ParseAddr(containerIP)
	port, portErr := strconv.Atoi(mappedPort)
	if err != nil || !container.Is4() || !container.IsPrivate() || portErr != nil || port < 1 || port > 65535 {
		return "", "", errors.New("direct HTTPS bootstrap requires private container IPv4 and explicit mapped TLS port")
	}
	access, accessErr := netip.ParseAddr(accessHost)
	if accessErr != nil {
		// Missing placeholders and Cloud hostnames cannot be the direct TLS origin.
		// Container IP remains a precise, local, independently reachable address.
		return container.String(), mappedPort, nil
	}
	if !access.Is4() || !access.IsPrivate() && !access.IsLoopback() {
		return "", "", errors.New("direct HTTPS bootstrap refuses a public access IP")
	}
	return access.String(), mappedPort, nil
}

// reconcileAppListener keeps an App-bootstrapped installation reachable after
// RouterOS re-creates its container with a different private IPv4 address. Only the
// persisted listener and bootstrap-owned TLS files change; authentication, model,
// drafts, subscriptions and every other state file stay untouched.
func reconcileAppListener(directory string) error {
	containerIP := os.Getenv("MC_CONTAINER_IP")
	if containerIP == "" {
		return nil // Operator-provisioned process startup keeps its file settings.
	}
	container, err := netip.ParseAddr(containerIP)
	if err != nil || !container.Is4() || !container.IsPrivate() {
		return nil // Leave the existing settings to report the real startup failure.
	}
	settingsPath := filepath.Join(directory, "bootstrap/app.json")
	var current appSettings
	if privateJSON(settingsPath, &current, 65536) != nil || current.SchemaVersion != 1 {
		return nil // loadAppSettings reports the actual settings error.
	}
	listenHost, listenPort, err := net.SplitHostPort(current.Listen)
	if err != nil || listenHost == containerIP {
		return nil
	}
	persisted, err := netip.ParseAddr(listenHost)
	if err != nil || !persisted.Is4() || localInterfaceAddress(persisted) {
		return nil // A locally assigned listener address is authoritative.
	}
	if !canonicalAppPath(directory) || filepath.Dir(current.TLSCert) != filepath.Join(directory, "bootstrap") || filepath.Dir(current.TLSKey) != filepath.Join(directory, "bootstrap") {
		return errors.New("management listener container address changed; operator TLS material requires an explicit update")
	}
	// The previous listener address stays certified so an interrupted update can
	// still serve the old settings until the new settings file is committed.
	ipAddresses := []string{container.String(), persisted.String()}
	dnsNames := []string{}
	if current.PublicOrigin != "" {
		origin, err := url.Parse(current.PublicOrigin)
		if err != nil || origin.Hostname() == "" {
			return nil
		}
		if access, err := netip.ParseAddr(origin.Hostname()); err == nil {
			if access.Is4() {
				ipAddresses = append(ipAddresses, access.String())
			}
		} else {
			dnsNames = append(dnsNames, origin.Hostname())
		}
	}
	certificatePEM, keyPEM, err := bootstrapTLS(ipAddresses, dnsNames)
	if err != nil {
		return errors.New("management listener TLS generation failed")
	}
	if err := config.WriteAtomic(current.TLSCert, certificatePEM); err != nil {
		return errors.New("management listener certificate update failed")
	}
	if err := config.WriteAtomic(current.TLSKey, keyPEM); err != nil {
		return errors.New("management listener key update failed")
	}
	raw, err := readRouterFile(settingsPath, 65536, true)
	if err != nil {
		return errors.New("management listener settings unavailable")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil
	}
	updatedListen, err := json.Marshal(net.JoinHostPort(container.String(), listenPort))
	if err != nil {
		return errors.New("management listener settings encoding failed")
	}
	fields["listen"] = updatedListen
	updated, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return errors.New("management listener settings encoding failed")
	}
	updated = append(updated, '\n')
	if err := config.WriteAtomic(settingsPath, updated); err != nil {
		return errors.New("management listener settings update failed")
	}
	fmt.Fprintln(os.Stdout, "MikroCentauri management listener re-bound to container address", net.JoinHostPort(container.String(), listenPort))
	return nil
}

// localInterfaceAddress reports whether the persisted listener address belongs to
// this process network namespace; a reviewed operator secondary address wins.
func localInterfaceAddress(want netip.Addr) bool {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, item := range addresses {
		ipNet, ok := item.(*net.IPNet)
		if !ok {
			continue
		}
		address, ok := netip.AddrFromSlice(ipNet.IP)
		if ok && address.Unmap() == want {
			return true
		}
	}
	return false
}

// bootstrapTLS creates the private self-signed management identity of an
// App-bootstrapped volume, binding both the listener IP and the advertised origin.
func bootstrapTLS(ipAddresses, dnsNames []string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "MikroCentauri local management"}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: dnsNames}
	for _, address := range ipAddresses {
		ip := net.ParseIP(address)
		if ip == nil {
			return nil, nil, errors.New("invalid TLS IP address")
		}
		certificate.IPAddresses = append(certificate.IPAddresses, ip)
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// bootstrapApp consumes only a declared RouterOS file secret on a fresh volume.
// It never obtains router credentials or grants forwarding authority.
func bootstrapApp(directory, containerIP, accessHost, accessPort, secretFile string) error {
	settingsPath := filepath.Join(directory, "bootstrap/app.json")
	if _, err := os.Lstat(settingsPath); err == nil {
		return nil // Existing protected installation wins over all environment values.
	} else if !os.IsNotExist(err) {
		return errors.New("bootstrap settings unavailable")
	}
	addr, err := netip.ParseAddr(containerIP)
	port, portErr := strconv.Atoi(accessPort)
	origin, originErr := api.CanonicalOrigin("https://" + net.JoinHostPort(accessHost, accessPort))
	if err != nil || !addr.Is4() || !addr.IsPrivate() || portErr != nil || port < 1 || port > 65535 || originErr != nil {
		return errors.New("bootstrap requires RouterOS private container IP and explicit HTTPS access host/port")
	}
	if access, e := netip.ParseAddr(accessHost); e == nil && !access.IsPrivate() && !access.IsLoopback() {
		return errors.New("bootstrap refuses a public access IP")
	}
	// RouterOS named volumes may start as 0755. Only an empty, non-symlink
	// fresh volume may be tightened; never repair or overwrite existing state.
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("bootstrap requires a real persistent directory")
	}
	for parent := filepath.Dir(directory); parent != filepath.Dir(parent); parent = filepath.Dir(parent) {
		info, e := os.Lstat(parent)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("unsafe bootstrap directory")
		}
	}
	entries, err := os.ReadDir(directory)
	emptyInheritedBootstrap := false
	if err == nil && len(entries) == 1 && entries[0].Name() == "bootstrap" && entries[0].IsDir() && entries[0].Type()&os.ModeSymlink == 0 {
		children, readErr := os.ReadDir(filepath.Join(directory, "bootstrap"))
		emptyInheritedBootstrap = readErr == nil && len(children) == 0
	}
	if err != nil || len(entries) != 0 && !emptyInheritedBootstrap {
		return errors.New("bootstrap refuses nonempty uninitialized state; review and recover it manually")
	}
	// App secrets are generated by RouterOS and mounted read-only, commonly
	// 0444. Copy once into the fresh private volume; regular operator inputs
	// retain their existing strict 0400/0600 policy.
	f, err := os.OpenFile(secretFile, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("RouterOS generated admin file secret unavailable")
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() < 16 || info.Size() > 1024 {
		return errors.New("bootstrap admin secret must be a bounded read-only regular file")
	}
	password, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(password) < 16 || len(password) > 1024 {
		return errors.New("invalid bootstrap secret")
	}
	defer clear(password)
	ipAddresses := []string{containerIP}
	dnsNames := []string{}
	if access, e := netip.ParseAddr(accessHost); e == nil {
		ipAddresses = append(ipAddresses, access.String())
	} else {
		dnsNames = append(dnsNames, accessHost)
	}
	certificatePEM, keyPEM, err := bootstrapTLS(ipAddresses, dnsNames)
	if err != nil {
		return errors.New("bootstrap TLS generation failed")
	}
	settings := appSettings{SchemaVersion: 1, DataDirectory: directory, Listen: net.JoinHostPort(containerIP, "8443"), PublicOrigin: origin,
		AllowClients: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"},
		TLSCert:      filepath.Join(directory, "bootstrap/api.crt"), TLSKey: filepath.Join(directory, "bootstrap/api.key"),
		Model: filepath.Join(directory, "bootstrap/model.json"), PasswordFile: filepath.Join(directory, "bootstrap/password")}
	model := coreconfig.Model{SchemaVersion: 2, Instance: "mikrocentauri", Mode: "hybrid", DefaultOutbound: "direct",
		Endpoints: []endpoints.Endpoint{}, Groups: []coreconfig.Group{}, Rules: []coreconfig.Rule{},
		DNS: coreconfig.DNS{Bootstrap: "1.1.1.1", FakeIPRange: "198.18.0.0/15", CachePath: "/data/runtime/cache.db"}}
	if err := model.Validate(); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return errors.New("bootstrap cannot protect state volume")
	}
	if emptyInheritedBootstrap {
		if err := os.Chmod(filepath.Join(directory, "bootstrap"), 0700); err != nil {
			return errors.New("bootstrap directory protection failed")
		}
	} else {
		if err := os.Mkdir(filepath.Join(directory, "bootstrap"), 0700); err != nil {
			return errors.New("bootstrap directory creation failed")
		}
	}
	write := func(path string, data []byte) error {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			return errors.New("bootstrap file creation failed")
		}
		defer file.Close()
		if _, err := file.Write(data); err != nil {
			return errors.New("bootstrap file write failed")
		}
		return file.Sync()
	}
	modelJSON, _ := json.MarshalIndent(model, "", "  ")
	settingsJSON, _ := json.MarshalIndent(settings, "", "  ")
	for _, item := range []struct {
		path string
		data []byte
	}{
		{settings.Model, modelJSON}, {settings.TLSCert, certificatePEM},
		{settings.TLSKey, keyPEM}, {settings.PasswordFile, password},
	} {
		if err := write(item.path, item.data); err != nil {
			return err
		}
	}
	// Settings is the last commit marker. Interrupted initialization is refused
	// rather than resetting credentials or silently discarding partial state.
	if err := write(settingsPath, settingsJSON); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Join(directory, "bootstrap"))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
