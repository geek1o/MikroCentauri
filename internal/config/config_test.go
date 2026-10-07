package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	b, e := os.ReadFile("../../lab/configs/hybrid.json")
	if e != nil {
		t.Fatal(e)
	}
	c, e := Decode(b)
	if e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.GatewayIP = "198.18.0.1" }, func(c *Config) { c.Instance = "lab\"; /ip reset" }, func(c *Config) { c.Domains = []string{"Example.com"} }, func(c *Config) { c.ProxySources = c.DirectSources }, func(c *Config) { c.DNSUpstream = c.GatewayIP }, func(c *Config) { c.FakeIPRange = "192.168.0.0/16" }} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("unsafe config accepted")
		}
	}
	if _, e := Decode(append(b, []byte(` {}`)...)); e == nil {
		t.Fatal("trailing JSON accepted")
	}
}
func TestAtomicWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "private.json")
	if e := WriteAtomic(p, []byte("first")); e != nil {
		t.Fatal(e)
	}
	if e := WriteAtomic(p, []byte("second")); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(p)
	if e != nil || string(b) != "second" {
		t.Fatal("replacement failed")
	}
	s, _ := os.Stat(p)
	if s.Mode().Perm() != 0600 {
		t.Fatal("secret file permissions")
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".candidate-*"))
	if len(files) != 0 {
		t.Fatal("temporary secret files retained")
	}
}
