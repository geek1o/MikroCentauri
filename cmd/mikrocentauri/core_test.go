package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mikrocentauri.local/core/internal/subscriptions"
)

func TestCorePrivateImports(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "endpoint")
	if err = os.WriteFile(file, []byte("trojan://secret-token@example.com:443#fixture"), 0644); err != nil {
		t.Fatal(err)
	}
	if err = coreCommand("endpoint-preview", []string{"-uri-file", file}); err == nil {
		t.Fatal("public secret file accepted")
	}
	if err = os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if err = coreCommand("endpoint-preview", []string{"-uri-file", file}); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, []byte("unsupported://secret-token@example.com"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = coreCommand("endpoint-preview", []string{"-uri-file", file}); err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatal("invalid import accepted or credential leaked")
	}
}

func TestSubscriptionCLIBlocksPrivateDownload(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "spec.json")
	b, _ := json.Marshal(subscriptions.Spec{ID: "fixture", URL: "http://127.0.0.1:9/private-token"})
	if err = os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	err = coreCommand("subscription-refresh", []string{"-config", file, "-state", state})
	if err == nil || strings.Contains(err.Error(), "private-token") {
		t.Fatal("private download accepted or URL leaked")
	}
	if err = coreCommand("subscription-status", []string{"-id", "fixture", "-state", state}); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, []byte(`{"id":"fixture","id":"other","url":"https://example.com"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = coreCommand("subscription-refresh", []string{"-config", file, "-state", state}); err == nil {
		t.Fatal("duplicate specification accepted")
	}
}
