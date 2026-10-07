package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func provisionFixture(t *testing.T) (string, string) {
	t.Helper()
	s, _, _, _, settings, bundle := installFixture(t)
	s.PasswordFile = "/data/bootstrap/password"
	data, _ := json.Marshal(s)
	if err := os.WriteFile(settings, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "bootstrap/password"), []byte("PrivateProvisionPassword-2026\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	w := tar.NewWriter(&output)
	entries, err := os.ReadDir(filepath.Join(bundle, "bootstrap"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		content, err := os.ReadFile(filepath.Join(bundle, "bootstrap", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err = w.WriteHeader(&tar.Header{Name: "bootstrap/" + entry.Name(), Mode: 0600, Size: int64(len(content)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(bundle, "install.tar")
	if err = os.WriteFile(archive, output.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(bundle, "state")
	if err = os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	return archive, target
}

func TestAppProvisionProtectedNativeBundleNoAuthAndNoOverwrite(t *testing.T) {
	archive, target := provisionFixture(t)
	if err := provisionAppArchive(archive, target); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{target, filepath.Join(target, "bootstrap")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("private directories", err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(target, "bootstrap"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("private files", err)
		}
	}
	if _, err := os.Lstat(filepath.Join(target, "api")); !os.IsNotExist(err) {
		t.Fatal("provisioning initialized authentication", err)
	}
	before, err := os.ReadFile(filepath.Join(target, "bootstrap/app.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := provisionAppArchive(archive, target); err == nil {
		t.Fatal("existing state overwritten")
	}
	after, err := os.ReadFile(filepath.Join(target, "bootstrap/app.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing settings changed", err)
	}
}

func TestAppProvisionRejectsUntrustedArchiveAndUnsafeTargetsBeforeWrite(t *testing.T) {
	for name, mutate := range map[string]func(*tar.Header){
		"escape":       func(h *tar.Header) { h.Name = "bootstrap/../app.json" },
		"unknown file": func(h *tar.Header) { h.Name = "bootstrap/unrelated.json" },
		"public mode":  func(h *tar.Header) { h.Mode = 0644 },
		"symlink":      func(h *tar.Header) { h.Typeflag = tar.TypeSymlink; h.Linkname = "/data/bootstrap/app.json"; h.Size = 0 },
		"hardlink":     func(h *tar.Header) { h.Typeflag = tar.TypeLink; h.Linkname = "/private/secret"; h.Size = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			w := tar.NewWriter(&output)
			h := tar.Header{Name: "bootstrap/app.json", Mode: 0600, Size: 2}
			mutate(&h)
			if err := w.WriteHeader(&h); err != nil {
				t.Fatal(err)
			}
			if h.Size != 0 {
				_, _ = w.Write([]byte("{}"))
			}
			_ = w.Close()
			if _, err := decodeAppProvisionArchive(output.Bytes()); err == nil {
				t.Fatal("unsafe entry accepted")
			}
		})
	}
	archive, target := provisionFixture(t)
	if err := os.Chmod(archive, 0644); err != nil {
		t.Fatal(err)
	}
	if err := provisionAppArchive(archive, target); err == nil {
		t.Fatal("public archive accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatal("rejected archive changed target", err)
	}
	os.Chmod(archive, 0600)
	link := target + "-symlink"
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := provisionAppArchive(archive, link); err == nil {
		t.Fatal("symlink target accepted")
	}
}

func TestAppProvisionInvalidCompleteBundleLeavesVolumeUntouched(t *testing.T) {
	archive, target := provisionFixture(t)
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	files, err := decodeAppProvisionArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	delete(files, "server.key")
	var output bytes.Buffer
	w := tar.NewWriter(&output)
	for name, content := range files {
		if err = w.WriteHeader(&tar.Header{Name: "bootstrap/" + name, Mode: 0600, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(content)
	}
	_ = w.Close()
	if err = os.WriteFile(archive, output.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := provisionAppArchive(archive, target); err == nil {
		t.Fatal("missing private input accepted")
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatal("partial bundle published", err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("failed validation altered volume mode", err)
	}
	bootstrap := filepath.Join(target, "bootstrap")
	if err := os.Mkdir(bootstrap, 0751); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if err := provisionAppArchive(archive, target); err == nil {
		t.Fatal("missing input accepted with existing empty bootstrap")
	}
	after, err := os.Lstat(bootstrap)
	if err != nil || !os.SameFile(before, after) || after.Mode() != before.Mode() {
		t.Fatal("invalid archive changed original bootstrap", err)
	}
	children, err := os.ReadDir(bootstrap)
	if err != nil || len(children) != 0 {
		t.Fatal("invalid archive populated bootstrap", err)
	}
}

func TestAppProvisionAcceptsOnlySoleRealEmptyBootstrap(t *testing.T) {
	archive, target := provisionFixture(t)
	bootstrap := filepath.Join(target, "bootstrap")
	if err := os.Mkdir(bootstrap, 0755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if err := provisionAppArchive(archive, target); err != nil {
		t.Fatal("image-populated empty bootstrap rejected", err)
	}
	after, err := os.Lstat(bootstrap)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0700 {
		t.Fatal("directory identity or permissions", err)
	}
	for name, prepare := range map[string]func(string) error{
		"populated bootstrap": func(target string) error {
			path := filepath.Join(target, "bootstrap")
			if err := os.Mkdir(path, 0755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(path, "existing"), []byte("preserve"), 0600)
		},
		"linked bootstrap": func(target string) error { return os.Symlink(filepath.Dir(target), filepath.Join(target, "bootstrap")) },
		"other directory":  func(target string) error { return os.Mkdir(filepath.Join(target, "api"), 0700) },
		"other alongside bootstrap": func(target string) error {
			if err := os.Mkdir(filepath.Join(target, "bootstrap"), 0700); err != nil {
				return err
			}
			return os.Mkdir(filepath.Join(target, "api"), 0700)
		},
	} {
		t.Run(name, func(t *testing.T) {
			archive, target := provisionFixture(t)
			if err := prepare(target); err != nil {
				t.Fatal(err)
			}
			if err := provisionAppArchive(archive, target); err == nil {
				t.Fatal("existing or linked state accepted")
			}
			info, err := os.Stat(target)
			if err != nil || info.Mode().Perm() != 0755 {
				t.Fatal("rejected target altered", err)
			}
		})
	}
}
