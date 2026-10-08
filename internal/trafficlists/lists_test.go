package trafficlists

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testDownloader struct {
	body []byte
	err  error
}

func (d *testDownloader) Download(context.Context, string) ([]byte, error) { return d.body, d.err }
func TestDomainListParsing(t *testing.T) {
	names, e := Parse([]byte("\ufeff# comment\r\n//comment\nYouTube.COM\n*.googlevideo.com\nyoutube.com # duplicate\n"))
	if e != nil || strings.Join(names, ",") != "googlevideo.com,youtube.com" {
		t.Fatal(names, e)
	}
	for _, body := range []string{"# empty", "https://secret.example/token", "192.0.2.0/24", "{\"domain\":\"site.example\"}", "ok.example\ninvalid;command"} {
		if _, e := Parse([]byte(body)); e == nil {
			t.Fatal("accepted invalid source")
		}
	}
	var b strings.Builder
	for i := 0; i < 4097; i++ {
		fmt.Fprintf(&b, "d%d.example\n", i)
	}
	if _, e := Parse([]byte(b.String())); e == nil {
		t.Fatal("truncated oversized list")
	}
}
func TestPrivateSnapshotFailureRetainsLastGood(t *testing.T) {
	directory, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(directory, 0700)
	d := &testDownloader{body: []byte("one.example\ntwo.example\n")}
	m := &Manager{directory: directory, downloader: d}
	spec := Spec{ID: "custom", Name: "My list", URL: "https://example.com/private-source-token"}
	first, e := m.Refresh(context.Background(), spec)
	if e != nil {
		t.Fatal(e)
	}
	d.body = []byte("bad source")
	if _, e = m.Refresh(context.Background(), spec); e == nil {
		t.Fatal("invalid refresh accepted")
	}
	d.err = errors.New("private-source-token")
	if _, e = m.Refresh(context.Background(), spec); e == nil || strings.Contains(e.Error(), "private-source-token") {
		t.Fatal("download leak")
	}
	after, e := m.Load("custom")
	if e != nil || first.SHA256 != after.SHA256 {
		t.Fatal("last good lost", e)
	}
	views, e := m.Views()
	if e != nil || len(views) != 1 || views[0].DomainCount != 2 {
		t.Fatal(views, e)
	}
	os.Remove(filepath.Join(directory, "custom.json"))
	os.Symlink("/etc/hosts", filepath.Join(directory, "custom.json"))
	if _, e = m.Load("custom"); e == nil {
		t.Fatal("symlink accepted")
	}
}

func TestSnapshotSourceBoundAndDigestValidation(t *testing.T) {
	directory, _ := filepath.EvalSymlinks(t.TempDir())
	d := &testDownloader{body: []byte("one.example\n")}
	m := &Manager{directory: directory, downloader: d}
	for i := 0; i < 64; i++ {
		if e := os.WriteFile(filepath.Join(directory, fmt.Sprintf("source-%d.json", i)), []byte("{}"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	spec := Spec{ID: "new-source", Name: "New source", URL: "https://example.com/domains"}
	if _, e := m.Refresh(context.Background(), spec); e == nil || e.Error() != "list_source_limit" {
		t.Fatal("unbounded snapshot registry", e)
	}
	os.Remove(filepath.Join(directory, "source-0.json"))
	if _, e := m.Refresh(context.Background(), spec); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(directory, spec.ID+".json")
	raw, _ := os.ReadFile(path)
	var snapshot Snapshot
	if e := json.Unmarshal(raw, &snapshot); e != nil {
		t.Fatal(e)
	}
	snapshot.SHA256 = strings.Repeat("g", 64)
	raw, _ = json.Marshal(snapshot)
	os.WriteFile(path, raw, 0600)
	if _, e := m.Load(spec.ID); e == nil {
		t.Fatal("invalid digest accepted")
	}
}
