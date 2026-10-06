package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mikrocentauri.local/core/internal/coreconfig"
)

func TestSafeBackupMigrationPreservesEngineOwnedCache(t *testing.T) {
	current := fixture(t)
	backup := Export(current)
	raw, _ := json.Marshal(backup)
	if backup.Schema != SafeBackupSchema || backup.DNS.CachePath != "" || strings.Contains(string(raw), current.DNS.CachePath) || strings.Contains(string(raw), "secret-password") {
		t.Fatal("safe export contains local state or credentials", string(raw))
	}
	backup.DNS.SelectedDomains = []string{"selected.example.test"}
	restored, e := Restore(backup, current)
	if e != nil || restored.DNS.CachePath != current.DNS.CachePath || len(restored.DNS.SelectedDomains) != 1 {
		t.Fatal("restore changed cache identity", e)
	}
	// Historical backups contained an installation-specific cache path. It must
	// be discarded, even when supplied by an otherwise matching old backup.
	backup.Schema = 1
	backup.DNS.CachePath = "/other/router/allocator.db"
	restored, e = Restore(backup, current)
	if e != nil || restored.DNS.CachePath != current.DNS.CachePath {
		t.Fatal(e, restored.DNS.CachePath)
	}
	backup.Schema = SafeBackupSchema
	if _, e = Restore(backup, current); e == nil {
		t.Fatal("schema two accepted private path")
	}
	backup.DNS.CachePath = ""
	backup.Schema++
	if _, e = Restore(backup, current); e == nil {
		t.Fatal("future schema accepted")
	}
	backup.Schema = SafeBackupSchema
	backup.Format = "mikrocentauri-encrypted-full"
	if _, e = Restore(backup, current); e == nil {
		t.Fatal("unsupported encrypted format accepted")
	}
}
func backupRequest(s *Server, path string, input any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(input)
	r := httptest.NewRequest("POST", path, bytes.NewReader(raw))
	w := httptest.NewRecorder()
	if !s.backupPost(w, r, raw, "test-request") {
		panic("route not handled")
	}
	return w
}
func TestRestoreDraftIsReviewedBeforeApplyAndRecoversSettings(t *testing.T) {
	rt := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 7, Ready: true}}
	s, _, _ := setup(t, rt)
	backup := Export(rt.m)
	preferences := Preferences{Language: "en", Theme: "dark", TimeZone: "Europe/Moscow"}
	backup.Preferences = &preferences
	backup.DNS.SelectedDomains = []string{"selected.example.test"}
	w := backupRequest(s, "/api/v1/backup/restore-preview", backup)
	if w.Code != 200 || s.draft != nil || rt.calls != 0 || rt.checks != 1 {
		t.Fatal(w.Body.String())
	}
	w = backupRequest(s, "/api/v1/backup/restore-draft", backup)
	if w.Code != 200 || s.draft == nil || s.draft.Restore == nil || rt.calls != 0 || len(rt.m.DNS.SelectedDomains) != 0 {
		t.Fatal(w.Body.String())
	}
	if p, _ := s.preferences(); p != defaultPreferences() {
		t.Fatal("draft applied preferences")
	}
	// Simulate a process exit after the network commit but before metadata
	// completion. The persisted draft is the recovery journal.
	committed, _ := s.draft.Model.Clone()
	rt.m = committed
	rt.v.Revision++
	raw, e := privateRead(filepath.Join(s.dir, "draft.json"), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	var durable draft
	if decode(raw, &durable) != nil {
		t.Fatal("invalid draft journal")
	}
	reopened := &Server{opts: s.opts, dir: s.dir, draft: &durable}
	if e := reopened.recoverRestoreSettings(); e != nil {
		t.Fatal(e)
	}
	if p, e := reopened.preferences(); e != nil || p != preferences {
		t.Fatal("settings not recovered", p, e)
	}
	if reopened.draft.Restore != nil {
		t.Fatal("finished journal retained")
	}
	raw, _ = privateRead(filepath.Join(s.dir, "draft.json"), 4<<20)
	durable = draft{}
	if decode(raw, &durable) != nil || durable.Restore != nil {
		t.Fatal("completion not durable")
	}
	if rt.calls != 0 || rt.m.DNS.CachePath != fixture(t).DNS.CachePath {
		t.Fatal("recovery mutated core or cache")
	}
}
func TestRestoreSettingsRequireExactCommittedDraft(t *testing.T) {
	rt := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 7, Ready: true}}
	s, _, _ := setup(t, rt)
	p := Preferences{"en", "light", "UTC"}
	if e := s.saveDraftWithRestore(rt.m, &RestoreSettings{Preferences: &p}); e != nil {
		t.Fatal(e)
	}
	rt.v.Revision = 9
	if s.recoverRestoreSettings() == nil {
		t.Fatal("unrelated revision accepted")
	}
	if got, _ := s.preferences(); got != defaultPreferences() {
		t.Fatal("unrelated commit applied settings")
	}
	if s.saveDraft(coreconfig.Model{}) == nil {
		t.Fatal("uncompleted restoration overwritten")
	}
	rt.v.Revision = 8
	rt.m.DNS.SelectedDomains = []string{"changed.example.test"}
	if s.recoverRestoreSettings() == nil {
		t.Fatal("different model accepted")
	}
	if got, _ := s.preferences(); got != defaultPreferences() {
		t.Fatal("different model applied settings")
	}
}
func TestPreferencesStrictPersistenceAndBackup(t *testing.T) {
	s, _, _ := setup(t, nil)
	p := Preferences{"en", "dark", "America/New_York"}
	if w := backupRequest(s, "/api/v1/preferences", p); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	reopened := &Server{dir: s.dir}
	if got, e := reopened.preferences(); e != nil || got != p {
		t.Fatal(got, e)
	}
	w := httptest.NewRecorder()
	if !s.backupGet(w, httptest.NewRequest("GET", "/api/v1/backup", nil)) || w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var exported SafeExport
	if json.Unmarshal(w.Body.Bytes(), &exported) != nil || exported.Preferences == nil || *exported.Preferences != p {
		t.Fatal(w.Body.String())
	}
	for _, invalid := range []Preferences{{"zz", "dark", "UTC"}, {"en", "custom", "UTC"}, {"en", "light", "Local"}, {"en", "light", "../../etc/shadow"}} {
		if w := backupRequest(s, "/api/v1/preferences", invalid); w.Code != 400 {
			t.Fatal("invalid preference accepted", invalid)
		}
	}
	if e := os.WriteFile(filepath.Join(s.dir, "preferences.json"), []byte(`{"language":"en","language":"ru","theme":"dark","time_zone":"UTC"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := reopened.preferences(); e == nil {
		t.Fatal("ambiguous persisted preferences accepted")
	}
}

func TestRestoreMetadataAndPreferencesReplayAfterPartialSettingsWrite(t *testing.T) {
	rt := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 7, Ready: true}}
	s, _, _ := setup(t, rt)
	registry, manager, _ := workflowRegistry(t)
	s.opts.Subscriptions = registry
	backup := Export(rt.m)
	backup.Subscriptions = []SubscriptionMetadata{{ID: "provider", Include: "restored"}}
	pref := Preferences{"en", "dark", "UTC"}
	backup.Preferences = &pref
	if w := backupRequest(s, "/api/v1/backup/restore-draft", backup); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	// Fail the second settings write after metadata has reached disk. The
	// journal survives, and replay reuses the same private provider URL.
	preferencesPath := filepath.Join(s.dir, "preferences.json")
	if os.Mkdir(preferencesPath, 0700) != nil {
		t.Fatal("cannot inject persistence failure")
	}
	rt.m, _ = s.draft.Model.Clone()
	rt.v.Revision++
	if s.recoverRestoreSettings() == nil || !s.poisoned || s.draft.Restore == nil {
		t.Fatal("partial write lost durable recovery state")
	}
	metadata, e := registry.Metadata()
	if e != nil || metadata[0].Include != "restored" {
		t.Fatal(metadata, e)
	}
	if e := os.Remove(preferencesPath); e != nil {
		t.Fatal(e)
	}
	raw, e := privateRead(filepath.Join(s.dir, "draft.json"), 4<<20)
	if e != nil {
		t.Fatal(e)
	}
	var durable draft
	if decode(raw, &durable) != nil {
		t.Fatal("missing restore journal")
	}
	reopened := &Server{opts: s.opts, dir: s.dir, draft: &durable}
	if e := reopened.recoverRestoreSettings(); e != nil {
		t.Fatal(e)
	}
	if got, e := reopened.preferences(); e != nil || got != pref {
		t.Fatal(got, e)
	}
	w := httptest.NewRecorder()
	reopened.backupGet(w, httptest.NewRequest("GET", "/api/v1/backup", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "subscription-private-token") || strings.Contains(w.Body.String(), "subscription-secret") {
		t.Fatal(w.Body.String())
	}
	if manager.refreshes != 0 || rt.calls != 0 {
		t.Fatal("restore refreshed provider or reapplied core")
	}
	if registry.specs[0].URL != "https://provider.example/subscription-private-token" {
		t.Fatal("private provider URL overwritten")
	}
}

func TestRestoreAPIUsesNormalPlanApplyAndRejectsChangedMetadata(t *testing.T) {
	rt := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 7, Ready: true}}
	s, _, token := setup(t, rt)
	registry, _, _ := workflowRegistry(t)
	s.opts.Subscriptions = registry
	backup := Export(rt.m)
	backup.Subscriptions = []SubscriptionMetadata{{ID: "provider", Include: "restored"}}
	p := Preferences{"en", "dark", "UTC"}
	backup.Preferences = &p
	backup.DNS.SelectedDomains = []string{"selected.example.test"}
	w := call(s, "POST", "/api/v1/backup/restore-draft", token, backup)
	if w.Code != 200 || rt.calls != 0 {
		t.Fatal(w.Body.String())
	}
	w = call(s, "POST", "/api/v1/config/plan", token, map[string]any{"draft_revision": 1})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	planID := field(t, w, "plan_id")
	if w = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": planID}); w.Code != 200 || rt.calls != 1 {
		t.Fatal(w.Body.String())
	}
	if got, e := s.preferences(); e != nil || got != p {
		t.Fatal(got, e)
	}
	if s.draft.Restore != nil || rt.m.DNS.CachePath != fixture(t).DNS.CachePath {
		t.Fatal("restore completion or cache identity invalid")
	}
	if w = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": planID}); w.Code != 409 || rt.calls != 1 {
		t.Fatal("restore plan replay")
	}
	w = call(s, "POST", "/api/v1/backup/restore-draft", token, backup)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = call(s, "POST", "/api/v1/config/plan", token, map[string]any{"draft_revision": 2})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	planID = field(t, w, "plan_id")
	if e := registry.Delete("provider"); e != nil {
		t.Fatal(e)
	}
	if w = call(s, "POST", "/api/v1/config/apply", token, map[string]any{"plan_id": planID}); w.Code != 409 || rt.calls != 1 || !rt.v.Ready {
		t.Fatal("changed restore metadata committed core", w.Code, w.Body.String())
	}
}
