package api

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/trafficlists"
)

func TestSectionsSnapshotsAreIsolatedReviewableAndRestorable(t *testing.T) {
	runtime := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 7, Ready: true}}
	s, _, token := setup(t, runtime)
	body := "site.example\nvideo.example\n"
	requests := 0
	source := listSourceFixture(t, s, func(w http.ResponseWriter, r *http.Request) { requests++; fmt.Fprint(w, body) })
	spec := trafficlists.Spec{ID: "shared", Name: "Shared", URL: source.URL + "/private-token"}
	// Prepare a cached source without adding any standalone route.
	snapshot, e := s.opts.TrafficLists.Refresh(t.Context(), spec)
	if e != nil {
		t.Fatal(e)
	}
	sections := []coreconfig.Section{{ID: "video", Name: "Видео", Enabled: true, Outbound: runtime.m.Groups[0].ID, Lists: []coreconfig.SectionList{{ID: spec.ID}}}, {ID: "exception", Name: "Exception", Enabled: true, Outbound: "direct", Lists: []coreconfig.SectionList{{ID: spec.ID}}}}
	save := func(seq uint64, values []coreconfig.Section, refresh string) int {
		w := call(s, "POST", "/api/v1/sections/save", token, SectionsRequest{DraftRevision: seq, Sections: values, RefreshID: refresh})
		if w.Code == 200 && strings.Contains(w.Body.String(), "private-token") {
			t.Fatal("URL leaked")
		}
		return w.Code
	}
	if code := save(0, sections, ""); code != 200 {
		t.Fatal(code)
	}
	if requests != 1 || runtime.calls != 0 || runtime.checks != 0 {
		t.Fatal("save unexpectedly downloaded/applied")
	}
	if len(s.draft.Model.Rules) != len(runtime.m.Rules) || len(s.draft.Model.Sections) != 2 {
		t.Fatal("sections polluted standalone rules")
	}
	if s.draft.Model.Sections[0].Lists[0].SHA256 != snapshot.SHA256 || len(s.draft.Model.DNS.SelectedDomains) < 2 {
		t.Fatal("immutable snapshots or literal DNS admission missing")
	}
	if code := save(0, sections, "video"); code != 409 || requests != 1 {
		t.Fatal("stale request fetched data")
	}
	body = "new.example\n"
	if code := save(s.draft.Sequence, sections, "video"); code != 200 {
		t.Fatal(code)
	}
	a, b := s.draft.Model.Sections[0].Lists[0], s.draft.Model.Sections[1].Lists[0]
	if a.SHA256 == b.SHA256 || a.Domains[0] != "new.example" || len(b.Domains) != 2 {
		t.Fatal("refresh changed another section snapshot")
	}
	// Ordinary policy edits and safe backups preserve sections and their snapshots.
	m := s.draft.Model
	changed, e := mergePolicy(m, DraftPolicyRequest{Mode: m.Mode, Groups: m.Preview().Groups, Policy: policyPreview(m)})
	if e != nil || len(changed.Sections) != 2 {
		t.Fatal("policy edit lost sections", e)
	}
	restored, e := Restore(Export(m), runtime.m)
	if e != nil || restored.Sections[0].Lists[0].SHA256 != a.SHA256 {
		t.Fatal("backup restore lost section", e)
	}
	seq := s.draft.Sequence
	body = "malformed data"
	if save(seq, sections, "video") != 422 || s.draft.Sequence != seq {
		t.Fatal("failed download replaced draft")
	}
	// Disabling/deleting only changes draft; active engine stays untouched.
	sections = s.draft.Model.Sections
	sections[0].Enabled = false
	if save(seq, sections, "") != 200 || s.draft.Model.Sections[0].Enabled {
		t.Fatal("disable failed")
	}
	if save(s.draft.Sequence, sections[1:], "") != 200 || len(s.draft.Model.Sections) != 1 || runtime.calls != 0 {
		t.Fatal("delete failed or touched engine")
	}
}
func TestSectionDownloadDoesNotBlockAndCannotOverwriteNewDraft(t *testing.T) {
	runtime := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 7, Ready: true}}
	s, _, token := setup(t, runtime)
	started, release := make(chan struct{}), make(chan struct{})
	blocked := false
	source := listSourceFixture(t, s, func(w http.ResponseWriter, r *http.Request) {
		if blocked {
			close(started)
			<-release
		}
		fmt.Fprint(w, "site.example\n")
	})
	_, e := s.opts.TrafficLists.Refresh(t.Context(), trafficlists.Spec{ID: "cached", Name: "Cached", URL: source.URL})
	if e != nil {
		t.Fatal(e)
	}
	section := coreconfig.Section{ID: "video", Name: "Video", Enabled: true, Outbound: runtime.m.Groups[0].ID, Lists: []coreconfig.SectionList{{ID: "cached"}}}
	blocked = true
	result := make(chan int, 1)
	go func() {
		result <- call(s, "POST", "/api/v1/sections/save", token, SectionsRequest{Sections: []coreconfig.Section{section}, RefreshID: "video"}).Code
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("no download")
	}
	health := make(chan int, 1)
	go func() { health <- call(s, "GET", "/api/v1/health/ready", token, nil).Code }()
	select {
	case code := <-health:
		if code != 200 {
			t.Fatal(code)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("download blocked health")
	}
	in := DraftPolicyRequest{Mode: runtime.m.Mode, Groups: runtime.m.Preview().Groups, Policy: policyPreview(runtime.m)}
	if call(s, "POST", "/api/v1/config/draft/policy", token, in).Code != 200 {
		close(release)
		t.Fatal("parallel edit failed")
	}
	seq := s.draft.Sequence
	close(release)
	if code := <-result; code != 409 || s.draft.Sequence != seq || len(s.draft.Model.Sections) != 0 {
		t.Fatal("stale download overwrote newer draft", code)
	}
}

func TestSectionCanCreateItsOwnManualOrAutomaticSelector(t *testing.T) {
	for _, typ := range []string{"selector", "urltest"} {
		t.Run(typ, func(t *testing.T) {
			runtime := &fakeRuntime{m: fixture(t), v: RuntimeView{Revision: 7, Ready: true}}
			s, _, token := setup(t, runtime)
			groups := runtime.m.Preview().Groups
			own := coreconfig.Group{ID: "section-selector", Type: typ, Members: []string{runtime.m.Endpoints[0].ID}}
			if typ == "urltest" {
				own.Interval = "3m"
				own.Tolerance = 50
			} else {
				own.Selected = own.Members[0]
			}
			groups = append(groups, own)
			section := coreconfig.Section{ID: "ai", Name: "AI", Enabled: true, Outbound: own.ID, Domains: []string{"ai.example"}}
			w := call(s, "POST", "/api/v1/sections/save", token, SectionsRequest{Groups: &groups, Sections: []coreconfig.Section{section}})
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			if s.draft.Model.Groups[len(groups)-1].Type != typ || runtime.calls != 0 {
				t.Fatal("selector missing or applied prematurely")
			}
			originalURLs := map[string]string{}
			for _, g := range runtime.m.Groups {
				originalURLs[g.ID] = g.URL
			}
			for _, g := range s.draft.Model.Groups {
				if g.ID != own.ID && g.URL != originalURLs[g.ID] {
					t.Fatal("private probe URL lost")
				}
			}
			// Removing a selector still referenced by a section must fail atomically.
			groups = runtime.m.Preview().Groups
			seq := s.draft.Sequence
			w = call(s, "POST", "/api/v1/sections/save", token, SectionsRequest{DraftRevision: seq, Groups: &groups, Sections: []coreconfig.Section{section}})
			if w.Code != 400 || s.draft.Sequence != seq {
				t.Fatal("dangling section route accepted")
			}
		})
	}
}

func TestLegacyPolicyEditPreservesSectionsAndCannotForgeSnapshots(t *testing.T) {
	m := fixture(t)
	m.Sections = []coreconfig.Section{{ID: "retained", Name: "Retained", Enabled: true, Outbound: "direct", Domains: []string{"site.example"}}}
	policy := policyPreview(m)
	policy.Sections = nil
	result, e := mergePolicy(m, DraftPolicyRequest{Mode: m.Mode, Groups: m.Preview().Groups, Policy: policy})
	if e != nil || len(result.Sections) != 1 {
		t.Fatal("legacy policy deleted section", e)
	}
	policy.Sections = []coreconfig.Section{{ID: "forged", Name: "Forged", Enabled: true, Outbound: "direct", Domains: []string{"other.example"}}}
	if _, e = mergePolicy(m, DraftPolicyRequest{Mode: m.Mode, Groups: m.Preview().Groups, Policy: policy}); e == nil {
		t.Fatal("generic policy bypassed snapshot-aware section workflow")
	}
}
