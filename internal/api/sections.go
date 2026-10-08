package api

import (
	"context"
	"net/http"
	"sort"
	"time"

	"mikrocentauri.local/core/internal/coreconfig"
	"mikrocentauri.local/core/internal/trafficlists"
)

type SectionsRequest struct {
	Groups        *[]coreconfig.Group  `json:"groups,omitempty"`
	DraftRevision uint64               `json:"draft_revision"`
	Sections      []coreconfig.Section `json:"sections"`
	RefreshID     string               `json:"refresh_id,omitempty"`
}

// Saving sections downloads only new sources or the explicitly refreshed
// section. Existing sections retain reviewed snapshots even if another section
// refreshes the same catalog ID. CAS is rechecked after releasing the API lock.
func (s *Server) sectionsPost(w http.ResponseWriter, r *http.Request, raw []byte, id string) bool {
	if r.URL.Path != "/api/v1/sections/save" {
		return false
	}
	var in SectionsRequest
	if decode(raw, &in) != nil || len(in.Sections) > 64 {
		reject(w, 400, "invalid_request")
		return true
	}
	m, base, e := s.editableModel(in.DraftRevision)
	if e != nil {
		reject(w, 409, "stale_draft")
		return true
	}
	if in.Groups != nil {
		urls := map[string]string{}
		for _, group := range m.Groups {
			urls[group.ID] = group.URL
		}
		m.Groups = append([]coreconfig.Group{}, (*in.Groups)...)
		for i, group := range m.Groups {
			if group.URL != "" {
				reject(w, 400, "invalid_section")
				return true
			}
			m.Groups[i].URL = urls[group.ID]
		}
	}
	old := map[string]coreconfig.Section{}
	for _, section := range m.Sections {
		old[section.ID] = section
	}
	specs := map[string]trafficlists.Spec{}
	fetched := map[string]coreconfig.SectionList{}
	seen := map[string]bool{}
	refreshFound := in.RefreshID == ""
	for i, section := range in.Sections {
		if seen[section.ID] || len(section.Lists) > 32 {
			reject(w, 400, "invalid_section")
			return true
		}
		seen[section.ID] = true
		refresh := section.ID == in.RefreshID
		if refresh {
			refreshFound = true
		}
		listSeen := map[string]bool{}
		for j, list := range section.Lists {
			if listSeen[list.ID] {
				reject(w, 400, "invalid_list_source")
				return true
			}
			listSeen[list.ID] = true
			var preserved *coreconfig.SectionList
			if !refresh {
				for _, prior := range old[section.ID].Lists {
					if prior.ID == list.ID {
						value := prior
						preserved = &value
						break
					}
				}
			}
			if preserved != nil {
				in.Sections[i].Lists[j] = *preserved
				continue
			}
			snapshot, loadErr := s.opts.TrafficLists.Load(list.ID)
			if !refresh && loadErr == nil {
				in.Sections[i].Lists[j] = sectionList(snapshot)
				continue
			}
			var spec trafficlists.Spec
			for _, entry := range trafficlists.Catalog() {
				if entry.ID == list.ID {
					spec = trafficlists.Spec{ID: entry.ID, Name: entry.Name, Kind: entry.Kind, URL: entry.URL}
					break
				}
			}
			if spec.ID == "" && loadErr == nil {
				spec = snapshot.Spec
			}
			if spec.ID == "" {
				reject(w, 400, "invalid_list_source")
				return true
			}
			specs[list.ID] = spec
			// A temporary valid target permits schema validation before network I/O.
			in.Sections[i].Lists[j] = coreconfig.SectionList{ID: list.ID, Name: spec.Name, SHA256: "0000000000000000000000000000000000000000000000000000000000000000", Domains: []string{"validation.example"}}
		}
	}
	if !refreshFound {
		reject(w, 400, "invalid_section")
		return true
	}
	candidate := m
	candidate.Sections = in.Sections
	if candidate.Validate() != nil {
		reject(w, 400, "invalid_section")
		return true
	}
	if len(specs) > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		keys := []string{}
		for key := range specs {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		err := func() error {
			s.mu.Unlock()
			defer s.mu.Lock()
			for _, key := range keys {
				snapshot, err := s.opts.TrafficLists.Refresh(ctx, specs[key])
				if err != nil {
					return err
				}
				fetched[key] = sectionList(snapshot)
			}
			return nil
		}()
		if err != nil {
			reject(w, 422, "list_download_failed")
			return true
		}
	}
	reloaded, newBase, e := s.editableModel(in.DraftRevision)
	if e != nil || newBase != base {
		reject(w, 409, "stale_draft")
		return true
	}
	for i, section := range in.Sections {
		for j, list := range section.Lists {
			// Preserve snapshots in other sections sharing a refreshed source.
			if _, needed := specs[list.ID]; needed {
				preserve := false
				if section.ID != in.RefreshID {
					for _, prior := range old[section.ID].Lists {
						if prior.ID == list.ID {
							preserve = true
							break
						}
					}
				}
				if !preserve {
					in.Sections[i].Lists[j] = fetched[list.ID]
				}
			}
		}
	}
	reloaded.Groups = m.Groups
	reloaded.Sections = in.Sections
	admitted := map[string]bool{}
	for _, domain := range reloaded.DNS.SelectedDomains {
		admitted[domain] = true
	}
	for _, rule := range reloaded.SectionRules() {
		if !rule.IsEnabled() {
			continue
		}
		for _, domain := range rule.Suffixes {
			admitted[domain] = true
		}
	}
	reloaded.DNS.SelectedDomains = []string{}
	for domain := range admitted {
		reloaded.DNS.SelectedDomains = append(reloaded.DNS.SelectedDomains, domain)
	}
	sort.Strings(reloaded.DNS.SelectedDomains)
	if reloaded.Validate() != nil {
		reject(w, 400, "invalid_section")
		return true
	}
	if s.view().Revision != base || s.view().Pending {
		reject(w, 409, "stale_draft")
		return true
	}
	if s.saveDraft(reloaded) != nil {
		reject(w, 503, "draft_persistence_failed")
		return true
	}
	s.event("sections_draft_saved", id)
	reply(w, 200, DraftPolicyResult{s.draft.Sequence, base, reloaded.Preview(), policyPreview(reloaded)})
	return true
}
func sectionList(snapshot trafficlists.Snapshot) coreconfig.SectionList {
	return coreconfig.SectionList{ID: snapshot.Spec.ID, Name: snapshot.Spec.Name, SHA256: snapshot.SHA256, Domains: append([]string{}, snapshot.Domains...), Prefixes: append([]string{}, snapshot.Prefixes...)}
}
