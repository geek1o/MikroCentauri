package coreconfig

import (
	"errors"
	"sort"
	"strings"
)

// Section owns immutable list contents as well as its route and device scope.
// Downloaded source URLs and credentials never belong to this model projection.
type SectionList struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	SHA256   string   `json:"sha256"`
	Domains  []string `json:"domains,omitempty"`
	Prefixes []string `json:"prefixes,omitempty"`
}
type Section struct {
	ID               string        `json:"id"`
	Name             string        `json:"name"`
	Enabled          bool          `json:"enabled"`
	Outbound         string        `json:"outbound"`
	Domains          []string      `json:"domains,omitempty"`
	DestinationCIDRs []string      `json:"destination_cidrs,omitempty"`
	SourceCIDRs      []string      `json:"source_cidrs,omitempty"`
	Lists            []SectionList `json:"lists,omitempty"`
	AllTraffic       bool          `json:"all_traffic,omitempty"`
}

func uniqueSorted(items []string) []string {
	seen := map[string]bool{}
	for _, item := range items {
		seen[item] = true
	}
	result := []string{}
	for item := range seen {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

// Sections run in declared order before ordinary priority-zero rules. Advanced
// negative-priority rules and global device policies can still precede them.
// Domain and destination-address targets are separate OR branches; the device
// scope is ANDed into each branch. An empty target never means all traffic.
func (m Model) SectionRules() []Rule {
	result := []Rule{}
	for i, s := range m.Sections {
		domains := append([]string{}, s.Domains...)
		prefixes := append([]string{}, s.DestinationCIDRs...)
		for _, list := range s.Lists {
			domains = append(domains, list.Domains...)
			prefixes = append(prefixes, list.Prefixes...)
		}
		add := func(kind string, d, p []string) {
			enabled := s.Enabled
			result = append(result, Rule{ID: "section-" + s.ID + "-" + kind, Name: s.Name, Enabled: &enabled, Priority: -1000 + i, SourceCIDRs: append([]string{}, s.SourceCIDRs...), Suffixes: d, DestinationCIDRs: p, Outbound: s.Outbound})
		}
		if s.AllTraffic {
			add("all", nil, nil)
		} else {
			if len(domains) > 0 {
				add("domains", uniqueSorted(domains), nil)
			}
			if len(prefixes) > 0 {
				add("networks", nil, uniqueSorted(prefixes))
			}
		}
	}
	return result
}
func (m Model) validateSections() error {
	if len(m.Sections) > 64 {
		return errors.New("section bound exceeded")
	}
	seen := map[string]bool{}
	for _, s := range m.Sections {
		if !idPattern.MatchString(s.ID) || len(s.ID) > 40 || seen[s.ID] || strings.TrimSpace(s.Name) == "" || len(s.Name) > 256 || strings.ContainsAny(s.Name, "\x00\r\n") {
			return errors.New("invalid section identity")
		}
		seen[s.ID] = true
		if len(s.Lists) > 32 || domains(s.Domains) != nil {
			return errors.New("invalid section targets")
		}
		sources := map[string]bool{}
		count := len(s.Domains) + len(s.DestinationCIDRs)
		for _, list := range s.Lists {
			if !idPattern.MatchString(list.ID) || sources[list.ID] || len(list.Name) > 256 || strings.ContainsAny(list.Name, "\x00\r\n") || len(list.SHA256) != 64 || strings.Trim(list.SHA256, "0123456789abcdef") != "" || domains(list.Domains) != nil || len(list.Domains)+len(list.Prefixes) == 0 {
				return errors.New("invalid section list snapshot")
			}
			sources[list.ID] = true
			count += len(list.Domains) + len(list.Prefixes)
		}
		if count > 4096 || (!s.AllTraffic && count == 0) || (s.AllTraffic && (count != 0 || len(s.SourceCIDRs) == 0)) {
			return errors.New("section requires targets or explicit device scope")
		}
	}
	return nil
}

// Flatten once for a generation pass; rebuilding list unions for each admitted
// DNS name would multiply the cost of large community snapshots.
func (m Model) withSectionRules() Model {
	m.Rules = append(append([]Rule{}, m.Rules...), m.SectionRules()...)
	m.Sections = nil
	return m
}
