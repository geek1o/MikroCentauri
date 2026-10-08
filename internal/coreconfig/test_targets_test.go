package coreconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestURLTestTargetsReachGeneratedEngineAndPublicPreview(t *testing.T) {
	for _, target := range []string{"google", "cloudflare", "apple", "mozilla"} {
		t.Run(target, func(t *testing.T) {
			m := fixture(t)
			m.Groups[0].TestTarget = target
			m.Groups[0].URL = "https://operator.example/check?token=private-canary"
			b, err := Generate(m)
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Outbounds []struct {
					Tag string `json:"tag"`
					URL string `json:"url"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal(b, &config); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, outbound := range config.Outbounds {
				if outbound.Tag == "auto" {
					found = true
					if outbound.URL != TestTargetURL(target) {
						t.Fatalf("unexpected URL %q", outbound.URL)
					}
				}
			}
			if !found {
				t.Fatal("automatic group missing")
			}
			preview := m.Preview().Groups[0]
			if preview.URL != "" || preview.TestTarget != target {
				t.Fatal("incorrect public projection")
			}
		})
	}
	m := fixture(t)
	m.Groups[0].TestTarget = "https://arbitrary.example/"
	if err := m.Validate(); err == nil {
		t.Fatal("unbounded target accepted")
	}
}

func TestLegacyURLTestTargetsPreservePrivateOperatorURL(t *testing.T) {
	m := fixture(t)
	m.Groups[0].URL = "https://operator.example/check?token=private-canary"
	if m.Groups[0].TestURL() != m.Groups[0].URL {
		t.Fatal("private operator target replaced")
	}
	b, _ := json.Marshal(m.Preview())
	if strings.Contains(string(b), "private-canary") {
		t.Fatal("private URL exposed")
	}
	if m.Preview().Groups[0].TestTarget != "" {
		t.Fatal("custom target misidentified")
	}
	m.Groups[0].URL = ""
	if m.Preview().Groups[0].TestTarget != "google" {
		t.Fatal("default target not identified")
	}
	m.Groups[0].URL = TestTargetURL("apple")
	if m.Preview().Groups[0].TestTarget != "apple" {
		t.Fatal("legacy public target not identified")
	}
}
