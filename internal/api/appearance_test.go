package api

import (
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestAppearanceProjectionPersistenceAndLegacyUpdate(t *testing.T) {
	s, _, token := setup(t, nil)
	w := call(s, "GET", "/api/v1/appearance", "", nil)
	var appearance Appearance
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &appearance) != nil || appearance.Sky != defaultSky() || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String(), w.Header())
	}
	sky := defaultSky()
	sky.Density = 30
	sky.Brightness = 40
	sky.Scale = 140
	sky.Motion = true
	sky.Login = false
	prefs := Preferences{Language: "en", Theme: "dark", TimeZone: "Europe/Moscow", Sky: &sky}
	w = call(s, "POST", "/api/v1/preferences", token, prefs)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	reopened := &Server{dir: s.dir}
	got, err := reopened.preferences()
	if err != nil || !reflect.DeepEqual(got, prefs) {
		t.Fatal(got, err)
	}
	w = call(s, "GET", "/api/v1/appearance", "", nil)
	if json.Unmarshal(w.Body.Bytes(), &appearance) != nil || appearance.Theme != "dark" || appearance.Sky != sky {
		t.Fatal(w.Body.String())
	}
	for _, private := range []string{"time_zone", "language", "Europe/Moscow", "secret", "password"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("public projection leaked", private)
		}
	}
	if call(s, "POST", "/api/v1/preferences", "", prefs).Code != 401 || call(s, "POST", "/api/v1/appearance", "", prefs).Code != 401 {
		t.Fatal("public write accepted")
	}
	legacy := Preferences{Language: "ru", Theme: "light", TimeZone: "UTC"}
	if w = call(s, "POST", "/api/v1/preferences", token, legacy); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	got, err = reopened.preferences()
	if err != nil || got.Sky == nil || *got.Sky != sky || got.Theme != "light" {
		t.Fatal("legacy update lost sky", got, err)
	}
	w = call(s, "GET", "/api/v1/backup", token, nil)
	var backup SafeExport
	if json.Unmarshal(w.Body.Bytes(), &backup) != nil || backup.Preferences == nil || !reflect.DeepEqual(backup.Preferences.Sky, &sky) {
		t.Fatal("backup lost appearance", w.Body.String())
	}
	for _, invalid := range []SkyPreferences{
		{Mode: "remote-url", Density: 30, Brightness: 40, Scale: 100},
		{Mode: "stars", Density: 101, Brightness: 40, Scale: 100},
		{Mode: "stars", Density: 30, Brightness: 0, Scale: 100},
		{Mode: "stars", Density: 30, Brightness: 40, Scale: 161},
	} {
		prefs.Sky = &invalid
		if call(s, "POST", "/api/v1/preferences", token, prefs).Code != 400 {
			t.Fatal("invalid sky accepted", invalid)
		}
	}
	after, _ := reopened.preferences()
	if !reflect.DeepEqual(got, after) {
		t.Fatal("invalid settings changed persistence")
	}
}

func TestAppearanceRetainsTransportAndClientGuards(t *testing.T) {
	s, _, _ := setup(t, nil)
	for _, bad := range []string{"tls", "origin", "client", "query"} {
		r := httptest.NewRequest("GET", "https://127.0.0.1:8443/api/v1/appearance", nil)
		r.TLS = &tls.ConnectionState{}
		r.RemoteAddr = "127.0.0.1:1234"
		switch bad {
		case "tls":
			r.TLS = nil
		case "origin":
			r.Header.Set("Origin", "https://other.example")
		case "client":
			r.RemoteAddr = "203.0.113.3:1234"
		case "query":
			r.URL.RawQuery = "theme=dark"
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(bad, w.Code)
		}
	}
}
