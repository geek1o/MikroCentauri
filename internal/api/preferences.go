package api

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
	_ "time/tzdata"

	"mikrocentauri.local/core/internal/config"
)

// Preferences deliberately admits no arbitrary strings or secret-bearing URLs.
// Scheduler cadence is an operator setting, never changed by a backup restore.
type Preferences struct {
	Language string `json:"language"`
	Theme    string `json:"theme"`
	TimeZone string `json:"time_zone"`
}

func defaultPreferences() Preferences { return Preferences{"ru", "system", "UTC"} }
func (p Preferences) Validate() error {
	if p.Language != "ru" && p.Language != "en" {
		return errors.New("invalid language")
	}
	if p.Theme != "system" && p.Theme != "light" && p.Theme != "dark" {
		return errors.New("invalid theme")
	}
	if len(p.TimeZone) > 128 || p.TimeZone == "" || p.TimeZone == "Local" {
		return errors.New("invalid time zone")
	}
	if _, e := time.LoadLocation(p.TimeZone); e != nil {
		return errors.New("invalid time zone")
	}
	return nil
}
func (s *Server) preferences() (Preferences, error) {
	raw, e := privateRead(filepath.Join(s.dir, "preferences.json"), 4096)
	if os.IsNotExist(e) {
		return defaultPreferences(), nil
	}
	var p Preferences
	if e != nil || decode(raw, &p) != nil || p.Validate() != nil {
		return p, errors.New("preferences unavailable")
	}
	return p, nil
}
func (s *Server) savePreferences(p Preferences) error {
	if p.Validate() != nil {
		return errors.New("invalid preferences")
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return e
	}
	if config.WriteAtomic(filepath.Join(s.dir, "preferences.json"), raw) != nil {
		s.poisoned = true
		return errors.New("preferences persistence failed")
	}
	return nil
}
