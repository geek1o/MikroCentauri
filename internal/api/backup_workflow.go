package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"

	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/coreconfig"
)

// RestoreSettings lives inside the durable draft, making post-commit settings
// writes replayable if the process exits between core commit and completion.
type RestoreSettings struct {
	Preferences   *Preferences           `json:"preferences,omitempty"`
	Subscriptions []SubscriptionMetadata `json:"subscriptions,omitempty"`
}
type RestorePreview struct {
	Valid          bool                    `json:"valid"`
	Model          coreconfig.ModelPreview `json:"model"`
	Policy         PolicyPreview           `json:"policy"`
	Preferences    *Preferences            `json:"preferences,omitempty"`
	Subscriptions  []SubscriptionMetadata  `json:"subscriptions,omitempty"`
	ApplyPerformed bool                    `json:"apply_performed"`
	DraftRevision  uint64                  `json:"draft_revision,omitempty"`
}

func (s *Server) validateRestoreSettings(v *RestoreSettings) error {
	if v == nil {
		return nil
	}
	if v.Preferences != nil && v.Preferences.Validate() != nil {
		return errors.New("invalid preferences")
	}
	if len(v.Subscriptions) > 0 {
		if s.opts.Subscriptions == nil {
			return errors.New("subscription adapter required")
		}
		return s.opts.Subscriptions.ValidateMetadata(v.Subscriptions)
	}
	return nil
}
func (s *Server) writeDraft(d *draft) error {
	raw, e := json.Marshal(d)
	if e != nil {
		return e
	}
	if config.WriteAtomic(filepath.Join(s.dir, "draft.json"), raw) != nil {
		s.poisoned = true
		return errors.New("draft persistence failed")
	}
	s.draft = d
	s.plan = nil
	return nil
}
func (s *Server) saveDraftWithRestore(m coreconfig.Model, settings *RestoreSettings) error {
	if s.validateRestoreSettings(settings) != nil {
		return errors.New("restore settings unavailable")
	}
	if e := s.recoverRestoreSettings(); e != nil {
		return e
	}
	if s.draft != nil && s.draft.Restore != nil && s.view().Revision != s.draft.BaseRevision {
		return errors.New("restore commit requires recovery")
	}
	seq := uint64(1)
	if s.draft != nil {
		seq = s.draft.Sequence + 1
	}
	// Clone settings so subsequent caller edits cannot change the durable draft.
	raw, e := json.Marshal(settings)
	if e != nil {
		return e
	}
	var cloned *RestoreSettings
	if json.Unmarshal(raw, &cloned) != nil {
		return errors.New("invalid restore settings")
	}
	return s.writeDraft(&draft{Version: 1, Sequence: seq, BaseRevision: s.view().Revision, Model: m, Restore: cloned})
}
func modelDigest(m coreconfig.Model) [32]byte {
	raw, _ := json.Marshal(m)
	return sha256.Sum256(raw)
}

// recoverRestoreSettings must run after runtime recovery/apply and on reopening
// a server. It changes metadata only after proving this exact draft committed.
func (s *Server) recoverRestoreSettings() error {
	if s.draft == nil || s.draft.Restore == nil {
		return nil
	}
	if s.opts.Runtime == nil || s.view().Revision == s.draft.BaseRevision || s.view().Pending || !s.view().Ready {
		return nil
	}
	m, e := s.model()
	if e != nil || s.view().Revision != s.draft.BaseRevision+1 || modelDigest(m) != modelDigest(s.draft.Model) {
		return errors.New("restore commit requires recovery")
	}
	return s.applyRestoreSettings()
}
func (s *Server) applyRestoreSettings() error {
	if s.draft == nil || s.draft.Restore == nil {
		return nil
	}
	settings := s.draft.Restore
	if s.validateRestoreSettings(settings) != nil {
		return errors.New("restore settings unavailable")
	}
	if len(settings.Subscriptions) > 0 && s.opts.Subscriptions.RestoreMetadata(settings.Subscriptions) != nil {
		s.poisoned = true
		return errors.New("restore settings persistence failed")
	}
	if settings.Preferences != nil && s.savePreferences(*settings.Preferences) != nil {
		return errors.New("restore settings persistence failed")
	}
	d := *s.draft
	d.Restore = nil
	return s.writeDraft(&d)
}
func (s *Server) backupGet(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/api/v1/preferences":
		p, e := s.preferences()
		if e != nil {
			reject(w, 503, "preferences_unavailable")
		} else {
			reply(w, 200, p)
		}
	case "/api/v1/backup":
		m, e := s.model()
		if e != nil {
			reject(w, 503, "model_unavailable")
			return true
		}
		b := Export(m)
		p, e := s.preferences()
		if e != nil {
			reject(w, 503, "preferences_unavailable")
			return true
		}
		b.Preferences = &p
		if s.opts.Subscriptions != nil {
			b.Subscriptions, e = s.opts.Subscriptions.Metadata()
			if e != nil {
				reject(w, 503, "subscriptions_unavailable")
				return true
			}
		}
		reply(w, 200, b)
	default:
		return false
	}
	return true
}
func (s *Server) backupPost(w http.ResponseWriter, r *http.Request, raw []byte, id string) bool {
	switch r.URL.Path {
	case "/api/v1/preferences":
		var p Preferences
		if decode(raw, &p) != nil || p.Validate() != nil {
			reject(w, 400, "invalid_preferences")
			return true
		}
		if p.Sky == nil {
			previous, err := s.preferences()
			if err != nil {
				reject(w, 503, "preferences_unavailable")
				return true
			}
			p.Sky = previous.Sky
		}
		if s.savePreferences(p) != nil {
			reject(w, 503, "preferences_persistence_failed")
			return true
		}
		s.event("preferences_saved", id)
		reply(w, 200, p)
	case "/api/v1/backup/restore-preview", "/api/v1/backup/restore-draft":
		var input SafeExport
		if decode(raw, &input) != nil {
			reject(w, 400, "invalid_backup")
			return true
		}
		current, e := s.model()
		if e != nil {
			reject(w, 503, "model_unavailable")
			return true
		}
		m, e := Restore(input, current)
		settings := &RestoreSettings{Preferences: input.Preferences, Subscriptions: input.Subscriptions}
		if e != nil || s.validateRestoreSettings(settings) != nil {
			reject(w, 422, "backup_requires_matching_secrets")
			return true
		}
		if s.validate(r.Context(), s.view().Revision, m) != nil {
			reject(w, 422, "validation_failed")
			return true
		}
		result := RestorePreview{Valid: true, Model: m.Preview(), Policy: policyPreview(m), Preferences: input.Preferences, Subscriptions: input.Subscriptions}
		if r.URL.Path == "/api/v1/backup/restore-draft" {
			if s.saveDraftWithRestore(m, settings) != nil {
				reject(w, 503, "draft_persistence_failed")
				return true
			}
			result.DraftRevision = s.draft.Sequence
			s.event("restore_draft_saved", id)
		}
		reply(w, 200, result)
	default:
		return false
	}
	return true
}
