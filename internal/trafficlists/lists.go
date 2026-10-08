// Package trafficlists downloads operator-selected domain suffix lists into
// private snapshots. Activating a new snapshot always requires a configuration plan.
package trafficlists

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"mikrocentauri.local/core/internal/config"
	"mikrocentauri.local/core/internal/fakeip"
	"mikrocentauri.local/core/internal/subscriptions"
)

type CatalogEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

func Catalog() []CatalogEntry {
	base := "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/"
	return []CatalogEntry{
		{"youtube", "YouTube", "Видео и связанные домены", base + "Services/youtube.lst"},
		{"discord", "Discord", "Домены Discord; голосовые IP-подсети сюда не входят", base + "Services/discord.lst"},
		{"google-ai", "Google AI", "Gemini и сервисы Google AI", base + "Services/google_ai.lst"},
		{"telegram", "Telegram", "Домены Telegram; IP-подсети сюда не входят", base + "Services/telegram.lst"},
		{"meta", "Meta", "Домены Facebook, Instagram и связанных сервисов", base + "Services/meta.lst"},
		{"twitter", "X / Twitter", "Домены X и Twitter", base + "Services/twitter.lst"},
		{"tiktok", "TikTok", "Домены TikTok", base + "Services/tiktok.lst"},
		{"roblox", "Roblox", "Домены Roblox", base + "Services/roblox.lst"},
		{"google-play", "Google Play", "Домены магазина Google Play", base + "Services/google_play.lst"},
		{"google-meet", "Google Meet", "Домены видеоконференций Google Meet", base + "Services/google_meet.lst"},
		{"geoblock", "GeoBlock", "Сервисы с региональными ограничениями", base + "Categories/geoblock.lst"},
	}
}

type Spec struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}
type Snapshot struct {
	Spec      Spec      `json:"spec"`
	Domains   []string  `json:"domains"`
	SHA256    string    `json:"sha256"`
	UpdatedAt time.Time `json:"updated_at"`
}
type View struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DomainCount int       `json:"domain_count"`
	SHA256      string    `json:"sha256"`
	UpdatedAt   time.Time `json:"updated_at"`
	Sample      []string  `json:"sample"`
}
type Downloader interface {
	Download(context.Context, string) ([]byte, error)
}
type Manager struct {
	directory  string
	downloader Downloader
	mu         sync.Mutex
}

var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]{0,57}$`)

func ValidSpec(s Spec) bool {
	return identifier.MatchString(s.ID) && len(s.Name) > 0 && len(s.Name) <= 128 && !strings.ContainsAny(s.Name, "\x00\r\n")
}
func New(directory string, policy subscriptions.Policy) (*Manager, error) {
	downloader, e := subscriptions.New(directory, policy)
	if e != nil {
		return nil, e
	}
	return &Manager{directory: directory, downloader: downloader}, nil
}
func Parse(data []byte) ([]string, error) {
	if len(data) == 0 || len(data) > 4<<20 {
		return nil, errors.New("list_size_limit")
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		line = strings.TrimPrefix(line, "*.")
		line = strings.TrimPrefix(line, ".")
		domain, e := fakeip.CanonicalDomain(line)
		if e != nil || !strings.Contains(domain, ".") {
			return nil, errors.New("invalid_domain_list")
		}
		seen[domain] = true
		if len(seen) > 4096 {
			return nil, errors.New("list_domain_limit")
		}
	}
	if len(seen) == 0 {
		return nil, errors.New("empty_domain_list")
	}
	result := make([]string, 0, len(seen))
	for n := range seen {
		result = append(result, n)
	}
	sort.Strings(result)
	return result, nil
}
func (m *Manager) Refresh(ctx context.Context, s Spec) (Snapshot, error) {
	if !ValidSpec(s) {
		return Snapshot{}, errors.New("invalid_list_source")
	}
	data, e := m.downloader.Download(ctx, s.URL)
	if e != nil {
		return Snapshot{}, errors.New("list_download_failed")
	}
	domains, e := Parse(data)
	if e != nil {
		return Snapshot{}, e
	}
	digest := sha256.Sum256(data)
	next := Snapshot{Spec: s, Domains: domains, SHA256: hex.EncodeToString(digest[:]), UpdatedAt: time.Now().UTC()}
	raw, _ := json.Marshal(next)
	m.mu.Lock()
	defer m.mu.Unlock()
	path := filepath.Join(m.directory, s.ID+".json")
	if _, e := os.Lstat(path); os.IsNotExist(e) {
		files, e := os.ReadDir(m.directory)
		if e != nil {
			return Snapshot{}, errors.New("list_persistence_failed")
		}
		count := 0
		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".json") {
				count++
			}
		}
		if count >= 64 {
			return Snapshot{}, errors.New("list_source_limit")
		}
	}
	if st, e := os.Lstat(path); e == nil && (!st.Mode().IsRegular() || st.Mode().Perm() != 0600) {
		return Snapshot{}, errors.New("list_state_invalid")
	}
	if e = config.WriteAtomic(path, raw); e != nil {
		return Snapshot{}, errors.New("list_persistence_failed")
	}
	return next, nil
}
func (m *Manager) Load(id string) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.load(id)
}
func (m *Manager) load(id string) (Snapshot, error) {
	var s Snapshot
	if !identifier.MatchString(id) {
		return s, errors.New("invalid_list_source")
	}
	path := filepath.Join(m.directory, id+".json")
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 2<<20 {
		return s, errors.New("list_state_invalid")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return s, errors.New("list_state_invalid")
	}
	defer f.Close()
	st, e = f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 2<<20 {
		return s, errors.New("list_state_invalid")
	}
	raw, e := io.ReadAll(io.LimitReader(f, (2<<20)+1))
	if e != nil || json.Unmarshal(raw, &s) != nil || s.Spec.ID != id || !ValidSpec(s.Spec) || len(s.SHA256) != 64 || len(s.Domains) == 0 || len(s.Domains) > 4096 {
		return Snapshot{}, errors.New("list_state_invalid")
	}
	if _, e := hex.DecodeString(s.SHA256); e != nil {
		return Snapshot{}, errors.New("list_state_invalid")
	}
	domains, e := Parse([]byte(strings.Join(s.Domains, "\n")))
	if e != nil || strings.Join(domains, "\n") != strings.Join(s.Domains, "\n") {
		return Snapshot{}, errors.New("list_state_invalid")
	}
	return s, nil
}
func (m *Manager) Views() ([]View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	files, e := os.ReadDir(m.directory)
	if e != nil {
		return nil, e
	}
	result := []View{}
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(f.Name(), ".json")
		s, e := m.load(id)
		if e != nil {
			return nil, e
		}
		sample := s.Domains
		if len(sample) > 8 {
			sample = sample[:8]
		}
		result = append(result, View{s.Spec.ID, s.Spec.Name, len(s.Domains), s.SHA256, s.UpdatedAt, append([]string{}, sample...)})
	}
	return result, nil
}
