package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// bundle uses fixed archive names and explicit redacted projections, never files
// from disk, raw router rows, private model bytes or engine stdout/stderr.
func (s *Server) bundle(ctx context.Context) ([]byte, error) {
	m, e := s.model()
	if e != nil {
		return nil, errors.New("model unavailable")
	}
	entries := []struct {
		name  string
		value any
	}{{"status.json", s.view()}, {"model-preview.json", m.Preview()}, {"events.json", s.logEvents()}}
	if s.opts.Router != nil {
		snapshot, e := s.opts.Router.Snapshot(ctx)
		if e != nil {
			entries = append(entries, struct {
				name  string
				value any
			}{"routeros.json", map[string]string{"error": "routeros_unavailable"}})
		} else {
			entries = append(entries, struct {
				name  string
				value any
			}{"routeros.json", snapshot})
		}
	}
	if s.opts.Subscriptions != nil {
		rows, e := s.opts.Subscriptions.List()
		if e != nil {
			return nil, errors.New("subscription summary unavailable")
		}
		entries = append(entries, struct {
			name  string
			value any
		}{"subscriptions.json", rows})
	}
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	total := 0
	for _, entry := range entries {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		b, e := json.Marshal(entry.value)
		if e != nil {
			return nil, errors.New("diagnostics serialization failed")
		}
		total += len(b)
		if total > 8<<20 {
			return nil, errors.New("diagnostics size limit")
		}
		if tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0600, Size: int64(len(b))}) != nil {
			return nil, errors.New("diagnostics archive failed")
		}
		if _, e = tw.Write(b); e != nil {
			return nil, errors.New("diagnostics archive failed")
		}
	}
	if tw.Close() != nil || gz.Close() != nil {
		return nil, errors.New("diagnostics archive failed")
	}
	return output.Bytes(), nil
}
func (s *Server) downloadBundle(w http.ResponseWriter, r *http.Request) {
	b, e := s.bundle(r.Context())
	if e != nil {
		reject(w, 503, "diagnostics_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="mikrocentauri-diagnostics.tar.gz"`)
	w.WriteHeader(200)
	_, _ = w.Write(b)
}
