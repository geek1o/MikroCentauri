// Package webui serves the compiled, embedded administrative interface.
// The caller must enforce its TLS, Host, Origin and socket-client boundary.
package webui

import (
	"embed"
	"mime"
	"net/http"
	"path"
	"strings"
)

//go:embed dist/index.html dist/licenses.txt dist/assets/*
var files embed.FS

// Serve handles only the shell and exact build asset names; unknown paths never
// fall back to the shell. No filesystem, user data or source maps are exposed.
func Serve(w http.ResponseWriter, r *http.Request) bool {
	name := ""
	if r.URL.Path == "/" {
		name = "dist/index.html"
	} else if r.URL.Path == "/licenses.txt" {
		name = "dist/licenses.txt"
	} else if strings.HasPrefix(r.URL.Path, "/assets/") {
		leaf := strings.TrimPrefix(r.URL.Path, "/assets/")
		if leaf != "" && path.Base(leaf) == leaf && !strings.Contains(leaf, "\\") && (strings.HasSuffix(leaf, ".js") || strings.HasSuffix(leaf, ".css") || strings.HasSuffix(leaf, ".svg")) {
			name = "dist/assets/" + leaf
		}
	} else {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	data, err := files.ReadFile(name)
	if name == "" || err != nil || r.URL.EscapedPath() != r.URL.Path {
		http.NotFound(w, r)
		return true
	}
	w.Header().Set("Content-Type", mime.TypeByExtension(path.Ext(name)))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if r.Method == http.MethodGet {
		_, _ = w.Write(data)
	}
	return true
}
