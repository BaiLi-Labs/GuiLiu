// Package webui serves the embedded single-page console.
package webui

import (
	"embed"
	"net/http"
)

//go:embed index.html
var assets embed.FS

// Handler serves the console for any non-API path (hash-based routing).
func Handler() http.Handler {
	page, _ := assets.ReadFile("index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(page)
	})
}
