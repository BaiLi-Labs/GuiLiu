// Package webui serves the embedded single-page console.
package webui

import (
	"embed"
	"net/http"
)

//go:embed index.html brands.svg
var assets embed.FS

// Handler serves the console for any non-API path (hash-based routing).
func Handler() http.Handler {
	page, _ := assets.ReadFile("index.html")
	brands, _ := assets.ReadFile("brands.svg")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path == "/brands.svg" {
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			_, _ = w.Write(brands)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(page)
	})
}
