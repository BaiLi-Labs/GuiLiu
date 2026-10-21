// Package api exposes the GuiLiu REST surface. The API is deliberately boring:
// stable JSON, cursor-free offset pagination, explicit errors, read-only by
// default. Agents and humans consume the same endpoints.
package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/asset"
	"github.com/BaiLi-Labs/GuiLiu/internal/auth"
	"github.com/BaiLi-Labs/GuiLiu/internal/config"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/ingest"
	"github.com/BaiLi-Labs/GuiLiu/internal/mcp"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/BaiLi-Labs/GuiLiu/internal/version"
	"github.com/BaiLi-Labs/GuiLiu/web"
)

// Server wires the HTTP surface.
type Server struct {
	cfg       *config.Config
	store     store.Store
	engine    *ingest.Engine
	registry  *connector.Registry
	cipher    *secret.Cipher
	auth      *auth.Service
	mcp       *mcp.Server
	log       *slog.Logger
	startedAt time.Time
	assets    *asset.Service
}

func New(cfg *config.Config, st store.Store, engine *ingest.Engine, registry *connector.Registry, cipher *secret.Cipher, mcpServer *mcp.Server, authService *auth.Service, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg:       cfg,
		store:     st,
		engine:    engine,
		registry:  registry,
		cipher:    cipher,
		auth:      authService,
		mcp:       mcpServer,
		log:       log,
		startedAt: time.Now().UTC(),
		assets:    asset.New(st, cipher, cfg.Mock),
	}
}

func (s *Server) Handler() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /auth/me", s.handleMe)
	api.HandleFunc("POST /auth/logout", s.handleLogout)
	api.HandleFunc("POST /auth/password", s.handleChangePassword)
	api.HandleFunc("GET /auth/keys", s.handleListAPIKeys)
	api.HandleFunc("POST /auth/keys", s.handleCreateAPIKey)
	api.HandleFunc("DELETE /auth/keys/{id}", s.handleRevokeAPIKey)

	api.HandleFunc("GET /meta", s.handleMeta)
	api.HandleFunc("GET /providers", s.handleProviders)
	api.HandleFunc("GET /providers/{id}/mapping", s.handleMapping)
	api.HandleFunc("GET /coverage", s.handleCoverage)
	api.HandleFunc("GET /assets", s.handleListAssets)
	api.HandleFunc("GET /assets/{id}", s.handleGetAsset)
	api.HandleFunc("GET /assets/{id}/findings", s.handleAssetFindings)
	api.HandleFunc("GET /assets/{id}/revisions/{revision}/components/{component}/raw", s.handleAssetRaw)
	api.HandleFunc("GET /alerts/{id}/asset-context", s.handleAssetContext)
	api.HandleFunc("POST /accounts/{id}/assets/refresh", s.adminOnly(s.handleAssetRefresh))
	api.HandleFunc("GET /alerts/changes", s.handleChanges)
	api.HandleFunc("GET /alerts/{id}/revisions/{revision}", s.handleRevision)
	api.HandleFunc("GET /alerts/{id}/revisions/{revision}/raw", s.handleRevisionRaw)

	api.HandleFunc("GET /accounts", s.handleListAccounts)
	api.HandleFunc("POST /accounts", s.adminOnly(s.handleCreateAccount))
	api.HandleFunc("GET /accounts/{id}", s.handleGetAccount)
	api.HandleFunc("PATCH /accounts/{id}", s.adminOnly(s.handlePatchAccount))
	api.HandleFunc("DELETE /accounts/{id}", s.adminOnly(s.handleDeleteAccount))
	api.HandleFunc("POST /accounts/{id}/check", s.adminOnly(s.handleCheckAccount))
	api.HandleFunc("POST /accounts/{id}/sync", s.adminOnly(s.handleSyncAccount))
	api.HandleFunc("GET /accounts/{id}/health", s.handleAccountHealth)
	api.HandleFunc("GET /accounts/{id}/failures", s.handleAccountFailures)

	api.HandleFunc("POST /sync", s.adminOnly(s.handleSyncAll))
	api.HandleFunc("GET /sync-runs", s.handleSyncRuns)

	api.HandleFunc("GET /alerts", s.handleListAlerts)
	api.HandleFunc("GET /alerts/groups", s.handleListAlertGroups)
	api.HandleFunc("GET /alerts/{id}", s.handleGetAlert)
	api.HandleFunc("GET /alerts/{id}/raw", s.handleGetAlertRaw)
	api.HandleFunc("GET /alerts/{id}/revisions", s.handleGetAlertRevisions)
	api.HandleFunc("PATCH /alerts/{id}", s.adminOnly(s.handlePatchAlert))
	api.HandleFunc("GET /stats", s.handleStats)

	api.HandleFunc("GET /health", s.handleHealth)

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", s.handleHealthz)
	root.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	root.Handle("/api/v1/", http.StripPrefix("/api/v1", s.requireAuth(api)))
	root.Handle("/mcp", s.requireAuth(http.HandlerFunc(s.mcp.ServeHTTP)))
	root.Handle("/mcp/", s.requireAuth(http.HandlerFunc(s.mcp.ServeHTTP)))
	root.Handle("/", web.Handler())

	return s.recoverer(s.accessLog(root))
}

// ------------------------------------------------------------- middleware

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.auth.DevMode() {
			ctx := auth.WithPrincipal(r.Context(), s.auth.DevPrincipal())
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		token, fromCookie := tokenFromRequest(r)
		if token == "" {
			s.unauthorized(w)
			return
		}
		principal, err := s.auth.Authenticate(r.Context(), token)
		if err != nil {
			s.log.Debug("authentication failed", "error", err)
			s.unauthorized(w)
			return
		}
		// Cookie auth is SameSite=Lax; additionally reject cross-origin
		// state-changing requests as defense in depth.
		if fromCookie && isUnsafeMethod(r.Method) && !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "forbidden", "cross-origin request rejected")
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), principal)))
	})
}

func (s *Server) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := auth.FromContext(r.Context())
		if !ok || !principal.IsAdmin() {
			writeError(w, http.StatusForbidden, "forbidden", "admin role required")
			return
		}
		next(w, r)
	}
}

func (s *Server) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="guiliu"`)
	writeError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
}

func tokenFromRequest(r *http.Request) (string, bool) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:]), false
	}
	if h := strings.TrimSpace(r.Header.Get("X-API-Key")); h != "" {
		return h, false
	}
	if c, err := r.Cookie(auth.CookieName); err == nil && c.Value != "" {
		return c.Value, true
	}
	return "", false
}

func isUnsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/mcp") {
			s.log.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		}
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic", "error", v, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func (s *Server) writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "a resource with that name already exists")
	default:
		s.log.Error("store error", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "storage operation failed")
	}
}

func (s *Server) writeConnectorError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	if connector.AuthError(err) {
		status = http.StatusUnprocessableEntity
	}
	writeError(w, status, "connector_error", err.Error())
}

func metaVersion() string {
	if version.Version == "" {
		return "dev"
	}
	return version.Version
}
