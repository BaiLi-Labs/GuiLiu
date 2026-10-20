package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/auth"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/BaiLi-Labs/GuiLiu/internal/timeutil"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.auth.DevMode() {
		writeError(w, http.StatusBadRequest, "auth_disabled", "authentication is disabled in dev/mock mode")
		return
	}
	// Login CSRF defense: browsers send Origin on cross-site form/fetch posts.
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "cross-origin login rejected")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body: "+err.Error())
		return
	}
	principal, token, expires, err := s.auth.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrTooManyAttempts):
			w.Header().Set("Retry-After", "900")
			writeError(w, http.StatusTooManyRequests, "too_many_attempts", "too many login attempts, try again later")
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
		default:
			s.log.Error("login failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "login failed")
		}
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.auth.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
		MaxAge:   int(s.auth.SessionTTL().Seconds()),
	})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"token_type": "session",
		"expires_at": timeutil.Format(expires),
		"user":       principal.User,
	})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.FromContext(r.Context())
	if !ok {
		s.unauthorized(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       principal.User,
		"auth_type":  principal.Kind,
		"expires_at": timeutil.Format(principal.ExpiresAt),
		"dev_mode":   s.auth.DevMode(),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token, _ := tokenFromRequest(r)
	if err := s.auth.Logout(r.Context(), token); err != nil {
		s.log.Warn("logout failed", "error", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.auth.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.FromContext(r.Context())
	if !ok {
		s.unauthorized(w)
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body: "+err.Error())
		return
	}
	err := s.auth.ChangePassword(r.Context(), principal.User.ID, req.CurrentPassword, req.NewPassword)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusBadRequest, "invalid_credentials", "current password is incorrect")
		return
	case errors.Is(err, auth.ErrWeakPassword):
		writeError(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "user not found")
		return
	case err != nil:
		s.log.Error("change password failed", "user", principal.User.Username, "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "password update failed")
		return
	}
	// Every session was revoked; clear the browser cookie and force re-login.
	http.SetCookie(w, &http.Cookie{
		Name:     auth.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.auth.SecureCookies(),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.FromContext(r.Context())
	if !ok {
		s.unauthorized(w)
		return
	}
	keys, err := s.auth.ListAPIKeys(r.Context(), principal.User.ID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.FromContext(r.Context())
	if !ok {
		s.unauthorized(w)
		return
	}
	var req struct {
		Name          string `json:"name"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body: "+err.Error())
		return
	}
	ttl := time.Duration(0)
	if req.ExpiresInDays > 0 {
		ttl = time.Duration(req.ExpiresInDays) * 24 * time.Hour
	}
	raw, key, err := s.auth.CreateAPIKey(r.Context(), principal.User.ID, req.Name, ttl)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"key":     raw,
		"api_key": key,
	})
}

func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.FromContext(r.Context())
	if !ok {
		s.unauthorized(w)
		return
	}
	if err := s.auth.RevokeAPIKey(r.Context(), principal.User.ID, r.PathValue("id")); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
