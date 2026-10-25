package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/intake"
)

func newPushToken() (string, error) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	return "glp_" + base64.RawURLEncoding.EncodeToString(secret[:]), nil
}

func (s *Server) configManagesPushToken(name string) bool {
	for _, account := range s.cfg.Accounts {
		if account.Name == name && strings.TrimSpace(account.PushToken) != "" {
			return true
		}
	}
	return false
}

// Tokens are returned only on creation or rotation. Ordinary account reads
// expose a configured flag; neither plaintext nor the stored hash is returned.
func (s *Server) handleRotatePushToken(w http.ResponseWriter, r *http.Request) {
	account, err := s.store.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	desc, ok := s.registry.Descriptor(account.Provider)
	if !ok || len(desc.PushFormats) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "push_unsupported", "this source does not accept pushed records")
		return
	}
	if s.configManagesPushToken(account.Name) {
		writeError(w, http.StatusConflict, "config_managed", "push token is managed by the configuration file; update push_token there and restart")
		return
	}
	token, err := newPushToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "cannot generate push token")
		return
	}
	if account.Options == nil {
		account.Options = map[string]string{}
	}
	account.Options["push_token_sha256"] = intake.HashToken(token)
	if err := s.store.UpdateAccount(r.Context(), account, nil); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]string{
		"account_name": account.Name,
		"push_token":   token,
		"webhook_path": "/ingest/" + url.PathEscape(account.Name),
	})
}
