package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/BaiLi-Labs/GuiLiu/internal/asset"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func assetLimit(r *http.Request) (int, error) {
	n := 20
	var err error
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err = strconv.Atoi(raw)
	}
	if err != nil || n < 1 || n > 100 {
		return 0, fmt.Errorf("limit must be between 1 and 100")
	}
	return n, nil
}
func allowedAssetQuery(r *http.Request, keys ...string) error {
	for key, values := range r.URL.Query() {
		found := false
		for _, allowed := range keys {
			if key == allowed {
				found = true
			}
		}
		if !found || len(values) != 1 {
			return fmt.Errorf("unsupported or repeated query parameter: %s", key)
		}
	}
	return nil
}
func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	err := allowedAssetQuery(r, "provider", "account_id", "account_uid", "region", "resource_id", "resource_type", "after_id", "limit")
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	limit, err := assetLimit(r)
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	q := r.URL.Query()
	result, err := query.AssetList(r.Context(), s.store, model.AssetFilter{Provider: q.Get("provider"), AccountID: q.Get("account_id"), AccountUID: q.Get("account_uid"), Region: q.Get("region"), ResourceID: q.Get("resource_id"), ResourceType: q.Get("resource_type"), AfterID: q.Get("after_id"), Limit: limit})
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (s *Server) handleAssetLookup(w http.ResponseWriter, r *http.Request) {
	if err := allowedAssetQuery(r, "provider", "account_id", "account_uid", "region", "resource_type", "resource_id"); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	q := r.URL.Query()
	result, err := query.LookupAsset(r.Context(), s.store, model.AssetFilter{Provider: q.Get("provider"), AccountID: q.Get("account_id"), AccountUID: q.Get("account_uid"), Region: q.Get("region"), ResourceType: q.Get("resource_type"), ResourceID: q.Get("resource_id")})
	if err != nil {
		if errors.Is(err, query.ErrInvalidAssetReference) {
			writeError(w, 400, "invalid_request", err.Error())
		} else {
			s.writeStoreError(w, err)
		}
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	if err := allowedAssetQuery(r, "revision"); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	revision := 0
	if raw := r.URL.Query().Get("revision"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 {
			writeError(w, 400, "invalid_request", "revision must be positive")
			return
		}
		revision = n
	}
	a, err := s.store.GetAsset(r.Context(), r.PathValue("id"), revision)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, query.AssetView(*a))
}
func (s *Server) handleAssetContext(w http.ResponseWriter, r *http.Request) {
	if err := allowedAssetQuery(r, "snapshot_sequence", "revision"); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	a, err := s.readFinding(r)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeStoreError(w, err)
		} else {
			writeError(w, 400, "invalid_request", err.Error())
		}
		return
	}
	result, err := query.ContextForAlert(r.Context(), s.store, a)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) readFinding(r *http.Request) (*model.AlertRecord, error) {
	q := r.URL.Query()
	revision := 0
	var seq *int64
	if raw := q.Get("revision"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 {
			return nil, fmt.Errorf("%w: revision must be positive", query.ErrInvalidFindingSelection)
		}
		revision = n
	}
	if raw := q.Get("snapshot_sequence"); raw != "" {
		n, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || n < 0 {
			return nil, fmt.Errorf("%w: snapshot_sequence must be non-negative", query.ErrInvalidFindingSelection)
		}
		seq = &n
	}
	return query.ReadFinding(r.Context(), s.store, r.PathValue("id"), revision, seq)
}
func (s *Server) handleAssetFindings(w http.ResponseWriter, r *http.Request) {
	if err := allowedAssetQuery(r, "after_id", "limit", "snapshot_sequence"); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	limit, err := assetLimit(r)
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	var seq *int64
	if raw := r.URL.Query().Get("snapshot_sequence"); raw != "" {
		n, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || n < 0 {
			writeError(w, 400, "invalid_request", "invalid snapshot_sequence")
			return
		}
		seq = &n
	}
	result, err := query.AssetFindings(r.Context(), s.store, r.PathValue("id"), r.URL.Query().Get("after_id"), limit, seq)
	if err != nil {
		if errors.Is(err, query.ErrInvalidFindingSelection) || errors.Is(err, query.ErrInvalidAssetReference) {
			writeError(w, 400, "invalid_request", err.Error())
		} else {
			s.writeStoreError(w, err)
		}
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handleAssetRaw(w http.ResponseWriter, r *http.Request) {
	n, e := strconv.Atoi(r.PathValue("revision"))
	if e != nil || n < 1 {
		writeError(w, 400, "invalid_request", "invalid revision")
		return
	}
	a, err := s.store.GetAsset(r.Context(), r.PathValue("id"), n)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	c, ok := a.Components[r.PathValue("component")]
	if !ok || len(c.Raw) == 0 {
		writeError(w, 404, "not_found", "component evidence not available")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write(c.Raw)
}
func (s *Server) handleAssetRefresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ResourceID   string `json:"resource_id"`
		ResourceType string `json:"resource_type"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, 400, "invalid_request", "resource_id is required")
		return
	}
	result, err := s.assets.Refresh(r.Context(), r.PathValue("id"), body.ResourceType, body.ResourceID)
	if err != nil {
		if errors.Is(err, asset.ErrInvalidRequest) {
			writeError(w, 400, "invalid_request", err.Error())
		} else {
			s.writeStoreError(w, err)
		}
		return
	}
	if result.Asset != nil {
		v := query.AssetView(*result.Asset)
		result.Asset = &v
	}
	writeJSON(w, 200, result)
}
