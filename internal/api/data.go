package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" {
		n, e := strconv.ParseInt(cursor, 10, 64)
		if e != nil || n < 0 {
			writeError(w, 400, "invalid_request", "cursor must be a non-negative sequence")
			return
		}
	}
	limit := query.ChangeDefaultLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 || n > query.ChangeMaxLimit {
			writeError(w, 400, "invalid_request", fmt.Sprintf("limit must be between 1 and %d", query.ChangeMaxLimit))
			return
		}
		limit = n
	}
	high, err := s.store.SnapshotSequence(r.Context())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	if cursor != "" {
		n, _ := strconv.ParseInt(cursor, 10, 64)
		if n > high {
			writeError(w, 400, "invalid_request", "cursor is ahead of this database's change log")
			return
		}
	}
	page, err := s.store.ListAlertChanges(r.Context(), cursor, limit, r.URL.Query().Get("provider"), r.URL.Query().Get("account_id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, page)
}

func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	f, err := parseAlertFilter(r)
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	if err := query.PinSnapshot(r.Context(), s.store, &f); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	c, err := query.Coverage(r.Context(), s.store, s.registry, f, 3*s.cfg.Sync.Interval.Get())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) handleMapping(w http.ResponseWriter, r *http.Request) {
	d, ok := s.registry.Descriptor(r.PathValue("id"))
	if !ok {
		writeError(w, 404, "not_found", "provider not found")
		return
	}
	writeJSON(w, 200, map[string]any{"provider": d.ID, "mapper_version": d.MapperVersion, "fields": connector.MappingFor(d.ID)})
}

func (s *Server) handleRevision(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.Atoi(r.PathValue("revision"))
	if err != nil || n < 1 {
		writeError(w, 400, "invalid_request", "revision must be positive")
		return
	}
	rec, err := s.store.GetAlertRevision(r.Context(), r.PathValue("id"), n)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, 200, view.AlertFromRecord(rec, true))
}

func (s *Server) handleRevisionRaw(w http.ResponseWriter, r *http.Request) {
	n, e := strconv.Atoi(r.PathValue("revision"))
	if e != nil || n < 1 {
		writeError(w, 400, "invalid_request", "revision must be positive")
		return
	}
	rec, err := s.store.GetAlertRevision(r.Context(), r.PathValue("id"), n)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(200)
	_, _ = w.Write(rec.Raw)
}
