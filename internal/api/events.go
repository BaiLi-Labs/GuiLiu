package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func (s *Server) handleSearchEvents(w http.ResponseWriter, r *http.Request) {
	var q model.EventSearch
	if err := decodeEventJSON(w, r, &q); err != nil {
		writeError(w, 400, "invalid_request", "invalid event query: "+err.Error())
		return
	}
	page, err := s.events.Search(r.Context(), q)
	if err != nil {
		s.writeEventError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, page)
}

func (s *Server) handleEventFields(w http.ResponseWriter, r *http.Request) {
	if err := allowedAssetQuery(r, "account_id"); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	fields, err := s.events.Fields(r.Context(), r.URL.Query().Get("account_id"))
	if err != nil {
		s.writeEventError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, fields)
}

func (s *Server) handleEventEvidence(w http.ResponseWriter, r *http.Request) {
	var ref model.EventReference
	if err := decodeEventJSON(w, r, &ref); err != nil {
		writeError(w, 400, "invalid_request", "invalid event reference: "+err.Error())
		return
	}
	evidence, err := s.events.Evidence(r.Context(), ref)
	if err != nil {
		s.writeEventError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, evidence)
}

func decodeEventJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if err := allowedAssetQuery(r); err != nil {
		return err
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return errors.New("request must contain one JSON object")
	}
	if observer, ok := w.(interface{ ObserveRequest(any) }); ok {
		observer.ObserveRequest(target)
	}
	return nil
}

func (s *Server) writeEventError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		s.writeStoreError(w, err)
		return
	}
	var ce *connector.Error
	if errors.As(err, &ce) {
		status := http.StatusBadGateway
		switch ce.Kind {
		case connector.KindConfig:
			status = http.StatusBadRequest
		case connector.KindAuth, connector.KindPermission, connector.KindDenied:
			status = http.StatusUnprocessableEntity
		case connector.KindNotFound:
			status = http.StatusNotFound
		case connector.KindThrottled:
			status = http.StatusTooManyRequests
		}
		writeJSON(w, status, map[string]any{"error": map[string]any{"code": ce.Code, "message": ce.Error(), "source_error": connector.SourceError(ce)}})
		return
	}
	writeError(w, 500, "event_query_failed", "event query could not be completed")
}
