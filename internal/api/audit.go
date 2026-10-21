package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/audit"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/google/uuid"
)

func (s *Server) auditHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") && r.URL.Path != "/mcp" && !strings.HasPrefix(r.URL.Path, "/mcp/") {
			next.ServeHTTP(w, r)
			return
		}
		id := uuid.NewString()
		w.Header().Set("X-Request-ID", id)
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			peer = r.RemoteAddr
		}
		if net.ParseIP(peer) == nil {
			peer = ""
		}
		surface := "rest"
		if strings.HasPrefix(r.URL.Path, "/mcp") {
			surface = "mcp_http"
		}
		ctx, span, err := audit.Begin(r.Context(), s.store, s.log, model.AuditEvent{RequestID: id, Surface: surface, Method: r.Method, Operation: r.Method + " " + audit.Text(r.URL.Path), Path: audit.Text(r.URL.Path), PeerIP: peer, Parameters: audit.Parameters(r.URL.Query())})
		if err != nil {
			writeError(w, 503, "audit_unavailable", "access audit is unavailable; operation was not started")
			return
		}
		rec := &auditWriter{ResponseWriter: w, span: span}
		defer func() {
			span.Event.HTTPStatus = rec.status
			if rec.status == 0 {
				span.Event.HTTPStatus = 200
			}
			span.Event.ResponseBytes = rec.bytes
			outcome, code := "success", ""
			if span.Event.HTTPStatus >= 400 {
				outcome = "error"
			}
			if span.Event.HTTPStatus == 401 || span.Event.HTTPStatus == 403 {
				outcome = "denied"
			}
			if v, ok := span.Event.Summary["error_code"].(string); ok {
				code = v
				if outcome == "success" {
					outcome = "error"
				}
			}
			if r.Context().Err() != nil && outcome == "success" {
				outcome = "cancelled"
				code = "request_cancelled"
			}
			span.Finish(r.Context(), outcome, code)
		}()
		next.ServeHTTP(rec, r.WithContext(ctx))
	})
}

type auditWriter struct {
	http.ResponseWriter
	span   *audit.Span
	status int
	bytes  int64
}

func (w *auditWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *auditWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	if w.status != 0 {
		return
	}
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *auditWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, e := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, e
}
func (w *auditWriter) ObserveResult(v any) { w.span.Event.Summary = audit.Summary(v) }
func (w *auditWriter) ObserveRequest(v any) {
	for k, value := range audit.Parameters(v) {
		w.span.Event.Parameters[k] = value
	}
}

func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if err := allowedAssetQuery(r, "request_id", "user_id", "username", "api_key_id", "surface", "operation", "tool", "outcome", "start", "end", "before_sequence", "limit"); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	q := r.URL.Query()
	limit, err := assetLimit(r)
	if err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	f := model.AuditFilter{RequestID: q.Get("request_id"), UserID: q.Get("user_id"), Username: q.Get("username"), APIKeyID: q.Get("api_key_id"), Surface: q.Get("surface"), Operation: q.Get("operation"), Tool: q.Get("tool"), Outcome: q.Get("outcome"), Limit: limit + 1}
	if raw := q.Get("before_sequence"); raw != "" {
		f.BeforeSequence, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || f.BeforeSequence < 1 {
			writeError(w, 400, "invalid_request", "before_sequence must be positive")
			return
		}
	}
	for _, v := range []struct {
		key string
		dst **time.Time
	}{{"start", &f.Start}, {"end", &f.End}} {
		if raw := q.Get(v.key); raw != "" {
			at, e := time.Parse(time.RFC3339Nano, raw)
			if e != nil {
				writeError(w, 400, "invalid_request", "start/end must use RFC3339")
				return
			}
			*v.dst = &at
		}
	}
	if f.Start != nil && f.End != nil && f.Start.After(*f.End) {
		writeError(w, 400, "invalid_request", "start must not exceed end")
		return
	}
	items, err := s.store.ListAuditEvents(r.Context(), f)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	next := ""
	if more {
		next = strconv.FormatInt(items[len(items)-1].Sequence, 10)
	}
	writeJSON(w, 200, map[string]any{"events": items, "has_more": more, "next_cursor": next, "limit": limit, "retention_days": s.cfg.Audit.RetentionDays, "limitations": []string{"in_progress_does_not_prove_completion", "local_database_not_tamper_proof", "free_text_is_fingerprinted", "response_references_are_bounded"}})
}
