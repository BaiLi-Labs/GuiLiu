package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/credential"
	"github.com/BaiLi-Labs/GuiLiu/internal/ingest"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/BaiLi-Labs/GuiLiu/internal/timeutil"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"name":                  "guiliu",
		"version":               metaVersion(),
		"ocsf_version":          "1.6.0",
		"started_at":            timeutil.Format(s.startedAt),
		"auth_enabled":          !s.auth.DevMode(),
		"dev_mode":              s.auth.DevMode(),
		"mock":                  s.cfg.Mock,
		"session_ttl_seconds":   int64(s.auth.SessionTTL().Seconds()),
		"sync_enabled":          s.cfg.Sync.Enabled,
		"sync_interval_seconds": int64(s.cfg.Sync.Interval.Get().Seconds()),
		"providers":             s.sortedDescriptors(),
		"mcp_endpoint":          "/mcp",
		"api_prefix":            "/api/v1",
	})
}

func (s *Server) handleProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"providers": s.sortedDescriptors()})
}

func (s *Server) sortedDescriptors() []connector.Descriptor {
	descriptors := s.registry.List()
	sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].ID < descriptors[j].ID })
	return descriptors
}

// ---------------------------------------------------------------- accounts

func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.store.ListAccounts(r.Context())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	items := make([]view.Account, 0, len(accounts))
	for i := range accounts {
		v, err := s.accountView(r.Context(), &accounts[i], true)
		if err != nil {
			s.writeStoreError(w, err)
			return
		}
		items = append(items, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": items})
}

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	acct, err := s.store.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	v, err := s.accountView(r.Context(), acct, true)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

type createAccountRequest struct {
	Name               string            `json:"name"`
	Provider           string            `json:"provider"`
	AccountUID         string            `json:"account_uid"`
	Region             string            `json:"region"`
	AccessKeyID        string            `json:"access_key_id"`
	AccessKeySecret    string            `json:"access_key_secret"`
	SessionToken       string            `json:"session_token"`
	ServiceAccountJSON string            `json:"service_account_json"`
	Enabled            *bool             `json:"enabled"`
	Options            map[string]string `json:"options"`
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req createAccountRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body: "+err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "name is required")
		return
	}
	desc, ok := s.registry.Descriptor(req.Provider)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "unknown provider: "+req.Provider)
		return
	}
	cred := connector.Credential{
		AccessKeyID:        req.AccessKeyID,
		AccessKeySecret:    req.AccessKeySecret,
		SessionToken:       req.SessionToken,
		ServiceAccountJSON: req.ServiceAccountJSON,
	}
	if missing := missingCredentialFields(desc, cred); len(missing) > 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing required credential: "+strings.Join(missing, ", "))
		return
	}
	if req.Options == nil {
		req.Options = map[string]string{}
	}
	if missing := missingOptionFields(desc, req.Options); len(missing) > 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing required option: "+strings.Join(missing, ", "))
		return
	}
	enc, err := s.encryptCredential(cred)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "cannot encrypt credential")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	acct := &model.Account{
		Name:                req.Name,
		Provider:            req.Provider,
		AccountUID:          strings.TrimSpace(req.AccountUID),
		Region:              strings.TrimSpace(req.Region),
		Enabled:             enabled,
		Options:             req.Options,
		CredentialEncrypted: enc,
		AccessKeyHint:       credential.HintFor(cred),
		CredentialSet:       true,
	}
	if err := s.store.CreateAccount(r.Context(), acct); err != nil {
		s.writeStoreError(w, err)
		return
	}
	v, _ := s.accountView(r.Context(), acct, true)
	writeJSON(w, http.StatusCreated, v)
}

type patchAccountRequest struct {
	Name               *string           `json:"name"`
	AccountUID         *string           `json:"account_uid"`
	Region             *string           `json:"region"`
	Enabled            *bool             `json:"enabled"`
	Options            map[string]string `json:"options"`
	AccessKeyID        *string           `json:"access_key_id"`
	AccessKeySecret    *string           `json:"access_key_secret"`
	SessionToken       *string           `json:"session_token"`
	ServiceAccountJSON *string           `json:"service_account_json"`
}

func (s *Server) handlePatchAccount(w http.ResponseWriter, r *http.Request) {
	acct, err := s.store.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	var req patchAccountRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body: "+err.Error())
		return
	}
	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "name cannot be empty")
			return
		}
		acct.Name = strings.TrimSpace(*req.Name)
	}
	if req.AccountUID != nil {
		acct.AccountUID = strings.TrimSpace(*req.AccountUID)
	}
	if req.Region != nil {
		acct.Region = strings.TrimSpace(*req.Region)
	}
	if req.Enabled != nil {
		acct.Enabled = *req.Enabled
	}
	if req.Options != nil {
		acct.Options = req.Options
	}
	desc, ok := s.registry.Descriptor(acct.Provider)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "unknown provider: "+acct.Provider)
		return
	}
	if missing := missingOptionFields(desc, acct.Options); len(missing) > 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "missing required option: "+strings.Join(missing, ", "))
		return
	}
	var encoded *string
	if req.AccessKeyID != nil || req.AccessKeySecret != nil || req.SessionToken != nil || req.ServiceAccountJSON != nil {
		cred, err := s.decryptCredential(r.Context(), acct.ID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "cannot update credentials: "+err.Error())
			return
		}
		if req.AccessKeyID != nil {
			cred.AccessKeyID = *req.AccessKeyID
		}
		if req.AccessKeySecret != nil {
			cred.AccessKeySecret = *req.AccessKeySecret
		}
		if req.SessionToken != nil {
			cred.SessionToken = *req.SessionToken
		}
		if req.ServiceAccountJSON != nil {
			cred.ServiceAccountJSON = *req.ServiceAccountJSON
		}
		if missing := missingCredentialFields(desc, *cred); len(missing) > 0 {
			writeError(w, http.StatusBadRequest, "invalid_request", "missing required credential: "+strings.Join(missing, ", "))
			return
		}
		enc, err := s.encryptCredential(*cred)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "cannot encrypt credential")
			return
		}
		acct.AccessKeyHint = credential.HintFor(*cred)
		acct.CredentialSet = true
		encoded = &enc
	}
	if err := s.store.UpdateAccount(r.Context(), acct, encoded); err != nil {
		s.writeStoreError(w, err)
		return
	}
	v, _ := s.accountView(r.Context(), acct, true)
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteAccount(r.Context(), r.PathValue("id")); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCheckAccount(w http.ResponseWriter, r *http.Request) {
	acct, err := s.store.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	conn, err := s.buildConnector(r.Context(), acct)
	if err != nil {
		s.writeConnectorError(w, err)
		return
	}
	defer connector.Close(conn)
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	if err := conn.Check(ctx); err != nil {
		s.writeConnectorError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"account":    acct.Name,
		"provider":   acct.Provider,
		"checked_at": timeutil.Format(time.Now().UTC()),
	})
}

func (s *Server) handleSyncAccount(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeError(w, http.StatusServiceUnavailable, "sync_disabled", "sync engine is not available")
		return
	}
	id := r.PathValue("id")
	started, err := s.engine.Trigger(id, "manual")
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "not_found", "account not found")
		case errors.Is(err, ingest.ErrAlreadyRunning):
			writeError(w, http.StatusConflict, "already_running", "a sync is already running for this account")
		default:
			writeError(w, http.StatusBadRequest, "sync_failed", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "started", "started": started, "account_id": id})
}

func (s *Server) handleSyncAll(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		writeError(w, http.StatusServiceUnavailable, "sync_disabled", "sync engine is not available")
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		s.engine.SyncAll(ctx, "manual")
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "started"})
}

func (s *Server) handleAccountHealth(w http.ResponseWriter, r *http.Request) {
	acct, err := s.store.GetAccount(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	v, err := s.accountView(r.Context(), acct, true)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	state, err := s.store.GetSyncState(r.Context(), acct.ID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	runs, err := s.store.ListSyncRuns(r.Context(), acct.ID, 10)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	runViews := make([]view.SyncRun, 0, len(runs))
	for i := range runs {
		runViews = append(runViews, view.SyncRunFromModel(&runs[i]))
	}
	status := "ok"
	if acct.Enabled && !view.SyncStateFromModel(state, 3*s.cfg.Sync.Interval.Get()).Healthy {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      status,
		"account":     v,
		"sync_state":  view.SyncStateFromModel(state, 3*s.cfg.Sync.Interval.Get()),
		"recent_runs": runViews,
	})
}

func (s *Server) handleSyncRuns(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "invalid_request", "limit must be a positive integer")
			return
		}
		if n > 100 {
			n = 100
		}
		limit = n
	}
	runs, err := s.store.ListSyncRuns(r.Context(), r.URL.Query().Get("account_id"), limit)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	items := make([]view.SyncRun, 0, len(runs))
	for i := range runs {
		items = append(items, view.SyncRunFromModel(&runs[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": items})
}

func (s *Server) accountView(ctx context.Context, acct *model.Account, withState bool) (view.Account, error) {
	v := view.AccountFromModel(acct)
	if d, ok := s.registry.Descriptor(acct.Provider); ok {
		v.ProviderName = d.Name
	}
	if withState {
		state, err := s.store.GetSyncState(ctx, acct.ID)
		if err != nil {
			return v, err
		}
		sv := view.SyncStateFromModel(state, 3*s.cfg.Sync.Interval.Get())
		v.SyncState = &sv
	}
	return v, nil
}

// ------------------------------------------------------------------ alerts

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	f, err := parseAlertFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if f.GroupBy != "" && len(f.GroupKey) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "group_key is required when group_by is set")
		return
	}
	if f.End == nil {
		now := time.Now().UTC()
		f.End = &now
	}
	if err := query.PinSnapshot(r.Context(), s.store, &f); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	items, total, err := s.store.ListAlerts(r.Context(), f)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	alerts := make([]view.Alert, 0, len(items))
	for i := range items {
		alerts = append(alerts, view.AlertFromRecord(&items[i], false))
	}
	coverage, err := query.Coverage(r.Context(), s.store, s.registry, f, 3*s.cfg.Sync.Interval.Get())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	next := ""
	hasMore := f.Offset+len(items) < total
	if f.Sort == "id" && len(items) > 0 && hasMore {
		next = items[len(items)-1].ID
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"coverage": coverage, "snapshot_sequence": f.SnapshotSequence, "next_cursor": next, "has_more": hasMore,
		"alerts": alerts,
		"window": view.WindowFromFilter(f),
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
	})
}

func (s *Server) handleListAlertGroups(w http.ResponseWriter, r *http.Request) {
	f, err := parseAlertFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if f.GroupBy == "" {
		f.GroupBy = model.GroupByTypeAsset
	}
	if f.End == nil {
		now := time.Now().UTC()
		f.End = &now
	}
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if err := query.PinSnapshot(r.Context(), s.store, &f); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	groups, total, err := s.store.ListAlertGroups(r.Context(), f)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	coverage, err := query.Coverage(r.Context(), s.store, s.registry, f, 3*s.cfg.Sync.Interval.Get())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"coverage": coverage, "snapshot_sequence": f.SnapshotSequence,
		"groups":   groups,
		"window":   view.WindowFromFilter(f),
		"total":    total,
		"group_by": f.GroupBy,
		"limit":    f.Limit,
		"offset":   f.Offset,
	})
}

func (s *Server) handleGetAlertRevisions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.GetAlert(r.Context(), id); err != nil {
		s.writeStoreError(w, err)
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "invalid_request", "limit must be a positive integer")
			return
		}
		limit = n
	}
	if limit > 200 {
		limit = 200
	}
	before := 0
	if raw := r.URL.Query().Get("before_revision"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 1 {
			writeError(w, 400, "invalid_request", "before_revision must be positive")
			return
		}
		before = n
	}
	revisions, err := s.store.AlertRevisionPage(r.Context(), id, before, limit+1)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	hasMore := len(revisions) > limit
	if hasMore {
		revisions = revisions[:limit]
	}
	next := 0
	if hasMore && len(revisions) > 0 {
		next = revisions[len(revisions)-1].Revision
	}
	revisionViews := make([]view.Revision, 0, len(revisions))
	for _, rev := range revisions {
		revisionViews = append(revisionViews, view.RevisionFromModel(rev))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"has_more": hasMore, "next_before_revision": next,
		"alert_id":  id,
		"revisions": revisionViews,
	})
}

func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.GetAlert(r.Context(), r.PathValue("id"))
	if raw := r.URL.Query().Get("snapshot_sequence"); raw != "" {
		seq, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || seq < 0 {
			writeError(w, 400, "invalid_request", "invalid snapshot_sequence")
			return
		}
		rec, err = s.store.GetAlertAtSnapshot(r.Context(), r.PathValue("id"), seq)
	}
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view.AlertFromRecord(rec, true))
}

func (s *Server) handleGetAlertRaw(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.GetAlert(r.Context(), r.PathValue("id"))
	if raw := r.URL.Query().Get("snapshot_sequence"); raw != "" {
		seq, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || seq < 0 {
			writeError(w, 400, "invalid_request", "invalid snapshot_sequence")
			return
		}
		rec, err = s.store.GetAlertAtSnapshot(r.Context(), r.PathValue("id"), seq)
	}
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(rec.Raw)
}

func (s *Server) handlePatchAlert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body: "+err.Error())
		return
	}
	status, ok := model.ParseAlertStatus(req.Status)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request", "status must be one of: open, acknowledged, suppressed, closed")
		return
	}
	if err := s.store.UpdateAlertStatus(r.Context(), r.PathValue("id"), status); err != nil {
		s.writeStoreError(w, err)
		return
	}
	rec, err := s.store.GetAlert(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view.AlertFromRecord(rec, true))
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	f, err := parseAlertFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := query.PinSnapshot(r.Context(), s.store, &f); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	f.Limit = 1
	stats, err := s.store.AlertStats(r.Context(), f)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	coverage, err := query.Coverage(r.Context(), s.store, s.registry, f, 3*s.cfg.Sync.Interval.Get())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshot_sequence": f.SnapshotSequence, "coverage": coverage,
		"window": map[string]any{
			"start": formatOptional(f.Start),
			"end":   formatOptional(f.End),
		},
		"statistics": view.Summarize(*stats),
	})
}

func parseAlertFilter(r *http.Request) (model.AlertFilter, error) {
	q := r.URL.Query()
	f := model.AlertFilter{
		TimeField: q.Get("time_field"), RuleID: strings.TrimSpace(q.Get("rule_id")), FindingKind: strings.TrimSpace(q.Get("finding_kind")), VendorStatus: strings.TrimSpace(q.Get("vendor_status")), ObservableValue: strings.TrimSpace(q.Get("observable_value")), AfterID: strings.TrimSpace(q.Get("after_id")),
		Provider:  strings.TrimSpace(q.Get("provider")),
		AccountID: strings.TrimSpace(q.Get("account_id")),
		Keyword:   strings.TrimSpace(firstNonEmpty(q.Get("q"), q.Get("keyword"))),
		IP:        strings.TrimSpace(q.Get("ip")),
		Resource:  strings.TrimSpace(q.Get("resource")),
		Sort:      strings.TrimSpace(q.Get("sort")),
		Limit:     50,
	}
	if raw := q.Get("snapshot_sequence"); raw != "" {
		n, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || n < 0 {
			return f, errors.New("invalid snapshot_sequence")
		}
		f.SnapshotSequence = &n
	}
	if raw := q.Get("observable_type"); raw != "" {
		n, e := strconv.Atoi(raw)
		if e != nil || n < 0 {
			return f, errors.New("observable_type must be a numeric OCSF type ID")
		}
		f.ObservableType = &n
	}
	if f.AfterID != "" {
		f.Sort = "id"
	}
	if f.IP != "" && net.ParseIP(f.IP) == nil {
		return f, errors.New("invalid IP address")
	}
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return f, errors.New("limit must be a positive integer")
		}
		if n > 200 {
			n = 200
		}
		f.Limit = n
	}
	if raw := q.Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return f, errors.New("offset must be a non-negative integer")
		}
		f.Offset = n
	}
	for _, part := range strings.Split(q.Get("severity"), ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		sev, ok := model.ParseSeverity(part)
		if !ok {
			return f, fmt.Errorf("unknown severity %q", part)
		}
		f.Severities = append(f.Severities, sev)
	}
	for _, part := range strings.Split(q.Get("status"), ",") {
		if part = strings.TrimSpace(part); part == "" {
			continue
		}
		st, ok := model.ParseAlertStatus(part)
		if !ok {
			return f, fmt.Errorf("unknown status %q", part)
		}
		f.Statuses = append(f.Statuses, st)
	}
	if raw := q.Get("start"); raw != "" {
		t, ok := timeutil.Parse(raw)
		if !ok {
			return f, fmt.Errorf("invalid start %q", raw)
		}
		f.Start = &t
	}
	if raw := q.Get("end"); raw != "" {
		t, ok := timeutil.Parse(raw)
		if !ok {
			return f, fmt.Errorf("invalid end %q", raw)
		}
		f.End = &t
	}
	if raw := q.Get("since"); raw != "" {
		d, ok := timeutil.ParseDuration(raw)
		if !ok {
			return f, fmt.Errorf("invalid since %q", raw)
		}
		now := time.Now().UTC()
		if f.Start == nil {
			start := now.Add(-d)
			f.Start = &start
		}
		if f.End == nil {
			f.End = &now
		}
	}
	if f.Start != nil && f.End != nil && f.End.Before(*f.Start) {
		return f, errors.New("end must be after start")
	}
	if raw := q.Get("group_by"); raw != "" {
		groupBy, ok := model.ParseAlertGroupBy(raw)
		if !ok {
			return f, fmt.Errorf("unknown group_by %q", raw)
		}
		f.GroupBy = groupBy
	}
	if raw := q.Get("group_key"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &f.GroupKey); err != nil {
			return f, fmt.Errorf("invalid group_key: %w", err)
		}
		if len(f.GroupKey) == 0 {
			return f, errors.New("group_key must not be empty")
		}
	}
	return f, query.ValidateFilter(f)
}

// ------------------------------------------------------------------ health

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable", "database": "error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"version":        metaVersion(),
		"uptime_seconds": int64(time.Since(s.startedAt).Seconds()),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	dbStatus := "ok"
	if err := s.store.Ping(ctx); err != nil {
		dbStatus = "error"
	}
	accounts, err := s.store.ListAccounts(ctx)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	status := "ok"
	items := make([]view.Account, 0, len(accounts))
	for i := range accounts {
		v, err := s.accountView(ctx, &accounts[i], true)
		if err != nil {
			s.writeStoreError(w, err)
			return
		}
		if accounts[i].Enabled && v.SyncState != nil && !v.SyncState.Healthy {
			status = "degraded"
		}
		items = append(items, v)
	}
	if dbStatus != "ok" {
		status = "unavailable"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   status,
		"database": dbStatus,
		"version":  metaVersion(),
		"accounts": items,
	})
}

func (s *Server) handleAccountFailures(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := s.store.GetAccount(r.Context(), id); err != nil {
		s.writeStoreError(w, err)
		return
	}
	items, total, err := s.store.ListIngestFailures(r.Context(), id, 100)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	// A malformed JSON payload is still inspectable and remains byte-for-byte
	// unchanged in storage for retry.
	public := make([]map[string]any, 0, len(items))
	for _, f := range items {
		var raw any = f.Raw
		if !json.Valid(f.Raw) {
			raw = string(f.Raw)
		}
		public = append(public, map[string]any{
			"id": f.ID, "account_id": f.AccountID, "raw": raw, "error": f.Error,
			"attempts": f.Attempts, "mapper_version": f.MapperVersion,
			"created_at": timeutil.Format(f.CreatedAt), "last_attempt_at": timeutil.Format(f.LastAttemptAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"failures": public, "total": total, "limit": 100})
}

// ----------------------------------------------------------------- helpers

func (s *Server) encryptCredential(cred connector.Credential) (string, error) {
	return credential.Encrypt(s.cipher, cred)
}

func credentialFieldValue(cred connector.Credential, name string) string {
	switch name {
	case "access_key_id":
		return cred.AccessKeyID
	case "access_key_secret":
		return cred.AccessKeySecret
	case "session_token":
		return cred.SessionToken
	case "service_account_json":
		return cred.ServiceAccountJSON
	default:
		return ""
	}
}

func missingCredentialFields(desc connector.Descriptor, cred connector.Credential) []string {
	missing := []string{}
	for _, f := range desc.Credential {
		if f.Required && strings.TrimSpace(credentialFieldValue(cred, f.Name)) == "" {
			missing = append(missing, f.Name)
		}
	}
	return missing
}

func missingOptionFields(desc connector.Descriptor, options map[string]string) []string {
	missing := []string{}
	for _, f := range desc.OptionFields {
		if f.Required && strings.TrimSpace(options[f.Name]) == "" {
			missing = append(missing, f.Name)
		}
	}
	return missing
}

func (s *Server) decryptCredential(ctx context.Context, accountID string) (*connector.Credential, error) {
	cred, err := credential.Load(ctx, s.store, s.cipher, accountID)
	if err != nil {
		return nil, err
	}
	return &cred, nil
}

func (s *Server) buildConnector(ctx context.Context, acct *model.Account) (connector.Connector, error) {
	cred, err := s.decryptCredential(ctx, acct.ID)
	if err != nil {
		return nil, err
	}
	return s.registry.New(connector.AccountConfig{
		Provider:   acct.Provider,
		AccountID:  acct.ID,
		Name:       acct.Name,
		AccountUID: acct.AccountUID,
		Region:     acct.Region,
		Options:    acct.Options,
		Credential: *cred,
	})
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func formatOptional(t *time.Time) string {
	if t == nil {
		return ""
	}
	return timeutil.Format(*t)
}
