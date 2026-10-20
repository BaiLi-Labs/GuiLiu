// Package view defines the public JSON shape shared by the REST API, MCP tools
// and the Web console. Keeping it separate from storage avoids leaking internal
// fields (encrypted credentials, dedupe keys) to consumers.
package view

import (
	"encoding/json"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/timeutil"
)

type Resource struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

type Alert struct {
	ID               string          `json:"id"`
	Provider         string          `json:"provider"`
	AccountID        string          `json:"account_id"`
	AccountName      string          `json:"account_name,omitempty"`
	AccountUID       string          `json:"account_uid,omitempty"`
	ExternalID       string          `json:"external_id"`
	Product          string          `json:"product,omitempty"`
	Title            string          `json:"title"`
	Description      string          `json:"description,omitempty"`
	Severity         string          `json:"severity"`
	SeverityID       int             `json:"severity_id"`
	OriginalSeverity string          `json:"original_severity,omitempty"`
	Status           string          `json:"status"`
	VendorStatus     string          `json:"vendor_status,omitempty"`
	AlertType        string          `json:"alert_type,omitempty"`
	EventTime        string          `json:"event_time"`
	FirstSeenAt      string          `json:"first_seen_at"`
	LastSeenAt       string          `json:"last_seen_at"`
	Region           string          `json:"region,omitempty"`
	Resource         Resource        `json:"resource"`
	SourceIP         string          `json:"source_ip,omitempty"`
	DestinationIP    string          `json:"destination_ip,omitempty"`
	Actor            string          `json:"actor,omitempty"`
	Tactic           string          `json:"tactic,omitempty"`
	Technique        string          `json:"technique,omitempty"`
	Observables      []Observable    `json:"observables,omitempty"`
	Evidences        []Evidence      `json:"evidences,omitempty"`
	MapperVersion    string          `json:"mapper_version,omitempty"`
	OCSF             json.RawMessage `json:"ocsf,omitempty"`
	Raw              json.RawMessage `json:"raw,omitempty"`
	CreatedAt        string          `json:"created_at,omitempty"`
	UpdatedAt        string          `json:"updated_at,omitempty"`
}

type Observable struct {
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
	TypeID int    `json:"type_id"`
	Value  string `json:"value"`
}

type Evidence struct {
	Type string         `json:"type,omitempty"`
	Data map[string]any `json:"data,omitempty"`
}

func AlertFromRecord(rec *model.AlertRecord, includePayload bool) Alert {
	a := Alert{
		ID:               rec.ID,
		Provider:         rec.Provider,
		AccountID:        rec.AccountID,
		AccountName:      rec.AccountName,
		AccountUID:       rec.AccountUID,
		ExternalID:       rec.ExternalID,
		Product:          rec.Product,
		Title:            rec.Title,
		Description:      rec.Description,
		Severity:         rec.Severity.String(),
		SeverityID:       int(rec.Severity),
		OriginalSeverity: rec.OriginalSeverity,
		Status:           string(rec.Status),
		VendorStatus:     rec.VendorStatus,
		AlertType:        rec.AlertType,
		EventTime:        timeutil.Format(rec.EventTime),
		FirstSeenAt:      timeutil.Format(rec.FirstSeenAt),
		LastSeenAt:       timeutil.Format(rec.LastSeenAt),
		Region:           rec.Region,
		Resource:         Resource{ID: rec.Resource.ID, Name: rec.Resource.Name, Type: rec.Resource.Type},
		SourceIP:         rec.SourceIP,
		DestinationIP:    rec.DestinationIP,
		Actor:            rec.Actor,
		Tactic:           rec.Tactic,
		Technique:        rec.Technique,
		MapperVersion:    rec.MapperVersion,
		CreatedAt:        timeutil.Format(rec.CreatedAt),
		UpdatedAt:        timeutil.Format(rec.UpdatedAt),
	}
	for _, o := range rec.Observables {
		if o.Value == "" {
			continue
		}
		a.Observables = append(a.Observables, Observable{Name: o.Name, Type: o.Type, TypeID: o.TypeID, Value: o.Value})
	}
	for _, e := range rec.Evidences {
		a.Evidences = append(a.Evidences, Evidence{Type: e.Type, Data: e.Data})
	}
	if includePayload {
		a.OCSF = rec.OCSF
		a.Raw = rec.Raw
	}
	return a
}

type SyncState struct {
	CursorEnd           string `json:"cursor_end,omitempty"`
	Pending             bool   `json:"pending"`
	LastSuccessAt       string `json:"last_success_at,omitempty"`
	LastAttemptAt       string `json:"last_attempt_at,omitempty"`
	LastError           string `json:"last_error,omitempty"`
	LastErrorAt         string `json:"last_error_at,omitempty"`
	LastDurationMS      int64  `json:"last_duration_ms"`
	ItemsLastRun        int    `json:"items_last_run"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	Healthy             bool   `json:"healthy"`
}

func SyncStateFromModel(s *model.SyncState) SyncState {
	if s == nil {
		return SyncState{}
	}
	v := SyncState{
		CursorEnd:           timeutil.Format(s.CursorEnd),
		Pending:             s.PendingToken != "",
		LastSuccessAt:       ptrFormat(s.LastSuccessAt),
		LastAttemptAt:       ptrFormat(s.LastAttemptAt),
		LastError:           s.LastError,
		LastErrorAt:         ptrFormat(s.LastErrorAt),
		LastDurationMS:      s.LastDurationMS,
		ItemsLastRun:        s.ItemsLastRun,
		ConsecutiveFailures: s.ConsecutiveFailures,
		Healthy:             s.Healthy(),
	}
	return v
}

type Account struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Provider      string            `json:"provider"`
	ProviderName  string            `json:"provider_name,omitempty"`
	AccountUID    string            `json:"account_uid,omitempty"`
	Region        string            `json:"region,omitempty"`
	Enabled       bool              `json:"enabled"`
	Options       map[string]string `json:"options,omitempty"`
	AccessKeyHint string            `json:"access_key_hint,omitempty"`
	CredentialSet bool              `json:"credential_configured"`
	CreatedAt     string            `json:"created_at,omitempty"`
	UpdatedAt     string            `json:"updated_at,omitempty"`
	SyncState     *SyncState        `json:"sync_state,omitempty"`
}

func AccountFromModel(a *model.Account) Account {
	return Account{
		ID:            a.ID,
		Name:          a.Name,
		Provider:      a.Provider,
		AccountUID:    a.AccountUID,
		Region:        a.Region,
		Enabled:       a.Enabled,
		Options:       a.Options,
		AccessKeyHint: a.AccessKeyHint,
		CredentialSet: a.CredentialSet,
		CreatedAt:     timeutil.Format(a.CreatedAt),
		UpdatedAt:     timeutil.Format(a.UpdatedAt),
	}
}

type SyncRun struct {
	ID         string `json:"id"`
	AccountID  string `json:"account_id"`
	Provider   string `json:"provider,omitempty"`
	Trigger    string `json:"trigger"`
	Status     string `json:"status"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	Pages      int    `json:"pages"`
	Fetched    int    `json:"fetched"`
	Created    int    `json:"created"`
	Updated    int    `json:"updated"`
	Failed     int    `json:"failed"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

func SyncRunFromModel(r *model.SyncRun) SyncRun {
	return SyncRun{
		ID:         r.ID,
		AccountID:  r.AccountID,
		Provider:   r.Provider,
		Trigger:    r.Trigger,
		Status:     r.Status,
		StartedAt:  timeutil.Format(r.StartedAt),
		FinishedAt: ptrFormat(r.FinishedAt),
		Pages:      r.Pages,
		Fetched:    r.Fetched,
		Created:    r.Created,
		Updated:    r.Updated,
		Failed:     r.Failed,
		Error:      r.Error,
		DurationMS: r.DurationMS,
	}
}

func Summarize(m model.AlertStats) map[string]any {
	return map[string]any{
		"total":         m.Total,
		"by_severity":   m.BySeverity,
		"by_provider":   m.ByProvider,
		"by_status":     m.ByStatus,
		"by_day":        m.ByDay,
		"top_resources": m.TopResources,
	}
}

func ptrFormat(t *time.Time) string {
	if t == nil {
		return ""
	}
	return timeutil.Format(*t)
}
