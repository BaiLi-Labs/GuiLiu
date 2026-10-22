// Package view defines the public JSON shape shared by the REST API, MCP tools,
// the query CLI and the Web console. Keeping it separate from storage avoids leaking internal
// fields (encrypted credentials, dedupe keys) to consumers.
package view

import (
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/normalize"
	"github.com/BaiLi-Labs/GuiLiu/internal/timeutil"
)

// QueryWindow is returned with lists so pagination and group expansion can
// reuse the exact time bounds instead of recalculating a relative range.
type QueryWindow struct {
	TimeField string `json:"time_field,omitempty"`
	Start     string `json:"start,omitempty"`
	End       string `json:"end,omitempty"`
}

func WindowFromFilter(f model.AlertFilter) QueryWindow {
	format := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		// Keep subsecond bounds so copying the window cannot add or drop members.
		return t.UTC().Format(time.RFC3339Nano)
	}
	return QueryWindow{Start: format(f.Start), End: format(f.End), TimeField: f.TimeField}
}

type Resource struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Type       string `json:"type,omitempty"`
	AccountUID string `json:"account_uid,omitempty"`
	// Source is vendor_declared or identifier_fallback; see model.Resource.
	Source string `json:"source,omitempty"`
	// DeclaredName is the source's own name for the resource role, kept
	// verbatim; its semantics are not asserted by GuiLiu.
	DeclaredName string `json:"declared_name,omitempty"`
}

func ResourceFromModel(r model.Resource) Resource {
	return Resource{ID: r.ID, Name: r.Name, Type: r.Type, AccountUID: r.AccountUID, Source: r.Source, DeclaredName: r.DeclaredName}
}

type Alert struct {
	ProjectionUpdated  bool                         `json:"projection_updated"`
	ObservableCount    int                          `json:"observable_count"`
	EvidenceCount      int                          `json:"evidence_count"`
	SourceAPI          string                       `json:"source_api"`
	SourceAPIVersion   string                       `json:"source_api_version"`
	RawURL             string                       `json:"raw_url,omitempty"`
	OCSFOmissionReason string                       `json:"ocsf_omission_reason,omitempty"`
	RuleID             string                       `json:"rule_id,omitempty"`
	FindingKind        string                       `json:"finding_kind"`
	SourceCreatedAt    string                       `json:"source_created_at,omitempty"`
	SourceUpdatedAt    string                       `json:"source_updated_at,omitempty"`
	IngestedAt         string                       `json:"ingested_at"`
	LastIngestedAt     string                       `json:"last_ingested_at"`
	RawHash            string                       `json:"raw_hash"`
	Revision           int                          `json:"revision"`
	Sequence           int64                        `json:"sequence"`
	Provenance         map[string]model.FieldOrigin `json:"provenance,omitempty"`
	OccurrenceCount    *int64                       `json:"occurrence_count,omitempty"`
	OccurrenceScope    string                       `json:"occurrence_scope,omitempty"`

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
	Resources        []Resource      `json:"resources,omitempty"`
	SourceIP         string          `json:"source_ip,omitempty"`
	DestinationIP    string          `json:"destination_ip,omitempty"`
	SourceLocation   string          `json:"source_location,omitempty"`
	SourceCountry    string          `json:"source_country,omitempty"`
	ResponseAction   string          `json:"response_action,omitempty"`
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
		ProjectionUpdated: rec.ProjectionUpdated,
		ObservableCount:   len(rec.Observables), EvidenceCount: len(rec.Evidences),
		SourceAPI: rec.SourceAPI, SourceAPIVersion: rec.SourceAPIVersion,
		RuleID: rec.RuleID, FindingKind: rec.FindingKind, SourceCreatedAt: timeutil.Format(rec.SourceCreatedAt), SourceUpdatedAt: timeutil.Format(rec.SourceUpdatedAt), IngestedAt: timeutil.Format(rec.IngestedAt), LastIngestedAt: timeutil.Format(rec.LastIngestedAt), RawHash: rec.RawHash, Revision: rec.Revision, Sequence: rec.Sequence, OccurrenceCount: rec.OccurrenceCount, OccurrenceScope: rec.OccurrenceScope,

		ID:               rec.ID,
		Provider:         rec.Provider,
		AccountID:        rec.AccountID,
		AccountName:      rec.AccountName,
		AccountUID:       rec.AccountUID,
		ExternalID:       rec.ExternalID,
		Product:          rec.Product,
		Title:            rec.Title,
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
		Resource:         ResourceFromModel(rec.Resource),
		SourceIP:         rec.SourceIP,
		DestinationIP:    rec.DestinationIP,
		SourceLocation:   rec.SourceLocation,
		SourceCountry:    rec.SourceCountry,
		ResponseAction:   rec.ResponseAction,
		Actor:            rec.Actor,
		Tactic:           rec.Tactic,
		Technique:        rec.Technique,
		MapperVersion:    rec.MapperVersion,
		CreatedAt:        timeutil.Format(rec.CreatedAt),
		UpdatedAt:        timeutil.Format(rec.UpdatedAt),
	}
	if includePayload {
		a.Description = rec.Description
		for _, o := range rec.Observables {
			if o.Value == "" {
				continue
			}
			a.Observables = append(a.Observables, Observable{Name: o.Name, Type: o.Type, TypeID: o.TypeID, Value: o.Value})
		}
		for _, e := range rec.Evidences {
			a.Evidences = append(a.Evidences, Evidence{Type: e.Type, Data: e.Data})
		}
	}
	if len(rec.OCSF) == 0 {
		a.OCSFOmissionReason = normalize.OmissionReason(rec.Alert)
	}
	if rec.Revision > 0 {
		a.RawURL = fmt.Sprintf("/api/v1/alerts/%s/revisions/%d/raw", url.PathEscape(rec.ID), rec.Revision)
	}
	if includePayload {
		a.Provenance = rec.Provenance
		a.OCSF = rec.OCSF
		a.Raw = rec.Raw
		for _, r := range rec.Resources {
			a.Resources = append(a.Resources, ResourceFromModel(r))
		}
	}
	return a
}

type SyncState struct {
	CoverageStart       string             `json:"coverage_start,omitempty"`
	Status              string             `json:"status"`
	FailedRecords       int                `json:"failed_records"`
	CursorEnd           string             `json:"cursor_end,omitempty"`
	Pending             bool               `json:"pending"`
	PendingCount        int                `json:"pending_count,omitempty"`
	LastSuccessAt       string             `json:"last_success_at,omitempty"`
	LastAttemptAt       string             `json:"last_attempt_at,omitempty"`
	LastError           string             `json:"last_error,omitempty"`
	LastSourceError     *model.SourceError `json:"last_source_error,omitempty"`
	LastErrorAt         string             `json:"last_error_at,omitempty"`
	LastDurationMS      int64              `json:"last_duration_ms"`
	ItemsLastRun        int                `json:"items_last_run"`
	ConsecutiveFailures int                `json:"consecutive_failures"`
	Healthy             bool               `json:"healthy"`
}

func SyncStateFromModel(s *model.SyncState, maxAge ...time.Duration) SyncState {
	if s == nil {
		return SyncState{}
	}
	age := 15 * time.Minute
	if len(maxAge) > 0 && maxAge[0] > 0 {
		age = maxAge[0]
	}
	status := s.Health(time.Now().UTC(), age)
	v := SyncState{
		CoverageStart:       timeutil.Format(s.CoverageStart),
		Status:              status,
		FailedRecords:       s.FailedRecords,
		CursorEnd:           timeutil.Format(s.CursorEnd),
		Pending:             !s.PendingEnd.IsZero() || s.PendingToken != "",
		LastSuccessAt:       ptrFormat(s.LastSuccessAt),
		LastAttemptAt:       ptrFormat(s.LastAttemptAt),
		LastError:           s.LastError,
		LastSourceError:     s.LastSourceError,
		LastErrorAt:         ptrFormat(s.LastErrorAt),
		LastDurationMS:      s.LastDurationMS,
		ItemsLastRun:        s.ItemsLastRun,
		ConsecutiveFailures: s.ConsecutiveFailures,
		Healthy:             status == "healthy",
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
	ID          string             `json:"id"`
	AccountID   string             `json:"account_id"`
	Provider    string             `json:"provider,omitempty"`
	Trigger     string             `json:"trigger"`
	Status      string             `json:"status"`
	StartedAt   string             `json:"started_at"`
	FinishedAt  string             `json:"finished_at,omitempty"`
	Pages       int                `json:"pages"`
	Fetched     int                `json:"fetched"`
	Created     int                `json:"created"`
	Updated     int                `json:"updated"`
	Failed      int                `json:"failed"`
	Error       string             `json:"error,omitempty"`
	SourceError *model.SourceError `json:"source_error,omitempty"`
	DurationMS  int64              `json:"duration_ms"`
}

func SyncRunFromModel(r *model.SyncRun) SyncRun {
	return SyncRun{
		ID:          r.ID,
		AccountID:   r.AccountID,
		Provider:    r.Provider,
		Trigger:     r.Trigger,
		Status:      r.Status,
		StartedAt:   timeutil.Format(r.StartedAt),
		FinishedAt:  ptrFormat(r.FinishedAt),
		Pages:       r.Pages,
		Fetched:     r.Fetched,
		Created:     r.Created,
		Updated:     r.Updated,
		Failed:      r.Failed,
		Error:       r.Error,
		SourceError: r.SourceError,
		DurationMS:  r.DurationMS,
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

type Revision struct {
	ProjectionUpdated bool   `json:"projection_updated"`
	ID                string `json:"id"`
	AlertID           string `json:"alert_id"`
	Revision          int    `json:"revision"`
	Sequence          int64  `json:"sequence"`
	CapturedAt        string `json:"captured_at"`
	RawHash           string `json:"raw_hash"`
	MapperVersion     string `json:"mapper_version"`
	ChangeType        string `json:"change_type"`
	Record            Alert  `json:"record"`
}

func RevisionFromModel(r model.AlertRevision) Revision {
	return Revision{ProjectionUpdated: r.ProjectionUpdated, ID: r.ID, AlertID: r.AlertID, Revision: r.Revision, Sequence: r.Sequence, CapturedAt: timeutil.Format(r.CapturedAt), RawHash: r.RawHash, MapperVersion: r.MapperVersion, ChangeType: r.ChangeType, Record: AlertFromRecord(r.Record, false)}
}
