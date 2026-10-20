// Package model defines the vendor-neutral domain model shared by connectors,
// the normalization layer, storage and every consumer (REST, MCP, Web UI).
package model

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Severity is the OCSF severity_id scale. It is intentionally not vendor
// specific: every connector maps its native level onto this scale and keeps the
// original label in Alert.OriginalSeverity.
type Severity int

const (
	SeverityUnknown       Severity = 0
	SeverityInformational Severity = 1
	SeverityLow           Severity = 2
	SeverityMedium        Severity = 3
	SeverityHigh          Severity = 4
	SeverityCritical      Severity = 5
	SeverityFatal         Severity = 6
)

var severitySlugs = [...]string{
	"unknown", "informational", "low", "medium", "high", "critical", "fatal",
}

var severityCaptions = [...]string{
	"Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal",
}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severitySlugs) {
		return "unknown"
	}
	return severitySlugs[s]
}

// Caption returns the OCSF enum caption, which must be used as the sibling
// value of severity_id in an OCSF event.
func (s Severity) Caption() string {
	if s < 0 || int(s) >= len(severityCaptions) {
		return "Unknown"
	}
	return severityCaptions[s]
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		v, _ := ParseSeverity(str)
		*s = v
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("invalid severity %s", string(b))
	}
	if n < 0 || n > int(SeverityFatal) {
		return fmt.Errorf("severity %d out of range", n)
	}
	*s = Severity(n)
	return nil
}

// ParseSeverity accepts either an OCSF severity id or a name.
func ParseSeverity(v string) (Severity, bool) {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "info", "informational", "1":
		return SeverityInformational, true
	case "low", "2":
		return SeverityLow, true
	case "medium", "moderate", "3":
		return SeverityMedium, true
	case "high", "4":
		return SeverityHigh, true
	case "critical", "severe", "5":
		return SeverityCritical, true
	case "fatal", "6":
		return SeverityFatal, true
	case "unknown", "0", "":
		return SeverityUnknown, true
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= int(SeverityFatal) {
		return Severity(n), true
	}
	return SeverityUnknown, false
}

// AlertStatus is the lifecycle state managed by the platform (not the vendor).
type AlertStatus string

const (
	StatusOpen         AlertStatus = "open"
	StatusAcknowledged AlertStatus = "acknowledged"
	StatusSuppressed   AlertStatus = "suppressed"
	StatusClosed       AlertStatus = "closed"
)

var alertStatuses = []AlertStatus{StatusOpen, StatusAcknowledged, StatusSuppressed, StatusClosed}

func (s AlertStatus) Valid() bool {
	for _, v := range alertStatuses {
		if s == v {
			return true
		}
	}
	return false
}

func ParseAlertStatus(v string) (AlertStatus, bool) {
	s := AlertStatus(strings.ToLower(strings.TrimSpace(v)))
	return s, s.Valid()
}

// Resource describes the affected cloud asset. One alert has one primary
// resource; additional context belongs in Observables/OCSF resources.
type Resource struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

// Observable is a searchable indicator extracted from a vendor alert.
type Observable struct {
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
	TypeID int    `json:"type_id"`
	Value  string `json:"value"`
}

// Evidence is a vendor-provided artifact attached to an alert.
type Evidence struct {
	Type string         `json:"type,omitempty"`
	Data map[string]any `json:"data,omitempty"`
}

// Alert is the vendor-neutral representation produced by a connector's
// Normalize method. Raw always contains the vendor payload so that a mapping
// bug can be fixed later and history can be re-normalized.
type Alert struct {
	ExternalID       string          `json:"external_id"`
	Title            string          `json:"title"`
	Description      string          `json:"description"`
	Severity         Severity        `json:"severity"`
	OriginalSeverity string          `json:"original_severity,omitempty"`
	VendorStatus     string          `json:"vendor_status,omitempty"`
	EventTime        time.Time       `json:"event_time"`
	FirstSeenAt      time.Time       `json:"first_seen_at"`
	LastSeenAt       time.Time       `json:"last_seen_at"`
	OriginalTime     string          `json:"original_time,omitempty"`
	Product          string          `json:"product,omitempty"`
	AlertType        string          `json:"alert_type,omitempty"`
	Region           string          `json:"region,omitempty"`
	CloudAccountUID  string          `json:"cloud_account_uid,omitempty"`
	Resource         Resource        `json:"resource"`
	SourceIP         string          `json:"source_ip,omitempty"`
	DestinationIP    string          `json:"destination_ip,omitempty"`
	Actor            string          `json:"actor,omitempty"`
	Tactic           string          `json:"tactic,omitempty"`
	Technique        string          `json:"technique,omitempty"`
	Observables      []Observable    `json:"observables,omitempty"`
	Evidences        []Evidence      `json:"evidences,omitempty"`
	Unmapped         map[string]any  `json:"unmapped,omitempty"`
	Raw              json.RawMessage `json:"raw,omitempty"`
	OCSF             json.RawMessage `json:"ocsf,omitempty"`
	MapperVersion    string          `json:"mapper_version,omitempty"`
}

// AlertRecord is a stored alert: the normalized alert plus platform metadata.
type AlertRecord struct {
	ID          string `json:"id"`
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name,omitempty"`
	Provider    string `json:"provider"`
	AccountUID  string `json:"account_uid,omitempty"`
	Alert
	Status    AlertStatus `json:"status"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// DedupeKey is the stable identity of an alert inside one cloud account.
func (r *AlertRecord) DedupeKey() string {
	return r.Provider + "|" + r.AccountID + "|" + r.ExternalID
}

// Account is a configured cloud account (a connector instance).
type Account struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Provider      string            `json:"provider"`
	AccountUID    string            `json:"account_uid,omitempty"`
	Region        string            `json:"region,omitempty"`
	Enabled       bool              `json:"enabled"`
	Options       map[string]string `json:"options,omitempty"`
	AccessKeyHint string            `json:"access_key_hint,omitempty"`
	CredentialSet bool              `json:"credential_configured"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`

	// CredentialEncrypted is the base64 AES-GCM blob. It is never serialized.
	CredentialEncrypted string `json:"-"`
}

// SyncState is the per-account incremental cursor and health snapshot.
type SyncState struct {
	AccountID string    `json:"account_id"`
	CursorEnd time.Time `json:"cursor_end,omitempty"`
	// Pending* resume an interrupted window from the last successful page.
	// They are cleared only after the whole window has been committed.
	PendingStart time.Time `json:"pending_start,omitempty"`
	PendingEnd   time.Time `json:"pending_end,omitempty"`
	PendingToken string    `json:"pending_token,omitempty"`
	// PendingRecords are vendor payloads whose normalization or storage failed.
	// They are persisted before the cursor can advance and are retried before
	// the next page is fetched, so a bad record cannot be silently skipped.
	PendingRecords      []json.RawMessage `json:"pending_records,omitempty"`
	LastSuccessAt       *time.Time        `json:"last_success_at,omitempty"`
	LastAttemptAt       *time.Time        `json:"last_attempt_at,omitempty"`
	LastError           string            `json:"last_error,omitempty"`
	LastErrorAt         *time.Time        `json:"last_error_at,omitempty"`
	LastDurationMS      int64             `json:"last_duration_ms"`
	ItemsLastRun        int               `json:"items_last_run"`
	ConsecutiveFailures int               `json:"consecutive_failures"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

// Healthy reports whether the last sync succeeded recently.
func (s SyncState) Healthy() bool {
	return s.LastSuccessAt != nil && s.ConsecutiveFailures == 0
}

// SyncRun is one execution of the ingest loop for an account.
type SyncRun struct {
	ID         string     `json:"id"`
	AccountID  string     `json:"account_id"`
	Provider   string     `json:"provider,omitempty"`
	Trigger    string     `json:"trigger"`
	Status     string     `json:"status"` // running | success | partial | failed
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Pages      int        `json:"pages"`
	Fetched    int        `json:"fetched"`
	Created    int        `json:"created"`
	Updated    int        `json:"updated"`
	Failed     int        `json:"failed"`
	Error      string     `json:"error,omitempty"`
	DurationMS int64      `json:"duration_ms"`
}

// AlertFilter is shared by REST, MCP and the store.
type AlertFilter struct {
	Provider   string
	AccountID  string
	Severities []Severity
	Statuses   []AlertStatus
	Keyword    string
	IP         string
	Resource   string
	Start      *time.Time
	End        *time.Time
	Sort       string
	Limit      int
	Offset     int
}

// AlertStats is the aggregate view used by the dashboard and MCP.
type AlertStats struct {
	Total        int            `json:"total"`
	BySeverity   map[string]int `json:"by_severity"`
	ByProvider   map[string]int `json:"by_provider"`
	ByStatus     map[string]int `json:"by_status"`
	ByDay        []DayCount     `json:"by_day,omitempty"`
	TopResources []Count        `json:"top_resources,omitempty"`
}

type DayCount struct {
	Day   string `json:"day"`
	Count int    `json:"count"`
}

type Count struct {
	Key   string `json:"key"`
	Name  string `json:"name,omitempty"`
	Count int    `json:"count"`
}
