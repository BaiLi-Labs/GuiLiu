// Package model defines the vendor-neutral domain model shared by connectors,
// the normalization layer, storage and every consumer (REST, MCP, Web UI).
package model

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
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
	// SourcePaths are recorded by the mapper as it extracts the value. They are
	// persisted through Alert.Provenance, not as a second public representation.
	SourcePaths []string `json:"-"`
	Name        string   `json:"name,omitempty"`
	Type        string   `json:"type,omitempty"`
	TypeID      int      `json:"type_id"`
	Value       string   `json:"value"`
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
	SourceAPI        string                 `json:"source_api"`
	SourceAPIVersion string                 `json:"source_api_version"`
	RuleID           string                 `json:"rule_id,omitempty"`
	FindingKind      string                 `json:"finding_kind"`
	SourceCreatedAt  time.Time              `json:"source_created_at,omitempty"`
	SourceUpdatedAt  time.Time              `json:"source_updated_at,omitempty"`
	OccurrenceCount  *int64                 `json:"occurrence_count,omitempty"`
	OccurrenceScope  string                 `json:"occurrence_scope,omitempty"`
	Provenance       map[string]FieldOrigin `json:"provenance,omitempty"`
	ExternalID       string                 `json:"external_id"`
	Title            string                 `json:"title"`
	Description      string                 `json:"description"`
	Severity         Severity               `json:"severity"`
	OriginalSeverity string                 `json:"original_severity,omitempty"`
	VendorStatus     string                 `json:"vendor_status,omitempty"`
	EventTime        time.Time              `json:"event_time"`
	FirstSeenAt      time.Time              `json:"first_seen_at"`
	LastSeenAt       time.Time              `json:"last_seen_at"`
	OriginalTime     string                 `json:"original_time,omitempty"`
	Product          string                 `json:"product,omitempty"`
	AlertType        string                 `json:"alert_type,omitempty"`
	Region           string                 `json:"region,omitempty"`
	CloudAccountUID  string                 `json:"cloud_account_uid,omitempty"`
	Resource         Resource               `json:"resource"`
	Resources        []Resource             `json:"resources,omitempty"`
	SourceIP         string                 `json:"source_ip,omitempty"`
	DestinationIP    string                 `json:"destination_ip,omitempty"`
	Actor            string                 `json:"actor,omitempty"`
	Tactic           string                 `json:"tactic,omitempty"`
	Technique        string                 `json:"technique,omitempty"`
	Observables      []Observable           `json:"observables,omitempty"`
	Evidences        []Evidence             `json:"evidences,omitempty"`
	Unmapped         map[string]any         `json:"unmapped,omitempty"`
	Raw              json.RawMessage        `json:"raw,omitempty"`
	OCSF             json.RawMessage        `json:"ocsf,omitempty"`
	MapperVersion    string                 `json:"mapper_version,omitempty"`
}

// AlertRevision is a material change to an alert's vendor payload or mapping.
// Identical syncs do not create a new revision.
type AlertRevision struct {
	ProjectionUpdated bool            `json:"projection_updated"`
	Record            *AlertRecord    `json:"record,omitempty"`
	ID                string          `json:"id"`
	AlertID           string          `json:"alert_id"`
	Revision          int             `json:"revision"`
	Sequence          int64           `json:"sequence"`
	RawHash           string          `json:"raw_hash"`
	MapperVersion     string          `json:"mapper_version"`
	ChangeType        string          `json:"change_type"`
	CapturedAt        time.Time       `json:"captured_at"`
	Title             string          `json:"title,omitempty"`
	Severity          Severity        `json:"severity"`
	VendorStatus      string          `json:"vendor_status,omitempty"`
	Raw               json.RawMessage `json:"raw,omitempty"`
	OCSF              json.RawMessage `json:"ocsf,omitempty"`
}

// AlertRecord is a stored alert: the normalized alert plus platform metadata.
type AlertRecord struct {
	ID          string `json:"id"`
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name,omitempty"`
	Provider    string `json:"provider"`
	AccountUID  string `json:"account_uid,omitempty"`
	Alert
	Changed           bool        `json:"-"`
	ProjectionUpdated bool        `json:"projection_updated"`
	RawHash           string      `json:"raw_hash"`
	Revision          int         `json:"revision"`
	Sequence          int64       `json:"sequence"`
	IngestedAt        time.Time   `json:"ingested_at"`
	LastIngestedAt    time.Time   `json:"last_ingested_at"`
	Status            AlertStatus `json:"status"`
	CreatedAt         time.Time   `json:"created_at"`
	UpdatedAt         time.Time   `json:"updated_at"`
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
	AccountID     string    `json:"account_id"`
	CoverageStart time.Time `json:"coverage_start,omitempty"`
	CursorEnd     time.Time `json:"cursor_end,omitempty"`
	// Pending* resume an interrupted window from the last successful page.
	// They are cleared only after the whole window has been committed.
	PendingStart        time.Time  `json:"pending_start,omitempty"`
	PendingEnd          time.Time  `json:"pending_end,omitempty"`
	PendingToken        string     `json:"pending_token,omitempty"`
	FailedRecords       int        `json:"failed_records"`
	LastSuccessAt       *time.Time `json:"last_success_at,omitempty"`
	LastAttemptAt       *time.Time `json:"last_attempt_at,omitempty"`
	LastError           string     `json:"last_error,omitempty"`
	LastErrorAt         *time.Time `json:"last_error_at,omitempty"`
	LastDurationMS      int64      `json:"last_duration_ms"`
	ItemsLastRun        int        `json:"items_last_run"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// Healthy reports whether the last sync succeeded recently.
func (s SyncState) Healthy() bool {
	return s.Health(time.Now().UTC(), 15*time.Minute) == "healthy"
}

// Health describes data freshness as well as collection errors. maxAge should
// allow several scheduled intervals before declaring a quiet account stale.
func (s SyncState) Health(now time.Time, maxAge time.Duration) string {
	if s.LastError != "" || s.ConsecutiveFailures > 0 {
		return "failed"
	}
	if !s.PendingEnd.IsZero() || s.PendingToken != "" {
		return "pending"
	}
	if s.LastSuccessAt == nil || s.CursorEnd.IsZero() {
		return "never_synced"
	}
	if now.Sub(*s.LastSuccessAt) > maxAge || now.Sub(s.CursorEnd) > maxAge {
		return "stale"
	}
	if s.FailedRecords > 0 {
		return "partial"
	}
	return "healthy"
}

// IngestFailure preserves an unprocessed payload independently of the cursor.
type IngestFailure struct {
	ID            string          `json:"id"`
	AccountID     string          `json:"account_id"`
	Raw           json.RawMessage `json:"raw"`
	IngestedAt    time.Time       `json:"ingested_at"`
	MapperVersion string          `json:"mapper_version"`
	Error         string          `json:"error"`
	Attempts      int             `json:"attempts"`
	CreatedAt     time.Time       `json:"created_at"`
	LastAttemptAt time.Time       `json:"last_attempt_at"`
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
	AccountUID       string
	Region           string
	ExactResourceID  string
	ResourceType     string
	TimeField        string
	Provider         string
	AccountID        string
	Severities       []Severity
	Statuses         []AlertStatus
	Keyword          string
	IP               string
	ObservableType   *int
	ObservableValue  string
	RuleID           string
	FindingKind      string
	VendorStatus     string
	SnapshotSequence *int64
	AfterID          string
	Resource         string
	Start            *time.Time
	End              *time.Time
	Sort             string
	GroupBy          AlertGroupBy
	GroupKey         map[string]string
	Limit            int
	Offset           int
}

// AlertGroupBy is a read-only alert grouping strategy. Grouping never changes
// the underlying alert rows.
type AlertGroupBy string

const (
	GroupByTypeAsset AlertGroupBy = "type_asset"
	GroupBySignature AlertGroupBy = "signature"
	GroupByAsset     AlertGroupBy = "asset"
	GroupBySource    AlertGroupBy = "source"
)

func ParseAlertGroupBy(v string) (AlertGroupBy, bool) {
	switch AlertGroupBy(strings.ToLower(strings.TrimSpace(v))) {
	case GroupByTypeAsset:
		return GroupByTypeAsset, true
	case GroupBySignature:
		return GroupBySignature, true
	case GroupByAsset:
		return GroupByAsset, true
	case GroupBySource:
		return GroupBySource, true
	default:
		return "", false
	}
}

// AlertGroup is one query-time grouping result. Key is the exact, explainable
// grouping key; members remain available through the normal alerts query.
type AlertGroup struct {
	ID            string            `json:"id"`
	GroupBy       AlertGroupBy      `json:"group_by"`
	Key           map[string]string `json:"key"`
	Title         string            `json:"title"`
	FindingCount  int               `json:"finding_count"`
	RevisionCount int               `json:"revision_count"`
	MaxSeverity   Severity          `json:"max_severity"` // Maximum vendor-mapped severity among members.
	FirstSeenAt   *time.Time        `json:"first_seen_at"`
	LastSeenAt    *time.Time        `json:"last_seen_at"`
	Providers     []string          `json:"providers,omitempty"`
	ResourceID    string            `json:"resource_id,omitempty"`
	ResourceName  string            `json:"resource_name,omitempty"`
	SourceIP      string            `json:"source_ip,omitempty"`
	AlertType     string            `json:"alert_type,omitempty"`
}

// GroupID is stable for a group_by strategy and canonical key, independent of
// sort order and pagination.
func GroupID(groupBy AlertGroupBy, key map[string]string) string {
	keys := make([]string, 0, len(key))
	for k := range key {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	_, _ = h.Write([]byte(groupBy))
	for _, k := range keys {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{'='})
		_, _ = h.Write([]byte(key[k]))
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:12])
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
