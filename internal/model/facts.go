package model

import "time"

const (
	FindingDetection     = "detection"
	FindingVulnerability = "vulnerability"
	FindingCompliance    = "compliance"
	FindingIncident      = "incident"
	FindingOther         = "other"
)

// FieldOrigin describes inputs to a versioned, deterministic transformation.
// Paths are JSON pointers into the immutable source record or account scope.
type FieldOrigin struct {
	Source    string   `json:"source"`
	Paths     []string `json:"paths"`
	Transform string   `json:"transform"`
}

func FindingClass(kind string) (int, string) {
	switch kind {
	case FindingVulnerability:
		return 2002, "Vulnerability Finding"
	case FindingCompliance:
		return 2003, "Compliance Finding"
	case FindingIncident:
		return 2005, "Incident Finding"
	case FindingDetection:
		return 2004, "Detection Finding"
	default:
		return 0, "Other"
	}
}

type AlertChange struct {
	ProjectionUpdated bool      `json:"projection_updated"`
	Sequence          int64     `json:"sequence"`
	AlertID           string    `json:"alert_id"`
	Provider          string    `json:"provider"`
	AccountID         string    `json:"account_id"`
	ChangeType        string    `json:"change_type"`
	Revision          int       `json:"revision"`
	CapturedAt        time.Time `json:"captured_at"`
}

type ChangePage struct {
	Changes    []AlertChange `json:"changes"`
	NextCursor string        `json:"next_cursor"`
	HasMore    bool          `json:"has_more"`
}

type Coverage struct {
	Complete bool              `json:"complete"`
	Accounts []AccountCoverage `json:"accounts"`
	// Completeness is bounded by these sources, permissions and recorded windows.
	Boundary string `json:"boundary"`
}

type AccountCoverage struct {
	AccountID       string            `json:"account_id"`
	Provider        string            `json:"provider"`
	Name            string            `json:"name"`
	Enabled         bool              `json:"enabled"`
	Scope           map[string]string `json:"scope"`
	API             string            `json:"api"`
	APIVersion      string            `json:"api_version"`
	TimeBasis       string            `json:"time_basis"`
	Status          string            `json:"status"`
	Complete        bool              `json:"complete"`
	CoverageStart   *time.Time        `json:"coverage_start"`
	Watermark       *time.Time        `json:"watermark"`
	LastSuccessAt   *time.Time        `json:"last_success_at"`
	FailedRecords   int               `json:"failed_records"`
	LastError       string            `json:"last_error,omitempty"`
	LastSourceError *SourceError      `json:"last_source_error,omitempty"`
	Limitations     []string          `json:"limitations"`
}
