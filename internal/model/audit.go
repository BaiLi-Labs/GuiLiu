package model

import "time"

// AuditEvent describes platform access, independently of vendor security facts.
// It never contains authentication material or source evidence bodies.
type AuditEvent struct {
	Sequence       int64          `json:"sequence"`
	RequestID      string         `json:"request_id"`
	ParentSequence int64          `json:"parent_sequence,omitempty"`
	StartedAt      time.Time      `json:"started_at"`
	FinishedAt     *time.Time     `json:"finished_at,omitempty"`
	Surface        string         `json:"surface"`
	Operation      string         `json:"operation"`
	Tool           string         `json:"tool,omitempty"`
	Method         string         `json:"method,omitempty"`
	Path           string         `json:"path,omitempty"`
	PeerIP         string         `json:"peer_ip,omitempty"`
	AuthType       string         `json:"auth_type"`
	UserID         string         `json:"user_id,omitempty"`
	Username       string         `json:"username,omitempty"`
	Role           string         `json:"role,omitempty"`
	APIKeyID       string         `json:"api_key_id,omitempty"`
	APIKeyName     string         `json:"api_key_name,omitempty"`
	Parameters     map[string]any `json:"parameters"`
	EffectiveQuery map[string]any `json:"effective_query,omitempty"`
	Summary        map[string]any `json:"summary"`
	Outcome        string         `json:"outcome"`
	HTTPStatus     int            `json:"http_status,omitempty"`
	ErrorCode      string         `json:"error_code,omitempty"`
	DurationMS     int64          `json:"duration_ms"`
	ResponseBytes  int64          `json:"response_bytes,omitempty"`
}

type AuditFilter struct {
	RequestID, UserID, Username, APIKeyID, Surface, Operation, Tool, Outcome string
	Start, End                                                               *time.Time
	BeforeSequence                                                           int64
	Limit                                                                    int
}
