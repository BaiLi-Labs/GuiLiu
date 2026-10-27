package model

import (
	"encoding/json"
	"time"
)

// EventSearch is a bounded, explicit query against one upstream connection.
// It never triggers Finding ingestion or changes the upstream data.
type EventSearch struct {
	AccountID string            `json:"account_id"`
	Start     string            `json:"start,omitempty"`
	End       string            `json:"end,omitempty"`
	Since     string            `json:"since,omitempty"`
	Limit     int               `json:"limit,omitempty"`
	Cursor    string            `json:"cursor,omitempty"`
	Keyword   string            `json:"keyword,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Host      string            `json:"host,omitempty"`
	User      string            `json:"user,omitempty"`
	Filters   map[string]string `json:"filters,omitempty"`
	GroupBy   string            `json:"group_by,omitempty"`
	TopN      int               `json:"top_n,omitempty"`
}

// EventReference identifies an API-returned document, not immutable local bytes.
type EventReference struct {
	AccountID string `json:"account_id"`
	Index     string `json:"index"`
	ID        string `json:"id"`
	Routing   string `json:"routing,omitempty"`
	RawHash   string `json:"raw_hash,omitempty"`
}

type Event struct {
	ID              string            `json:"id"`
	Provider        string            `json:"provider"`
	AccountID       string            `json:"account_id"`
	EventTime       *time.Time        `json:"event_time,omitempty"`
	Message         string            `json:"message,omitempty"`
	HostIDs         []string          `json:"host_ids,omitempty"`
	HostNames       []string          `json:"host_names,omitempty"`
	SourceIPs       []string          `json:"source_ips,omitempty"`
	DestinationIPs  []string          `json:"destination_ips,omitempty"`
	Users           []string          `json:"users,omitempty"`
	Actions         []string          `json:"actions,omitempty"`
	Categories      []string          `json:"categories,omitempty"`
	Datasets        []string          `json:"datasets,omitempty"`
	SourceSeverity  string            `json:"source_severity,omitempty"`
	FieldSources    map[string]string `json:"field_sources"`
	MappingWarnings []string          `json:"mapping_warnings,omitempty"`
	Evidence        EventReference    `json:"evidence"`
}

type EventTotal struct {
	Value    int64  `json:"value"`
	Relation string `json:"relation"`
}

type EventBucket struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type EventAggregation struct {
	Field                   string        `json:"field"`
	Buckets                 []EventBucket `json:"buckets"`
	OtherDocumentCount      int64         `json:"other_document_count"`
	DocumentCountErrorBound int64         `json:"document_count_error_bound"`
}

type EventQueryCoverage struct {
	ExecutionComplete bool     `json:"execution_complete"`
	Consistency       string   `json:"consistency"`
	TimedOut          bool     `json:"timed_out"`
	FailedShards      int      `json:"failed_shards"`
	Limitations       []string `json:"limitations"`
}

type EventPage struct {
	Events        []Event            `json:"events"`
	AccountID     string             `json:"account_id"`
	Provider      string             `json:"provider"`
	Indices       []string           `json:"indices"`
	MapperVersion string             `json:"mapper_version"`
	FieldMapping  map[string]string  `json:"field_mapping"`
	Query         EventSearch        `json:"query"`
	Total         EventTotal         `json:"total"`
	HasMore       bool               `json:"has_more"`
	NextCursor    string             `json:"next_cursor"`
	ObservedAt    time.Time          `json:"observed_at"`
	Coverage      EventQueryCoverage `json:"coverage"`
	Aggregation   *EventAggregation  `json:"aggregation,omitempty"`
	// Continuation belongs to the connector and is sealed by the service.
	Continuation json.RawMessage `json:"-"`
}

type EventEvidence struct {
	Event          Event           `json:"event"`
	Raw            json.RawMessage `json:"raw"`
	RawHash        string          `json:"raw_hash"`
	Changed        bool            `json:"changed"`
	HashCompared   bool            `json:"hash_compared"`
	ObservedAt     time.Time       `json:"observed_at"`
	Representation string          `json:"representation"`
	Limitations    []string        `json:"limitations"`
}

type EventField struct {
	Name         string   `json:"name"`
	Types        []string `json:"types"`
	Searchable   bool     `json:"searchable"`
	Aggregatable bool     `json:"aggregatable"`
	Conflicting  bool     `json:"conflicting"`
}

type EventFields struct {
	AccountID     string            `json:"account_id"`
	Provider      string            `json:"provider"`
	Indices       []string          `json:"indices"`
	Mapping       map[string]string `json:"mapping"`
	MapperVersion string            `json:"mapper_version"`
	Fields        []EventField      `json:"fields"`
	Truncated     bool              `json:"truncated"`
	Limitations   []string          `json:"limitations"`
}
