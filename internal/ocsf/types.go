// Package ocsf contains the subset of the Open Cybersecurity Schema Framework
// used by GuiLiu, modelled after OCSF Detection Finding (class_uid 2004).
//
// Schema reference:
// https://github.com/ocsf/ocsf-schema/blob/main/events/findings/detection_finding.json
package ocsf

const (
	// SchemaVersion pins the OCSF version the emitted payload targets.
	SchemaVersion = "1.6.0"

	ClassUID             = 2004
	ClassName            = "Detection Finding"
	CategoryUID          = 2
	CategoryName         = "Findings"
	ActivityCreate       = 1
	ActivityCreateName   = "Create"
	TypeUIDFindingCreate = ClassUID*100 + ActivityCreate
)

// DetectionFinding is a valid OCSF Detection Finding payload with the
// attributes GuiLiu can populate from cloud security alerts.
type DetectionFinding struct {
	ClassUID     int    `json:"class_uid"`
	ClassName    string `json:"class_name"`
	CategoryUID  int    `json:"category_uid"`
	CategoryName string `json:"category_name"`
	ActivityID   int    `json:"activity_id"`
	ActivityName string `json:"activity_name,omitempty"`
	TypeUID      int    `json:"type_uid"`

	SeverityID int    `json:"severity_id"`
	Severity   string `json:"severity"`

	// OCSF timestamps are milliseconds since the Unix epoch.
	Time      int64 `json:"time"`
	StartTime int64 `json:"start_time,omitempty"`
	EndTime   int64 `json:"end_time,omitempty"`

	Message     string       `json:"message,omitempty"`
	IsAlert     bool         `json:"is_alert"`
	Metadata    Metadata     `json:"metadata"`
	FindingInfo FindingInfo  `json:"finding_info"`
	Cloud       Cloud        `json:"cloud"`
	Resources   []Resource   `json:"resources,omitempty"`
	Observables []Observable `json:"observables,omitempty"`
	Evidences   []Evidence   `json:"evidences,omitempty"`

	// Unmapped keeps vendor fields that have no OCSF home. This is an
	// intentionally permissive extension point; it never replaces Raw.
	Unmapped map[string]any `json:"unmapped,omitempty"`
}

type Metadata struct {
	Version      string   `json:"version"`
	Product      Product  `json:"product"`
	UID          string   `json:"uid,omitempty"`
	EventCode    string   `json:"event_code,omitempty"`
	OriginalTime string   `json:"original_time,omitempty"`
	LogProvider  string   `json:"log_provider,omitempty"`
	LogName      string   `json:"log_name,omitempty"`
	LoggedTime   int64    `json:"logged_time,omitempty"`
	ModifiedTime int64    `json:"modified_time,omitempty"`
	Profiles     []string `json:"profiles,omitempty"`
}

type Product struct {
	VendorName string   `json:"vendor_name"`
	Name       string   `json:"name"`
	UID        string   `json:"uid,omitempty"`
	Version    string   `json:"version,omitempty"`
	Feature    *Feature `json:"feature,omitempty"`
}

type Feature struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

type FindingInfo struct {
	UID           string   `json:"uid"`
	Title         string   `json:"title"`
	Desc          string   `json:"desc,omitempty"`
	Types         []string `json:"types,omitempty"`
	FirstSeenTime int64    `json:"first_seen_time,omitempty"`
	LastSeenTime  int64    `json:"last_seen_time,omitempty"`
	CreatedTime   int64    `json:"created_time,omitempty"`
	ModifiedTime  int64    `json:"modified_time,omitempty"`
	SrcURL        string   `json:"src_url,omitempty"`
	Attacks       []Attack `json:"attacks,omitempty"`
}

type Attack struct {
	Tactic    *Tactic    `json:"tactic,omitempty"`
	Technique *Technique `json:"technique,omitempty"`
	Version   string     `json:"version,omitempty"`
}

type Tactic struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

type Technique struct {
	Name string `json:"name,omitempty"`
	UID  string `json:"uid,omitempty"`
}

type Cloud struct {
	Provider string   `json:"provider"`
	Region   string   `json:"region,omitempty"`
	Account  *Account `json:"account,omitempty"`
}

type Account struct {
	UID  string `json:"uid"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
}

type Resource struct {
	UID    string `json:"uid,omitempty"`
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
	Role   string `json:"role,omitempty"`
	Region string `json:"region,omitempty"`
}

// Observable type ids from the OCSF observable object.
const (
	ObservableUnknown          = 0
	ObservableHostname         = 1
	ObservableIPAddress        = 2
	ObservableUserName         = 4
	ObservableFileName         = 7
	ObservableFileHash         = 8
	ObservableProcessName      = 9
	ObservableResourceUID      = 10
	ObservableCommandLine      = 13
	ObservableProcessNameOther = 99
)

var observableTypeNames = map[int]string{
	ObservableUnknown:          "Unknown",
	ObservableHostname:         "Hostname",
	ObservableIPAddress:        "IP Address",
	ObservableUserName:         "User Name",
	ObservableFileName:         "File Name",
	ObservableFileHash:         "File Hash",
	ObservableProcessName:      "Process Name",
	ObservableResourceUID:      "Resource UID",
	ObservableCommandLine:      "Command Line",
	ObservableProcessNameOther: "Other",
}

// ObservableTypeName resolves the sibling caption for a type_id.
func ObservableTypeName(typeID int) string {
	if v, ok := observableTypeNames[typeID]; ok {
		return v
	}
	return "Other"
}

type Observable struct {
	Name   string `json:"name,omitempty"`
	Type   string `json:"type,omitempty"`
	TypeID int    `json:"type_id"`
	Value  string `json:"value"`
}

type Evidence struct {
	Data any `json:"data,omitempty"`
}
