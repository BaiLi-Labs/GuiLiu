package crowdstrike

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

type device struct {
	DeviceID     string `json:"device_id"`
	Hostname     string `json:"hostname"`
	PlatformName string `json:"platform_name"`
	LocalIP      string `json:"local_ip"`
	ExternalIP   string `json:"external_ip"`
	OSVersion    string `json:"os_version"`
}

func normalize(raw json.RawMessage) (model.Alert, error) {
	var item struct {
		CompositeID      string `json:"composite_id"`
		ID               string `json:"id"`
		DisplayName      string `json:"display_name"`
		Name             string `json:"name"`
		Description      string `json:"description"`
		Severity         int    `json:"severity"`
		SeverityName     string `json:"severity_name"`
		Status           string `json:"status"`
		Timestamp        string `json:"timestamp"`
		CreatedTimestamp string `json:"created_timestamp"`
		UpdatedTimestamp string `json:"updated_timestamp"`
		Product          string `json:"product"`
		Type             string `json:"type"`
		Tactic           string `json:"tactic"`
		Technique        string `json:"technique"`
		Scenario         string `json:"scenario"`
		Objective        string `json:"objective"`
		UserName         string `json:"user_name"`
		FileName         string `json:"file_name"`
		FilePath         string `json:"file_path"`
		SHA256           string `json:"sha256"`
		MD5              string `json:"md5"`
		CommandLine      string `json:"command_line"`
		Device           device `json:"device"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return model.Alert{}, fmt.Errorf("decode crowdstrike alert: %w", err)
	}

	externalID := connector.FirstNonEmpty(strings.TrimSpace(item.CompositeID), strings.TrimSpace(item.ID))
	if externalID == "" {
		externalID = connector.HashRaw(raw)
	}
	severity, original := severityOf(item.SeverityName, item.Severity)

	collector := connector.NewObservableCollector(raw)
	collector.Add("hostname", 1, strings.TrimSpace(item.Device.Hostname), "/device/hostname")
	collector.Add("ip", 2, strings.TrimSpace(item.Device.LocalIP), "/device/local_ip")
	collector.Add("ip", 2, strings.TrimSpace(item.Device.ExternalIP), "/device/external_ip")
	collector.Add("user.name", 4, strings.TrimSpace(item.UserName), "/user_name")
	collector.Add("file.name", 7, strings.TrimSpace(item.FileName), "/file_name")
	collector.Add("file.hash.sha256", 8, strings.TrimSpace(item.SHA256), "/sha256")

	var evidences []model.Evidence
	process := map[string]any{}
	for key, value := range map[string]string{
		"command_line": item.CommandLine,
		"file_name":    item.FileName,
		"file_path":    item.FilePath,
		"sha256":       item.SHA256,
		"md5":          item.MD5,
	} {
		if strings.TrimSpace(value) != "" {
			process[key] = value
		}
	}
	if len(process) > 0 {
		evidences = append(evidences, model.Evidence{Type: "process", Data: process})
	}

	unmapped := map[string]any{"crowdstrike": map[string]any{
		"scenario":           item.Scenario,
		"objective":          item.Objective,
		"technique":          item.Technique,
		"severity_raw":       item.Severity,
		"severity_name":      item.SeverityName,
		"device_platform":    item.Device.PlatformName,
		"device_os_version":  item.Device.OSVersion,
		"device_id":          item.Device.DeviceID,
		"device_local_ip":    item.Device.LocalIP,
		"device_external_ip": item.Device.ExternalIP,
	}}

	title := connector.FirstNonEmpty(strings.TrimSpace(item.DisplayName), strings.TrimSpace(item.Name))
	if title == "" {
		title = "Falcon alert"
	}
	resource := connector.NamedResource(
		connector.FirstNonEmpty(strings.TrimSpace(item.Device.DeviceID), strings.TrimSpace(item.Device.Hostname)),
		"host",
		strings.TrimSpace(item.Device.Hostname),
		strings.TrimSpace(item.Device.Hostname),
	)

	return model.Alert{
		ExternalID:       externalID,
		Title:            title,
		Description:      strings.TrimSpace(item.Description),
		Severity:         severity,
		OriginalSeverity: original,
		VendorStatus:     strings.TrimSpace(item.Status),
		EventTime:        parseTime(item.Timestamp),
		SourceCreatedAt:  parseTime(item.CreatedTimestamp),
		SourceUpdatedAt:  parseTime(item.UpdatedTimestamp),
		OriginalTime:     strings.TrimSpace(item.Timestamp),
		Product:          strings.TrimSpace(item.Product),
		AlertType:        strings.TrimSpace(item.Type),
		Resource:         resource,
		Actor:            strings.TrimSpace(item.UserName),
		Tactic:           strings.TrimSpace(item.Tactic),
		Technique:        strings.TrimSpace(item.Technique),
		Observables:      collector.Values(),
		Evidences:        evidences,
		Unmapped:         unmapped,
		Raw:              append(json.RawMessage(nil), raw...),
	}, nil
}

// severityOf prefers the vendor's label. The numeric scale is only a fallback
// and its bands are deliberately coarse; the original value is always kept.
func severityOf(name string, value int) (model.Severity, string) {
	label := strings.TrimSpace(name)
	switch strings.ToLower(label) {
	case "informational", "info":
		return model.SeverityInformational, original(label, value)
	case "low":
		return model.SeverityLow, original(label, value)
	case "medium", "moderate":
		return model.SeverityMedium, original(label, value)
	case "high":
		return model.SeverityHigh, original(label, value)
	case "critical":
		return model.SeverityCritical, original(label, value)
	}
	switch {
	case value <= 0:
		return model.SeverityUnknown, original(label, value)
	case value < 20:
		return model.SeverityInformational, original(label, value)
	case value < 40:
		return model.SeverityLow, original(label, value)
	case value < 60:
		return model.SeverityMedium, original(label, value)
	case value < 80:
		return model.SeverityHigh, original(label, value)
	default:
		return model.SeverityCritical, original(label, value)
	}
}

func original(label string, value int) string {
	if label != "" {
		return label
	}
	return strconv.Itoa(value)
}

func parseTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999Z0700"} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
