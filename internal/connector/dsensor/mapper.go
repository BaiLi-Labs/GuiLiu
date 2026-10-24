package dsensor

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func normalize(raw json.RawMessage, severityFrom bool) (model.Alert, error) {
	var item struct {
		ID            json.RawMessage `json:"id"`
		AgentID       json.RawMessage `json:"agent_id"`
		AlarmType     json.RawMessage `json:"alarm_type"`
		Description   json.RawMessage `json:"description"`
		SrcIP         json.RawMessage `json:"src_ip"`
		DestIP        json.RawMessage `json:"dest_ip"`
		RiskLevel     json.RawMessage `json:"risk_level"`
		Status        json.RawMessage `json:"status"`
		LastAlarmTime json.RawMessage `json:"last_alarm_time"`
		Node          json.RawMessage `json:"node"`
		History       json.RawMessage `json:"history"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return model.Alert{}, fmt.Errorf("decode dsensor alarm: %w", err)
	}

	externalID := strings.TrimSpace(scalarText(item.ID))
	if externalID == "" {
		externalID = connector.HashRaw(raw)
	}
	srcIP := strings.TrimSpace(scalarText(item.SrcIP))
	dstIP := strings.TrimSpace(scalarText(item.DestIP))
	alarmType := strings.TrimSpace(scalarText(item.AlarmType))
	severity, original := severityOf(item.RiskLevel, severityFrom)
	eventTime := parseTime(item.LastAlarmTime)

	collector := connector.NewObservableCollector(raw)
	collector.Add("ip", 2, srcIP, "/src_ip")
	collector.Add("ip", 2, dstIP, "/dest_ip")

	title := strings.TrimSpace(scalarText(item.Description))
	if title == "" {
		title = alarmTypeLabel(alarmType)
	}

	unmapped := map[string]any{"dsensor": map[string]any{
		"agent_id":   scalarText(item.AgentID),
		"node":       scalarText(item.Node),
		"alarm_type": alarmType,
		"risk_level": scalarText(item.RiskLevel),
		"status":     scalarText(item.Status),
		"history":    rawOrText(item.History),
	}}
	if severityFrom {
		unmapped["severity_source"] = "derived_from_risk_level"
	}

	return model.Alert{
		ExternalID:       externalID,
		Title:            title,
		Severity:         severity,
		OriginalSeverity: original,
		VendorStatus:     strings.TrimSpace(scalarText(item.Status)),
		EventTime:        eventTime,
		OriginalTime:     strings.TrimSpace(scalarText(item.LastAlarmTime)),
		Product:          "D-Sensor (谛听)",
		AlertType:        alarmType,
		SourceIP:         srcIP,
		DestinationIP:    dstIP,
		Observables:      collector.Values(),
		Unmapped:         unmapped,
		Raw:              append(json.RawMessage(nil), raw...),
	}, nil
}

// severityOf keeps the vendor level untouched unless derivation is enabled.
// The published schema enumerates 1-4 but does not state which end is most
// severe, so the derived ordering is labelled.
func severityOf(raw json.RawMessage, derive bool) (model.Severity, string) {
	text := strings.TrimSpace(scalarText(raw))
	if text == "" {
		return model.SeverityUnknown, ""
	}
	if !derive {
		return model.SeverityUnknown, text
	}
	switch text {
	case "1":
		return model.SeverityLow, text
	case "2":
		return model.SeverityMedium, text
	case "3":
		return model.SeverityHigh, text
	case "4":
		return model.SeverityCritical, text
	default:
		return model.SeverityUnknown, text
	}
}

// alarmTypeLabel uses the meaning documented in the schema.
func alarmTypeLabel(value string) string {
	switch strings.ToLower(value) {
	case "connection":
		return "Intrusion event"
	case "scanner":
		return "Port scan event"
	default:
		return "D-Sensor alarm"
	}
}

func parseTime(raw json.RawMessage) time.Time {
	text := strings.TrimSpace(scalarText(raw))
	if text == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, text); err == nil {
			return t.UTC()
		}
	}
	// Some builds emit epoch milliseconds instead of RFC 3339.
	if n, err := strconv.ParseInt(text, 10, 64); err == nil && len(text) >= 13 {
		return time.UnixMilli(n).UTC()
	}
	return time.Time{}
}

func rawOrText(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if json.Unmarshal(raw, &value) == nil {
		return value
	}
	return string(raw)
}

func scalarText(raw json.RawMessage) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return strings.TrimSpace(text)
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}
