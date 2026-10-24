package cosmos

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// Field names follow the filter names in the public alarm definition. They are
// the best available evidence for the response shape, not a confirmed schema:
// alarm.json declares an empty reply object, so every alert carries
// _mapping_unverified until a real response is compared.
func normalize(raw json.RawMessage, severityFrom bool) (model.Alert, error) {
	var item struct {
		ID             json.RawMessage `json:"id"`
		AlarmName      json.RawMessage `json:"alarm_name"`
		AlarmLevel     json.RawMessage `json:"alarm_level"`
		MajorType      json.RawMessage `json:"alarm_major_type"`
		MinorType      json.RawMessage `json:"alarm_minor_type"`
		AttackIP       json.RawMessage `json:"attack_ip"`
		AttackIPString json.RawMessage `json:"attack_ip_string"`
		VictimIP       json.RawMessage `json:"victim_ip"`
		VictimIPString json.RawMessage `json:"victim_ip_string"`
		AttackMethod   json.RawMessage `json:"attack_method"`
		AttackResult   json.RawMessage `json:"attack_result"`
		Direction      json.RawMessage `json:"attack_direction"`
		Phase          json.RawMessage `json:"attack_chain_phase"`
		DisposedState  json.RawMessage `json:"disposed_state"`
		JudgedState    json.RawMessage `json:"judged_state"`
		CreatedAt      json.RawMessage `json:"created_at"`
		UpdatedAt      json.RawMessage `json:"updated_at"`
		Tag            json.RawMessage `json:"tag"`
		VictimWebURL   json.RawMessage `json:"victim_web_url"`
		DeviceID       json.RawMessage `json:"device_id"`
		OrgID          json.RawMessage `json:"organization_id"`
		Comment        json.RawMessage `json:"comment"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return model.Alert{}, fmt.Errorf("decode cosmos alarm: %w", err)
	}

	externalID := strings.TrimSpace(scalarText(item.ID))
	if externalID == "" {
		externalID = connector.HashRaw(raw)
	}
	srcIP := firstIP(item.AttackIPString, item.AttackIP)
	dstIP := firstIP(item.VictimIPString, item.VictimIP)
	severity, original := severityOf(item.AlarmLevel, severityFrom)
	eventTime := alarmTime(item.CreatedAt)

	collector := connector.NewObservableCollector(raw)
	collector.Add("ip", 2, srcIP, "/attack_ip_string", "/attack_ip")
	collector.Add("ip", 2, dstIP, "/victim_ip_string", "/victim_ip")

	title := strings.TrimSpace(scalarText(item.AlarmName))
	if title == "" {
		title = "Cosmos alarm"
	}
	alertType := connector.FirstNonEmpty(
		strings.TrimSpace(scalarText(item.MajorType)),
		strings.TrimSpace(scalarText(item.MinorType)),
	)
	vendorStatus := connector.FirstNonEmpty(
		strings.TrimSpace(scalarText(item.DisposedState)),
		strings.TrimSpace(scalarText(item.JudgedState)),
	)

	return model.Alert{
		ExternalID:       externalID,
		Title:            title,
		Description:      strings.TrimSpace(scalarText(item.Comment)),
		Severity:         severity,
		OriginalSeverity: original,
		VendorStatus:     vendorStatus,
		EventTime:        eventTime,
		SourceUpdatedAt:  parseTime(item.UpdatedAt),
		OriginalTime:     strings.TrimSpace(scalarText(item.CreatedAt)),
		Product:          "Cosmos / AISOC",
		AlertType:        alertType,
		SourceIP:         srcIP,
		DestinationIP:    dstIP,
		Observables:      collector.Values(),
		Unmapped: map[string]any{"cosmos": map[string]any{
			"mapping_unverified": true,
			"contract_source":    "chaitin-cli products/cosmos/apis/alarm.json (reply schema is empty)",
			"major_type":         scalarText(item.MajorType),
			"minor_type":         scalarText(item.MinorType),
			"attack_method":      scalarText(item.AttackMethod),
			"attack_result":      scalarText(item.AttackResult),
			"direction":          scalarText(item.Direction),
			"chain_phase":        scalarText(item.Phase),
			"disposed_state":     scalarText(item.DisposedState),
			"judged_state":       scalarText(item.JudgedState),
			"tag":                rawOrText(item.Tag),
			"victim_web_url":     rawOrText(item.VictimWebURL),
			"device_id":          scalarText(item.DeviceID),
			"organization_id":    scalarText(item.OrgID),
			"attack_ip_raw":      rawOrText(item.AttackIP),
			"victim_ip_raw":      rawOrText(item.VictimIP),
		}},
		Raw: append(json.RawMessage(nil), raw...),
	}, nil
}

func severityOf(raw json.RawMessage, derive bool) (model.Severity, string) {
	text := strings.TrimSpace(scalarText(raw))
	if text == "" {
		return model.SeverityUnknown, ""
	}
	if !derive {
		// alarm_level semantics are not published; keep it without inventing.
		return model.SeverityUnknown, text
	}
	switch text {
	case "1":
		return model.SeverityCritical, text
	case "2":
		return model.SeverityHigh, text
	case "3":
		return model.SeverityMedium, text
	case "4":
		return model.SeverityLow, text
	default:
		return model.SeverityUnknown, text
	}
}

// firstIP prefers the scalar filter field and falls back to the first element
// of the array field. The array form is kept verbatim in Unmapped.
func firstIP(scalars ...json.RawMessage) string {
	for _, raw := range scalars {
		if text := strings.TrimSpace(scalarText(raw)); text != "" {
			return text
		}
		var list []json.RawMessage
		if json.Unmarshal(raw, &list) == nil && len(list) > 0 {
			if text := strings.TrimSpace(scalarText(list[0])); text != "" {
				return text
			}
		}
	}
	return ""
}

func alarmTime(raw json.RawMessage) time.Time {
	text := strings.TrimSpace(scalarText(raw))
	if text == "" {
		return time.Time{}
	}
	digits := true
	for _, r := range text {
		if r < '0' || r > '9' {
			digits = false
			break
		}
	}
	if digits {
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return time.Time{}
		}
		if len(text) >= 13 {
			return time.UnixMilli(n).UTC()
		}
		return time.Unix(n, 0).UTC()
	}
	return parseTime(raw)
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
