package safeline

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// Fields are decoded as RawMessage because the appliance is inconsistent about
// types: the list scope returns url_path as a string, while filters such as
// attack_type__in show that some identifiers may arrive as numbers.
func normalize(raw json.RawMessage) (model.Alert, error) {
	var item struct {
		EventID    json.RawMessage `json:"event_id"`
		Timestamp  json.RawMessage `json:"timestamp"`
		SrcIP      json.RawMessage `json:"src_ip"`
		Host       json.RawMessage `json:"host"`
		URLPath    json.RawMessage `json:"url_path"`
		URL        json.RawMessage `json:"url"`
		Method     json.RawMessage `json:"method"`
		AttackType json.RawMessage `json:"attack_type"`
		RiskLevel  json.RawMessage `json:"risk_level"`
		Action     struct {
			Translation json.RawMessage `json:"translation"`
		} `json:"action"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return model.Alert{}, fmt.Errorf("decode safeline detection: %w", err)
	}

	eventID := scalarText(item.EventID)
	externalID := strings.TrimSpace(eventID)
	if externalID == "" {
		externalID = connector.HashRaw(raw)
	}
	srcIP := strings.TrimSpace(scalarText(item.SrcIP))
	host := strings.TrimSpace(scalarText(item.Host))
	urlPath := connector.FirstNonEmpty(strings.TrimSpace(scalarText(item.URLPath)), strings.TrimSpace(scalarText(item.URL)))
	attackType := strings.TrimSpace(scalarText(item.AttackType))
	action := strings.TrimSpace(scalarText(item.Action.Translation))
	timestamp := strings.TrimSpace(scalarText(item.Timestamp))

	riskLevel := connector.SourceScalar(raw, "/risk_level")
	severity, original := riskSeverity(item.RiskLevel)
	eventTime, parsed := parseTimestamp(timestamp)
	originalTime := ""
	if parsed {
		originalTime = timestamp
	}

	collector := connector.NewObservableCollector(raw)
	collector.Add("src_endpoint.ip", 2, srcIP, "/src_ip")
	collector.Add("hostname", 1, host, "/host")

	title := attackType
	if title == "" {
		title = "SafeLine detection"
	}

	return model.Alert{
		ExternalID:       externalID,
		Title:            title,
		Severity:         severity,
		OriginalSeverity: original,
		VendorStatus:     action,
		EventTime:        eventTime,
		OriginalTime:     originalTime,
		Product:          "SafeLine WAF",
		AlertType:        attackType,
		Resource:         connector.NamedResource(host, "domain", "", host),
		SourceIP:         srcIP,
		Observables:      collector.Values(),
		Unmapped: map[string]any{
			"safeline": map[string]any{
				"risk_level": riskLevel,
				"method":     strings.TrimSpace(scalarText(item.Method)),
				"url_path":   urlPath,
				"action":     action,
			},
		},
		Raw: append(json.RawMessage(nil), raw...),
	}, nil
}

// riskSeverity maps the appliance's risk level. SafeLine is documented with
// numeric levels; text levels are accepted because later versions may render
// the label directly. The original value is always retained.
func riskSeverity(raw json.RawMessage) (model.Severity, string) {
	text := scalarText(raw)
	if text == "" {
		return model.SeverityUnknown, ""
	}
	switch strings.ToLower(text) {
	case "0", "unknown", "info", "informational":
		return model.SeverityUnknown, text
	case "1", "low":
		return model.SeverityLow, text
	case "2", "medium", "moderate", "middle":
		return model.SeverityMedium, text
	case "3", "high":
		return model.SeverityHigh, text
	case "4", "critical", "severe", "very-high", "very high":
		return model.SeverityCritical, text
	default:
		return model.SeverityUnknown, text
	}
}

// scalarText renders a JSON string or number exactly as the source spelled it.
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
