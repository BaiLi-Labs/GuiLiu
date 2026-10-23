package cloudflare

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func normalize(raw json.RawMessage, severityFromAction bool, zoneID string) (model.Alert, error) {
	var event struct {
		Action             string          `json:"action"`
		Source             string          `json:"source"`
		ClientIP           string          `json:"clientIP"`
		ClientASN          json.RawMessage `json:"clientASN"`
		ClientCountryName  string          `json:"clientCountryName"`
		ClientRequestPath  string          `json:"clientRequestPath"`
		ClientRequestQuery string          `json:"clientRequestQuery"`
		UserAgent          string          `json:"userAgent"`
		Datetime           string          `json:"datetime"`
		RuleID             string          `json:"ruleId"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		return model.Alert{}, fmt.Errorf("decode cloudflare firewall event: %w", err)
	}

	severity := model.SeverityUnknown
	severitySource := ""
	if severityFromAction {
		severity, severitySource = severityFromActionName(event.Action)
	}

	title := "WAF event"
	if rule := strings.TrimSpace(event.RuleID); rule != "" {
		title = "WAF rule " + rule
	} else if action := strings.TrimSpace(event.Action); action != "" {
		title = "WAF " + action
	}

	collector := connector.NewObservableCollector(raw)
	collector.Add("ip", 2, strings.TrimSpace(event.ClientIP), "/clientIP")

	unmapped := map[string]any{"cloudflare": map[string]any{
		"action":               event.Action,
		"source":               event.Source,
		"rule_id":              event.RuleID,
		"client_asn":           connector.SourceScalar(raw, "/clientASN"),
		"client_country":       event.ClientCountryName,
		"client_request_path":  event.ClientRequestPath,
		"client_request_query": event.ClientRequestQuery,
		"user_agent":           event.UserAgent,
		"zone_id":              zoneID,
	}}
	if severitySource != "" {
		unmapped["severity_source"] = severitySource
	}

	return model.Alert{
		ExternalID:       connector.HashRaw(raw),
		Title:            title,
		Description:      requestSummary(event.ClientRequestPath, event.ClientRequestQuery),
		Severity:         severity,
		OriginalSeverity: "",
		VendorStatus:     strings.TrimSpace(event.Action),
		EventTime:        parseTime(event.Datetime),
		OriginalTime:     strings.TrimSpace(event.Datetime),
		Product:          "WAF Security Events",
		AlertType:        strings.TrimSpace(event.Source),
		RuleID:           strings.TrimSpace(event.RuleID),
		CloudAccountUID:  zoneID,
		SourceIP:         strings.TrimSpace(event.ClientIP),
		Observables:      collector.Values(),
		Unmapped:         unmapped,
		Raw:              append(json.RawMessage(nil), raw...),
	}, nil
}

func requestSummary(path, query string) string {
	path, query = strings.TrimSpace(path), strings.TrimSpace(query)
	switch {
	case path == "" && query == "":
		return ""
	case query == "":
		return path
	default:
		return path + "?" + query
	}
}

// severityFromActionName is opt-in. Cloudflare does not assign a severity to
// firewall events, so a derived value is explicitly labelled as such.
func severityFromActionName(action string) (model.Severity, string) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "drop":
		return model.SeverityMedium, "derived_from_action"
	case "challenge", "js_challenge", "managed_challenge":
		return model.SeverityLow, "derived_from_action"
	case "log":
		return model.SeverityInformational, "derived_from_action"
	default:
		return model.SeverityUnknown, ""
	}
}

func parseTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
