package safelinece

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
		ID          json.RawMessage `json:"id"`
		EventID     json.RawMessage `json:"event_id"`
		EventIDAlt  json.RawMessage `json:"eventId"`
		Timestamp   json.RawMessage `json:"timestamp"`
		CreatedAt   json.RawMessage `json:"created_at"`
		UpdatedAt   json.RawMessage `json:"updated_at"`
		Action      json.RawMessage `json:"action"`
		AttackType  json.RawMessage `json:"attack_type"`
		RiskLevel   json.RawMessage `json:"risk_level"`
		Reason      json.RawMessage `json:"reason"`
		Module      json.RawMessage `json:"module"`
		PolicyName  json.RawMessage `json:"policy_name"`
		SrcIP       json.RawMessage `json:"src_ip"`
		DstIP       json.RawMessage `json:"dst_ip"`
		SrcPort     json.RawMessage `json:"src_port"`
		DstPort     json.RawMessage `json:"dst_port"`
		Host        json.RawMessage `json:"host"`
		URLPath     json.RawMessage `json:"url_path"`
		Method      json.RawMessage `json:"method"`
		QueryString json.RawMessage `json:"query_string"`
		RuleID      json.RawMessage `json:"rule_id"`
		ShortRuleID json.RawMessage `json:"short_rule_id"`
		RuleIDList  json.RawMessage `json:"rule_id_list"`
		JA4         json.RawMessage `json:"ja4_fingerprint"`
		Protocol    json.RawMessage `json:"protocol"`
		StatusCode  json.RawMessage `json:"status_code"`
		Country     json.RawMessage `json:"country"`
		Province    json.RawMessage `json:"province"`
		City        json.RawMessage `json:"city"`
		SiteUUID    json.RawMessage `json:"site_uuid"`
		Website     json.RawMessage `json:"website"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return model.Alert{}, fmt.Errorf("decode safeline ce record: %w", err)
	}

	externalID := connector.FirstNonEmpty(
		strings.TrimSpace(scalarText(item.EventID)),
		strings.TrimSpace(scalarText(item.EventIDAlt)),
		strings.TrimSpace(scalarText(item.ID)),
	)
	if externalID == "" {
		externalID = connector.HashRaw(raw)
	}
	srcIP := strings.TrimSpace(scalarText(item.SrcIP))
	dstIP := strings.TrimSpace(scalarText(item.DstIP))
	host := strings.TrimSpace(scalarText(item.Host))
	attackType := strings.TrimSpace(scalarText(item.AttackType))
	riskLevel := strings.TrimSpace(scalarText(item.RiskLevel))
	severity, original := severityOf(riskLevel, severityFrom)
	eventTime := parseTimestamp(scalarText(item.Timestamp))

	collector := connector.NewObservableCollector(raw)
	collector.Add("ip", 2, srcIP, "/src_ip")
	collector.Add("ip", 2, dstIP, "/dst_ip")
	collector.Add("hostname", 1, host, "/host")

	title := strings.TrimSpace(scalarText(item.Reason))
	if title == "" {
		title = "SafeLine CE attack log"
	}
	urlPath := strings.TrimSpace(scalarText(item.URLPath))
	queryString := strings.TrimSpace(scalarText(item.QueryString))
	description := urlPath
	if queryString != "" {
		description = urlPath + "?" + queryString
	}

	unmapped := map[string]any{"safeline_ce": map[string]any{
		"action":          scalarText(item.Action),
		"action_label":    actionLabel(scalarText(item.Action)),
		"attack_type":     attackType,
		"risk_level":      riskLevel,
		"module":          scalarText(item.Module),
		"policy_name":     scalarText(item.PolicyName),
		"method":          scalarText(item.Method),
		"url_path":        urlPath,
		"query_string":    queryString,
		"ja4_fingerprint": scalarText(item.JA4),
		"protocol":        scalarText(item.Protocol),
		"status_code":     scalarText(item.StatusCode),
		"src_port":        scalarText(item.SrcPort),
		"dst_port":        scalarText(item.DstPort),
		"short_rule_id":   scalarText(item.ShortRuleID),
		"rule_id_list":    rawOrText(item.RuleIDList),
		"country":         scalarText(item.Country),
		"province":        scalarText(item.Province),
		"city":            scalarText(item.City),
		"site_uuid":       scalarText(item.SiteUUID),
		"website":         scalarText(item.Website),
		// Large request/response captures stay in Raw only.
	}}
	if severityFrom {
		unmapped["severity_source"] = "derived_from_risk_level"
	}

	return model.Alert{
		ExternalID:       externalID,
		Title:            title,
		Description:      description,
		Severity:         severity,
		OriginalSeverity: original,
		VendorStatus:     actionLabel(scalarText(item.Action)),
		EventTime:        eventTime,
		SourceUpdatedAt:  parseTimestamp(scalarText(item.UpdatedAt)),
		OriginalTime:     scalarText(item.Timestamp),
		Product:          "SafeLine Community Edition",
		AlertType:        attackType,
		RuleID:           connector.FirstNonEmpty(strings.TrimSpace(scalarText(item.RuleID)), strings.TrimSpace(scalarText(item.ShortRuleID))),
		Resource:         connector.NamedResource(host, "domain", "", host),
		SourceIP:         srcIP,
		DestinationIP:    dstIP,
		Observables:      collector.Values(),
		Unmapped:         unmapped,
		Raw:              append(json.RawMessage(nil), raw...),
	}, nil
}

// actionLabel uses the documented mapping: 0 allow, 1 block. Any other value is
// kept verbatim instead of being coerced.
func actionLabel(value string) string {
	switch strings.TrimSpace(value) {
	case "0":
		return "allowed"
	case "1":
		return "blocked"
	case "":
		return ""
	default:
		return value
	}
}

// severityOf keeps the vendor level unless derivation is explicitly enabled.
func severityOf(text string, derive bool) (model.Severity, string) {
	text = strings.TrimSpace(text)
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

// parseTimestamp accepts Unix seconds, Unix milliseconds or a datetime string.
func parseTimestamp(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	digits := true
	for _, r := range value {
		if r < '0' || r > '9' {
			digits = false
			break
		}
	}
	if digits {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return time.Time{}
		}
		if len(value) >= 13 {
			return time.UnixMilli(n).UTC()
		}
		return time.Unix(n, 0).UTC()
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, value); err == nil {
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
