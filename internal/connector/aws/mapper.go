package aws

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func normalizeFinding(f map[string]any, raw json.RawMessage) (model.Alert, error) {
	info := mapAt(f, "finding_info")
	metadata := mapAt(f, "metadata")
	product := mapAt(metadata, "product")
	cloud := mapAt(f, "cloud")
	account := mapAt(cloud, "account")

	externalID := connector.FirstNonEmpty(
		stringAt(info, "uid"),
		stringAt(metadata, "uid"),
	)
	if externalID == "" {
		return model.Alert{}, fmt.Errorf("AWS source record has no native finding UID")
	}
	eventTime := timeAt(f, "time")
	firstSeen := timeAt(info, "first_seen_time")
	lastSeen := timeAt(info, "last_seen_time")
	kind := model.FindingOther
	switch int(numberAt(f, "class_uid")) {
	case 2004:
		kind = model.FindingDetection
	case 2002:
		kind = model.FindingVulnerability
	case 2003:
		kind = model.FindingCompliance
	case 2005:
		kind = model.FindingIncident
	}
	severity := mapSeverity(f)

	alert := model.Alert{
		ExternalID:       externalID,
		FindingKind:      kind,
		RuleID:           stringAt(mapAt(info, "analytic"), "uid"),
		SourceCreatedAt:  timeAt(info, "created_time"),
		SourceUpdatedAt:  timeAt(info, "modified_time"),
		OCSF:             append(json.RawMessage(nil), raw...),
		Title:            connector.FirstNonEmpty(stringAt(info, "title"), stringAt(product, "name"), "AWS Security Hub finding"),
		Description:      stringAt(info, "desc"),
		Severity:         severity,
		OriginalSeverity: connector.FirstNonEmpty(stringAt(f, "severity"), scalarString(f["severity_id"])),
		VendorStatus:     statusText(f),
		EventTime:        eventTime,
		FirstSeenAt:      firstSeen,
		LastSeenAt:       lastSeen,
		OriginalTime:     stringAt(metadata, "original_time"),
		Product:          connector.FirstNonEmpty(stringAt(product, "name"), "Security Hub"),
		AlertType:        connector.FirstNonEmpty(findingTypes(info), stringAt(metadata, "event_code"), stringAt(f, "class_name")),
		Region:           stringAt(cloud, "region"),
		CloudAccountUID:  stringAt(account, "uid"),
		Raw:              append(json.RawMessage(nil), raw...),
	}

	for _, value := range sliceAt(f, "resources") {
		if r, ok := value.(map[string]any); ok {
			alert.Resources = append(alert.Resources, connector.NamedResource(
				stringAt(r, "uid"),
				connector.FirstNonEmpty(stringAt(r, "type"), "resource"),
				stringAt(r, "name"),
				stringAt(r, "uid"),
			))
		}
	}
	if len(alert.Resources) > 0 {
		alert.Resource = alert.Resources[0]
	}
	alert.Observables, alert.SourceIP, alert.DestinationIP = observables(f, raw)
	if evidences := sliceAt(f, "evidences"); len(evidences) > 0 {
		for _, e := range evidences {
			if m, ok := e.(map[string]any); ok {
				alert.Evidences = append(alert.Evidences, model.Evidence{Type: "aws.securityhub", Data: m})
			}
		}
	}
	if len(alert.Evidences) == 0 && len(alert.Observables) > 0 {
		alert.Evidences = []model.Evidence{{Type: "aws.securityhub", Data: map[string]any{"observables": alert.Observables}}}
	}
	return alert, nil
}

func mapSeverity(f map[string]any) model.Severity {
	switch int(numberAt(f, "severity_id")) {
	case 1:
		return model.SeverityInformational
	case 2:
		return model.SeverityLow
	case 3:
		return model.SeverityMedium
	case 4:
		return model.SeverityHigh
	case 5:
		return model.SeverityCritical
	case 6:
		return model.SeverityFatal
	}
	switch strings.ToLower(stringAt(f, "severity")) {
	case "informational", "info":
		return model.SeverityInformational
	case "low":
		return model.SeverityLow
	case "medium":
		return model.SeverityMedium
	case "high":
		return model.SeverityHigh
	case "critical":
		return model.SeverityCritical
	case "fatal":
		return model.SeverityFatal
	default:
		return model.SeverityUnknown
	}
}

func statusText(f map[string]any) string {
	if status := stringAt(f, "status"); status != "" {
		return status
	}
	return scalarString(f["status_id"])
}

func observables(f map[string]any, raw json.RawMessage) ([]model.Observable, string, string) {
	collector := connector.NewObservableCollector(raw)
	add := collector.Add
	sourceIP, destIP := "", ""
	if values := sliceAt(f, "observables"); len(values) > 0 {
		for i, item := range values {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name := stringAt(m, "name")
			value := scalarString(m["value"])
			add(name, int(numberAt(m, "type_id")), value, fmt.Sprintf("/observables/%d/value", i))
			switch name {
			case "src_endpoint.ip":
				sourceIP = connector.FirstNonEmpty(sourceIP, value)
			case "dst_endpoint.ip":
				destIP = connector.FirstNonEmpty(destIP, value)
			}
		}
	}
	if evidences := sliceAt(f, "evidences"); len(evidences) > 0 {
		for i, item := range evidences {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			src := mapAt(m, "src_endpoint")
			dst := mapAt(m, "dst_endpoint")
			sourceIP = connector.FirstNonEmpty(sourceIP, stringAt(src, "ip"))
			destIP = connector.FirstNonEmpty(destIP, stringAt(dst, "ip"))
			add("src_endpoint.ip", 2, stringAt(src, "ip"), fmt.Sprintf("/evidences/%d/src_endpoint/ip", i))
			add("dst_endpoint.ip", 2, stringAt(dst, "ip"), fmt.Sprintf("/evidences/%d/dst_endpoint/ip", i))
		}
	}
	// Finding resources are useful observables even without an evidence block.
	for i, value := range sliceAt(f, "resources") {
		if r, ok := value.(map[string]any); ok {
			add("resources.uid", 10, stringAt(r, "uid"), fmt.Sprintf("/resources/%d/uid", i))
			add("resources.name", 38, stringAt(r, "name"), fmt.Sprintf("/resources/%d/name", i))
		}
	}
	return collector.Values(), sourceIP, destIP
}

func findingTypes(info map[string]any) string {
	values := sliceAt(info, "types")
	var types []string
	for _, v := range values {
		if s := scalarString(v); s != "" {
			types = append(types, s)
		}
	}
	return strings.Join(types, ", ")
}

func mapAt(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	v, _ := m[key].(map[string]any)
	return v
}

func sliceAt(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	v, _ := m[key].([]any)
	return v
}

func stringAt(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	return scalarString(m[key])
}

func numberAt(m map[string]any, key string) float64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		f, _ := v.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	default:
		return 0
	}
}

func scalarString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	default:
		return ""
	}
}

func timeAt(m map[string]any, key string) time.Time {
	if m == nil {
		return time.Time{}
	}
	// AWS OCSF documents may expose RFC3339 *_dt siblings instead of numeric
	// millisecond timestamps. Both are vendor-provided representations.
	if v, ok := m[key+"_dt"].(string); ok {
		if t, valid := connector.ParseVendorTime(v); valid {
			return t
		}
	}
	switch v := m[key].(type) {
	case string:
		if t, ok := connector.ParseVendorTime(v); ok {
			return t
		}
	case float64:
		return time.UnixMilli(int64(v)).UTC()
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return time.UnixMilli(n).UTC()
		}
	}
	return time.Time{}
}
