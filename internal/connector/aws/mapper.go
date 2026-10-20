package aws

import (
	"encoding/json"
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
		externalID = connector.HashRaw(raw)
	}
	eventTime := timeAt(f, "time")
	if eventTime.IsZero() {
		eventTime = timeAt(info, "last_seen_time")
	}
	if eventTime.IsZero() {
		eventTime = timeAt(info, "created_time")
	}
	firstSeen := timeAt(info, "first_seen_time")
	if firstSeen.IsZero() {
		firstSeen = timeAt(info, "created_time")
	}
	if firstSeen.IsZero() {
		firstSeen = eventTime
	}
	lastSeen := timeAt(info, "last_seen_time")
	if lastSeen.IsZero() {
		lastSeen = timeAt(info, "modified_time")
	}
	if lastSeen.IsZero() {
		lastSeen = eventTime
	}
	severity := mapSeverity(f)

	alert := model.Alert{
		ExternalID:       externalID,
		Title:            connector.FirstNonEmpty(stringAt(info, "title"), stringAt(f, "activity_name"), stringAt(product, "name"), "AWS Security Hub finding"),
		Description:      stringAt(info, "desc"),
		Severity:         severity,
		OriginalSeverity: connector.FirstNonEmpty(stringAt(f, "severity"), strconv.Itoa(int(numberAt(f, "severity_id")))),
		VendorStatus:     statusText(f),
		EventTime:        eventTime,
		FirstSeenAt:      firstSeen,
		LastSeenAt:       lastSeen,
		OriginalTime:     stringAt(metadata, "original_time"),
		Product:          connector.FirstNonEmpty(stringAt(product, "name"), "Security Hub"),
		AlertType:        connector.FirstNonEmpty(stringAt(f, "activity_name"), firstType(info), stringAt(metadata, "event_code")),
		Region:           stringAt(cloud, "region"),
		CloudAccountUID:  stringAt(account, "uid"),
		Raw:              append(json.RawMessage(nil), raw...),
	}

	if resources := sliceAt(f, "resources"); len(resources) > 0 {
		if r, ok := resources[0].(map[string]any); ok {
			alert.Resource = model.Resource{
				ID:   stringAt(r, "uid"),
				Name: stringAt(r, "name"),
				Type: connector.FirstNonEmpty(stringAt(r, "type"), "resource"),
			}
		}
	}
	alert.Observables, alert.SourceIP, alert.DestinationIP = observables(f, info)
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
		return strings.ToLower(status)
	}
	if id := numberAt(f, "status_id"); id > 0 {
		return strconv.Itoa(int(id))
	}
	return ""
}

func observables(f, info map[string]any) ([]model.Observable, string, string) {
	out := make([]model.Observable, 0, 6)
	seen := map[string]bool{}
	add := func(name string, typeID int, value string) {
		if value == "" || seen[name+"|"+value] {
			return
		}
		seen[name+"|"+value] = true
		out = append(out, model.Observable{Name: name, TypeID: typeID, Value: value})
	}
	sourceIP, destIP := "", ""
	if values := sliceAt(f, "observables"); len(values) > 0 {
		for _, item := range values {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name := stringAt(m, "name")
			value := scalarString(m["value"])
			add(name, int(numberAt(m, "type_id")), value)
			switch name {
			case "src_endpoint.ip":
				sourceIP = connector.FirstNonEmpty(sourceIP, value)
			case "dst_endpoint.ip":
				destIP = connector.FirstNonEmpty(destIP, value)
			}
		}
	}
	if evidences := sliceAt(f, "evidences"); len(evidences) > 0 {
		for _, item := range evidences {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			src := mapAt(m, "src_endpoint")
			dst := mapAt(m, "dst_endpoint")
			sourceIP = connector.FirstNonEmpty(sourceIP, stringAt(src, "ip"))
			destIP = connector.FirstNonEmpty(destIP, stringAt(dst, "ip"))
			add("src_endpoint.ip", 2, stringAt(src, "ip"))
			add("dst_endpoint.ip", 2, stringAt(dst, "ip"))
		}
	}
	// Finding resources are useful observables even without an evidence block.
	if resources := sliceAt(f, "resources"); len(resources) > 0 {
		if r, ok := resources[0].(map[string]any); ok {
			add("resources.uid", 10, stringAt(r, "uid"))
		}
	}
	return out, sourceIP, destIP
}

func firstType(info map[string]any) string {
	values := sliceAt(info, "types")
	for _, v := range values {
		if s := scalarString(v); s != "" {
			return s
		}
	}
	return ""
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
