package tanswer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// Alarm fields follow the list command's documented projection. Values are
// decoded as RawMessage because several fields switch between string and
// number depending on the appliance version.
func normalize(raw json.RawMessage) (model.Alert, error) {
	var item struct {
		DocID         json.RawMessage `json:"doc_id"`
		Name          json.RawMessage `json:"name"`
		Timestamp     json.RawMessage `json:"timestamp"`
		Severity      json.RawMessage `json:"severity"`
		Tag           json.RawMessage `json:"tag"`
		Type          json.RawMessage `json:"type"`
		Tool          json.RawMessage `json:"tool"`
		Attacker      json.RawMessage `json:"attacker"`
		Victim        json.RawMessage `json:"victim"`
		SrcIP         json.RawMessage `json:"src_ip"`
		SrcPort       json.RawMessage `json:"src_port"`
		DestIP        json.RawMessage `json:"dest_ip"`
		DestPort      json.RawMessage `json:"dest_port"`
		Proto         json.RawMessage `json:"proto"`
		AppProto      json.RawMessage `json:"app_proto"`
		Result        json.RawMessage `json:"result"`
		Phase         json.RawMessage `json:"phase"`
		Direction     json.RawMessage `json:"direction"`
		XFF           json.RawMessage `json:"xff"`
		Msg           json.RawMessage `json:"msg"`
		AttackerAsset json.RawMessage `json:"attacker_asset"`
		VictimAsset   json.RawMessage `json:"victim_asset"`
		GeoAttacker   json.RawMessage `json:"geo_attacker"`
		GeoVictim     json.RawMessage `json:"geo_victim"`
		AppBrief      json.RawMessage `json:"appbrief"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return model.Alert{}, fmt.Errorf("decode tanswer alarm: %w", err)
	}

	docID := scalarText(item.DocID)
	externalID := strings.TrimSpace(docID)
	if externalID == "" {
		externalID = connector.HashRaw(raw)
	}
	name := strings.TrimSpace(scalarText(item.Name))
	srcIP := strings.TrimSpace(scalarText(item.SrcIP))
	destIP := strings.TrimSpace(scalarText(item.DestIP))
	severity, original := severityOf(item.Severity)
	eventTime, parsed := parseAlarmTime(item.Timestamp)
	originalTime := ""
	if parsed {
		originalTime = strings.TrimSpace(scalarText(item.Timestamp))
	}

	collector := connector.NewObservableCollector(raw)
	collector.Add("ip", 2, srcIP, "/src_ip")
	collector.Add("ip", 2, destIP, "/dest_ip")

	resourceID, resourceName := assetValue(item.VictimAsset)
	if resourceID == "" {
		resourceID, resourceName = assetValue(item.AttackerAsset)
	}

	title := name
	if title == "" {
		title = "TAnswer alert"
	}

	unmapped := map[string]any{"tanswer": map[string]any{
		"tag":          scalarText(item.Tag),
		"type":         scalarText(item.Type),
		"tool":         scalarText(item.Tool),
		"phase":        scalarText(item.Phase),
		"direction":    scalarText(item.Direction),
		"proto":        scalarText(item.Proto),
		"app_proto":    scalarText(item.AppProto),
		"src_port":     scalarText(item.SrcPort),
		"dest_port":    scalarText(item.DestPort),
		"xff":          scalarText(item.XFF),
		"msg":          scalarText(item.Msg),
		"attacker":     scalarText(item.Attacker),
		"victim":       scalarText(item.Victim),
		"geo_attacker": rawOrText(item.GeoAttacker),
		"geo_victim":   rawOrText(item.GeoVictim),
		"app_brief":    rawOrText(item.AppBrief),
	}}

	return model.Alert{
		ExternalID:       externalID,
		Title:            title,
		Description:      strings.TrimSpace(scalarText(item.Msg)),
		Severity:         severity,
		OriginalSeverity: original,
		VendorStatus:     strings.TrimSpace(scalarText(item.Result)),
		EventTime:        eventTime,
		OriginalTime:     originalTime,
		Product:          "TAnswer (全悉)",
		AlertType:        connector.FirstNonEmpty(strings.TrimSpace(scalarText(item.Tag)), strings.TrimSpace(scalarText(item.Type))),
		Resource:         connector.NamedResource(resourceID, "host", resourceName, resourceID),
		SourceIP:         srcIP,
		DestinationIP:    destIP,
		Observables:      collector.Values(),
		Unmapped:         unmapped,
		Raw:              append(json.RawMessage(nil), raw...),
	}, nil
}

// severityOf maps both the numeric (1=critical .. 4=low) and the named form.
// The precedence and numbering follow the CLI's documented --severity values.
func severityOf(raw json.RawMessage) (model.Severity, string) {
	text := strings.TrimSpace(scalarText(raw))
	if text == "" {
		return model.SeverityUnknown, ""
	}
	switch strings.ToLower(text) {
	case "1", "critical":
		return model.SeverityCritical, text
	case "2", "high":
		return model.SeverityHigh, text
	case "3", "medium":
		return model.SeverityMedium, text
	case "4", "low":
		return model.SeverityLow, text
	default:
		return model.SeverityUnknown, text
	}
}

// parseAlarmTime accepts epoch milliseconds, epoch seconds or RFC3339.
func parseAlarmTime(raw json.RawMessage) (time.Time, bool) {
	text := strings.TrimSpace(scalarText(raw))
	if text == "" {
		return time.Time{}, false
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
			return time.Time{}, false
		}
		if len(text) >= 13 {
			return time.UnixMilli(n).UTC(), true
		}
		return time.Unix(n, 0).UTC(), true
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, text); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// assetValue accepts either a scalar identifier or an object with name/ip.
func assetValue(raw json.RawMessage) (string, string) {
	if len(raw) == 0 {
		return "", ""
	}
	var object struct {
		Name string `json:"name"`
		IP   string `json:"ip"`
		ID   string `json:"id"`
	}
	if json.Unmarshal(raw, &object) == nil && (object.Name != "" || object.IP != "" || object.ID != "") {
		return connector.FirstNonEmpty(object.ID, object.IP, object.Name), object.Name
	}
	text := strings.TrimSpace(scalarText(raw))
	return text, text
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
