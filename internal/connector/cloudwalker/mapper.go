package cloudwalker

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// Event fields are shared across the generated event families; family-specific
// fields are kept in Unmapped rather than guessed into typed columns.
func normalize(raw json.RawMessage, eventType string) (model.Alert, error) {
	var item struct {
		ID          json.RawMessage `json:"id"`
		EventType   json.RawMessage `json:"event_type"`
		Level       json.RawMessage `json:"level"`
		State       json.RawMessage `json:"state"`
		CreatedAt   json.RawMessage `json:"created_at"`
		UpdatedAt   json.RawMessage `json:"updated_at"`
		HostID      json.RawMessage `json:"host_id"`
		HostIP      json.RawMessage `json:"host_ip"`
		HostName    json.RawMessage `json:"host_name"`
		SourceIP    json.RawMessage `json:"source_ip"`
		SrcIP       json.RawMessage `json:"src_ip"`
		DestIP      json.RawMessage `json:"dest_ip"`
		Name        json.RawMessage `json:"name"`
		FileName    json.RawMessage `json:"file_name"`
		FilePath    json.RawMessage `json:"file_path"`
		MalwareName json.RawMessage `json:"malware_name"`
		WebshellTyp json.RawMessage `json:"webshell_type"`
		Description json.RawMessage `json:"description"`
		Comment     json.RawMessage `json:"comment"`
		Port        json.RawMessage `json:"port"`
		UserName    json.RawMessage `json:"user_name"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return model.Alert{}, fmt.Errorf("decode cloudwalker event: %w", err)
	}

	externalID := strings.TrimSpace(scalarText(item.ID))
	if externalID == "" {
		externalID = connector.HashRaw(raw)
	}
	hostIP := strings.TrimSpace(scalarText(item.HostIP))
	hostName := strings.TrimSpace(scalarText(item.HostName))
	sourceIP := connector.FirstNonEmpty(strings.TrimSpace(scalarText(item.SourceIP)), strings.TrimSpace(scalarText(item.SrcIP)))
	eventTime := parseTime(item.CreatedAt)

	collector := connector.NewObservableCollector(raw)
	collector.Add("ip", 2, hostIP, "/host_ip")
	collector.Add("ip", 2, sourceIP, "/source_ip", "/src_ip")

	title := connector.FirstNonEmpty(
		strings.TrimSpace(scalarText(item.Name)),
		strings.TrimSpace(scalarText(item.FileName)),
		strings.TrimSpace(scalarText(item.MalwareName)),
		strings.TrimSpace(scalarText(item.Description)),
		eventType,
	)
	severity, original := severityOf(item.Level)

	return model.Alert{
		ExternalID:       externalID,
		Title:            title,
		Description:      connector.FirstNonEmpty(strings.TrimSpace(scalarText(item.Description)), strings.TrimSpace(scalarText(item.Comment))),
		Severity:         severity,
		OriginalSeverity: original,
		VendorStatus:     strings.TrimSpace(scalarText(item.State)),
		EventTime:        eventTime,
		SourceUpdatedAt:  parseTime(item.UpdatedAt),
		OriginalTime:     strings.TrimSpace(scalarText(item.CreatedAt)),
		Product:          "CloudWalker (牧云)",
		AlertType:        connector.FirstNonEmpty(strings.TrimSpace(scalarText(item.EventType)), eventType),
		Resource:         connector.NamedResource(connector.FirstNonEmpty(hostIP, hostName), "host", hostName, hostName),
		SourceIP:         sourceIP,
		DestinationIP:    strings.TrimSpace(scalarText(item.DestIP)),
		Actor:            strings.TrimSpace(scalarText(item.UserName)),
		Observables:      collector.Values(),
		Unmapped: map[string]any{"cloudwalker": map[string]any{
			"mapping_unverified": true,
			"contract_source":    "chaitin-cli products/cloudwalker (generated clients; reply decoded as map)",
			"event_type":         scalarText(item.EventType),
			"level":              scalarText(item.Level),
			"state":              scalarText(item.State),
			"host_id":            scalarText(item.HostID),
			"file_name":          scalarText(item.FileName),
			"file_path":          scalarText(item.FilePath),
			"malware_name":       scalarText(item.MalwareName),
			"webshell_type":      scalarText(item.WebshellTyp),
			"port":               scalarText(item.Port),
			"comment":            scalarText(item.Comment),
		}},
		Raw: append(json.RawMessage(nil), raw...),
	}, nil
}

// severityOf uses the ordering documented by the CLI help text:
// 1 low, 2 medium, 3 high, 4 severe.
func severityOf(raw json.RawMessage) (model.Severity, string) {
	text := strings.TrimSpace(scalarText(raw))
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
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		if len(text) >= 13 {
			return time.UnixMilli(n).UTC()
		}
		return time.Unix(n, 0).UTC()
	}
	return time.Time{}
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
