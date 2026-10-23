package cef

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/pushwire"
)

type envelope struct {
	Format  string            `json:"format"`
	Syslog  *pushwire.Message `json:"syslog"`
	CEF     *pushwire.CEF     `json:"cef"`
	Message string            `json:"message"`
}

func normalize(raw json.RawMessage, defaultDevice string) (model.Alert, error) {
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return model.Alert{}, fmt.Errorf("decode CEF envelope: %w", err)
	}
	if env.CEF == nil {
		return model.Alert{}, fmt.Errorf("CEF envelope does not contain a decoded record")
	}
	cef := env.CEF
	ext := cef.Extension
	if ext == nil {
		ext = map[string]string{}
	}

	eventTime, originalTime := extensionTime(ext, "rt", "deviceReceiptTime", "start", "end", "art")
	if eventTime.IsZero() {
		eventTime, originalTime = syslogTime(env.Syslog)
	}

	title := strings.TrimSpace(cef.Name)
	if title == "" {
		title = connector.FirstNonEmpty(defaultDevice, cef.DeviceProduct, "CEF event")
	}
	description := connector.FirstNonEmpty(ext["msg"], ext["message"], ext["reason"])
	severity, originalSeverity := severityOf(cef.Severity)

	collector := connector.NewObservableCollector(raw)
	collector.Add("src_endpoint.ip", 2, strings.TrimSpace(ext["src"]), "/cef/extension/src")
	collector.Add("dst_endpoint.ip", 2, strings.TrimSpace(ext["dst"]), "/cef/extension/dst")
	collector.Add("hostname", 1, strings.TrimSpace(ext["shost"]), "/cef/extension/shost")
	collector.Add("hostname", 1, strings.TrimSpace(ext["dhost"]), "/cef/extension/dhost")
	collector.Add("user.name", 4, strings.TrimSpace(ext["suser"]), "/cef/extension/suser")
	collector.Add("user.name", 4, strings.TrimSpace(ext["duser"]), "/cef/extension/duser")
	collector.Add("url", 6, strings.TrimSpace(connector.FirstNonEmpty(ext["requestURL"], ext["request"])), "/cef/extension/requestURL", "/cef/extension/request")
	collector.Add("file.hash", 8, strings.TrimSpace(connector.FirstNonEmpty(ext["fileHash"], ext["fhash"])), "/cef/extension/fileHash", "/cef/extension/fhash")

	resourceID := connector.FirstNonEmpty(strings.TrimSpace(ext["dvchost"]), strings.TrimSpace(ext["dhost"]), strings.TrimSpace(ext["shost"]))
	resourceType := "host"
	if strings.TrimSpace(ext["dvchost"]) == "" && resourceID != "" {
		resourceType = "domain"
	}
	resource := connector.NamedResource(resourceID, resourceType, "", resourceID)

	externalID := connector.FirstNonEmpty(
		strings.TrimSpace(ext["externalId"]),
		strings.TrimSpace(ext["deviceExternalId"]),
		strings.TrimSpace(ext["eventId"]),
	)
	if externalID == "" {
		externalID = connector.HashRaw(raw)
	}

	alert := model.Alert{
		ExternalID:       externalID,
		Title:            title,
		Description:      description,
		Severity:         severity,
		OriginalSeverity: originalSeverity,
		VendorStatus:     connector.FirstNonEmpty(ext["outcome"], ext["disposition"], ext["act"]),
		EventTime:        eventTime,
		OriginalTime:     originalTime,
		Product:          connector.FirstNonEmpty(cef.DeviceProduct, defaultDevice),
		AlertType:        strings.TrimSpace(cef.Name),
		RuleID:           strings.TrimSpace(cef.SignatureID),
		Resource:         resource,
		SourceIP:         strings.TrimSpace(ext["src"]),
		DestinationIP:    strings.TrimSpace(ext["dst"]),
		Actor:            strings.TrimSpace(ext["suser"]),
		Observables:      collector.Values(),
		Unmapped: map[string]any{"cef": map[string]any{
			"version":        cef.Version,
			"device_vendor":  cef.DeviceVendor,
			"device_product": cef.DeviceProduct,
			"device_version": cef.DeviceVersion,
			"signature_id":   cef.SignatureID,
			"extension":      ext,
		}},
		Raw: append(json.RawMessage(nil), raw...),
	}
	if env.Syslog != nil {
		alert.Unmapped["syslog"] = map[string]any{
			"hostname": env.Syslog.Hostname,
			"app_name": env.Syslog.AppName,
			"facility": env.Syslog.Facility,
			"severity": env.Syslog.Severity,
		}
	}
	return alert, nil
}

// extensionTime reads the first present time field. CEF time values are epoch
// milliseconds, but some devices emit seconds or a vendor-formatted string.
func extensionTime(ext map[string]string, keys ...string) (time.Time, string) {
	for _, key := range keys {
		value := strings.TrimSpace(ext[key])
		if value == "" {
			continue
		}
		if t, ok := parseEpoch(value); ok {
			return t, value
		}
		if t, ok := connector.ParseVendorTime(value); ok {
			return t, value
		}
	}
	return time.Time{}, ""
}

func parseEpoch(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return time.Time{}, false
		}
	}
	switch len(value) {
	case 13:
		ms, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		return time.UnixMilli(ms).UTC(), true
	case 10:
		sec, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(sec, 0).UTC(), true
	default:
		return time.Time{}, false
	}
}

// syslogTime only trusts RFC 5424 timestamps. RFC 3164 carries no year or zone,
// so it stays unknown instead of being completed with a guessed year.
func syslogTime(msg *pushwire.Message) (time.Time, string) {
	if msg == nil || msg.Version == 0 || strings.TrimSpace(msg.Timestamp) == "" {
		return time.Time{}, ""
	}
	if t, err := time.Parse(time.RFC3339Nano, msg.Timestamp); err == nil {
		return t.UTC(), msg.Timestamp
	}
	return time.Time{}, msg.Timestamp
}

func severityOf(value string) (model.Severity, string) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return model.SeverityUnknown, ""
	}
	if n, err := strconv.Atoi(raw); err == nil {
		switch {
		case n <= 0:
			return model.SeverityUnknown, raw
		case n <= 3:
			return model.SeverityLow, raw
		case n <= 6:
			return model.SeverityMedium, raw
		case n <= 8:
			return model.SeverityHigh, raw
		default:
			return model.SeverityCritical, raw
		}
	}
	switch strings.ToLower(raw) {
	case "unknown":
		return model.SeverityUnknown, raw
	case "info", "informational":
		return model.SeverityInformational, raw
	case "low":
		return model.SeverityLow, raw
	case "medium", "moderate":
		return model.SeverityMedium, raw
	case "high":
		return model.SeverityHigh, raw
	case "very-high", "very high", "critical":
		return model.SeverityCritical, raw
	default:
		return model.SeverityUnknown, raw
	}
}
