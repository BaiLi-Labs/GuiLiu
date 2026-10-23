package defender

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

type evidence struct {
	ODataType   string `json:"@odata.type"`
	IPAddress   string `json:"ipAddress"`
	URL         string `json:"url"`
	DeviceDNS   string `json:"deviceDnsName"`
	AccountName string `json:"accountName"`
	UserAccount struct {
		AccountName string `json:"accountName"`
		DomainName  string `json:"domainName"`
	} `json:"userAccount"`
	FileDetails struct {
		FileName string `json:"fileName"`
		FilePath string `json:"filePath"`
		FileHash struct {
			HashType  string `json:"hashType"`
			HashValue string `json:"hashValue"`
		} `json:"fileHash"`
	} `json:"fileDetails"`
	ProcessCommandLine string `json:"processCommandLine"`
}

func normalize(raw json.RawMessage) (model.Alert, error) {
	var item struct {
		ID                 string          `json:"id"`
		ProviderAlertID    string          `json:"providerAlertId"`
		IncidentID         string          `json:"incidentId"`
		Status             string          `json:"status"`
		Severity           string          `json:"severity"`
		Determination      string          `json:"determination"`
		Classification     string          `json:"classification"`
		Title              string          `json:"title"`
		Description        string          `json:"description"`
		Category           string          `json:"category"`
		AlertWebURL        string          `json:"alertWebUrl"`
		CreatedDateTime    string          `json:"createdDateTime"`
		FirstActivityTime  string          `json:"firstActivityDateTime"`
		LastActivityTime   string          `json:"lastActivityDateTime"`
		LastUpdateDateTime string          `json:"lastUpdateDateTime"`
		ActorDisplayName   string          `json:"actorDisplayName"`
		ThreatDisplayName  string          `json:"threatDisplayName"`
		ThreatFamilyName   string          `json:"threatFamilyName"`
		ServiceSource      string          `json:"serviceSource"`
		DetectionSource    string          `json:"detectionSource"`
		ProductName        string          `json:"productName"`
		MITRETechniques    []string        `json:"mitreTechniques"`
		Evidence           []evidence      `json:"evidence"`
		AdditionalData     json.RawMessage `json:"additionalData"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		return model.Alert{}, fmt.Errorf("decode defender alert: %w", err)
	}

	externalID := connector.FirstNonEmpty(strings.TrimSpace(item.ID), strings.TrimSpace(item.ProviderAlertID))
	if externalID == "" {
		externalID = connector.HashRaw(raw)
	}

	collector := connector.NewObservableCollector(raw)
	var resourceHost, resourceID string
	evidenceTypes := make([]string, 0, len(item.Evidence))
	for i, ev := range item.Evidence {
		evidenceTypes = append(evidenceTypes, ev.ODataType)
		prefix := fmt.Sprintf("/evidence/%d", i)
		if account := connector.FirstNonEmpty(ev.UserAccount.AccountName, ev.AccountName); account != "" {
			collector.Add("user.name", 4, account, prefix+"/userAccount/accountName", prefix+"/accountName")
		}
		collector.Add("ip", 2, strings.TrimSpace(ev.IPAddress), prefix+"/ipAddress")
		collector.Add("url", 6, strings.TrimSpace(ev.URL), prefix+"/url")
		collector.Add("hostname", 1, strings.TrimSpace(ev.DeviceDNS), prefix+"/deviceDnsName")
		collector.Add("file.hash", 8, strings.TrimSpace(ev.FileDetails.FileHash.HashValue), prefix+"/fileDetails/fileHash/hashValue")
		if resourceHost == "" && strings.TrimSpace(ev.DeviceDNS) != "" {
			resourceHost = strings.TrimSpace(ev.DeviceDNS)
		}
	}
	if resourceHost != "" {
		resourceID = resourceHost
	}
	resource := connector.NamedResource(resourceID, "host", resourceHost, resourceHost)

	eventTime := parseTime(item.LastActivityTime)
	if eventTime.IsZero() {
		eventTime = parseTime(item.CreatedDateTime)
	}
	firstSeen := parseTime(item.FirstActivityTime)

	return model.Alert{
		ExternalID:       externalID,
		Title:            connector.FirstNonEmpty(strings.TrimSpace(item.Title), "Defender alert"),
		Description:      strings.TrimSpace(item.Description),
		Severity:         severityOf(item.Severity),
		OriginalSeverity: strings.TrimSpace(item.Severity),
		VendorStatus:     strings.TrimSpace(item.Status),
		EventTime:        eventTime,
		FirstSeenAt:      firstSeen,
		SourceCreatedAt:  parseTime(item.CreatedDateTime),
		SourceUpdatedAt:  parseTime(item.LastUpdateDateTime),
		OriginalTime:     strings.TrimSpace(connector.FirstNonEmpty(item.LastActivityTime, item.CreatedDateTime)),
		Product:          strings.TrimSpace(item.ProductName),
		AlertType:        connector.FirstNonEmpty(strings.TrimSpace(item.Category), strings.TrimSpace(item.DetectionSource)),
		Resource:         resource,
		Actor:            strings.TrimSpace(item.ActorDisplayName),
		Technique:        strings.Join(item.MITRETechniques, ","),
		Observables:      collector.Values(),
		Unmapped: map[string]any{"defender": map[string]any{
			"provider_alert_id": item.ProviderAlertID,
			"incident_id":       item.IncidentID,
			"service_source":    item.ServiceSource,
			"detection_source":  item.DetectionSource,
			"determination":     item.Determination,
			"classification":    item.Classification,
			"threat_display":    item.ThreatDisplayName,
			"threat_family":     item.ThreatFamilyName,
			"alert_web_url":     item.AlertWebURL,
			"evidence_types":    evidenceTypes,
			"mitre_techniques":  item.MITRETechniques,
		}},
		Raw: append(json.RawMessage(nil), raw...),
	}, nil
}

func severityOf(value string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "informational", "info":
		return model.SeverityInformational
	case "low":
		return model.SeverityLow
	case "medium", "moderate":
		return model.SeverityMedium
	case "high":
		return model.SeverityHigh
	case "critical":
		return model.SeverityCritical
	default:
		return model.SeverityUnknown
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
