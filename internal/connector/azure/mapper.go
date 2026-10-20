package azure

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/ocsf"
)

func normalizeAlert(raw json.RawMessage) (model.Alert, error) {
	var a armsecurity.Alert
	if err := json.Unmarshal(raw, &a); err != nil {
		return model.Alert{}, fmt.Errorf("decode Azure alert: %w", err)
	}
	p := a.Properties
	if p == nil {
		p = &armsecurity.AlertProperties{}
	}
	externalID := firstNonEmpty(connector.Str(p.SystemAlertID), connector.Str(a.Name), connector.Str(a.ID), connector.HashRaw(raw))
	title := firstNonEmpty(connector.Str(p.AlertDisplayName), connector.Str(p.AlertType), "Microsoft Defender alert")
	eventTime := firstTime(p.TimeGeneratedUTC, p.StartTimeUTC, p.EndTimeUTC, p.ProcessingEndTimeUTC)
	firstSeen := firstTime(p.StartTimeUTC, p.TimeGeneratedUTC, systemCreatedAt(a.SystemData))
	lastSeen := firstTime(p.EndTimeUTC, p.ProcessingEndTimeUTC, p.TimeGeneratedUTC)
	resourceID := azureResourceID(p)
	resourceName := firstNonEmpty(connector.Str(p.CompromisedEntity), nameFromResourceID(resourceID))
	resourceType := resourceTypeFromID(resourceID)
	if resourceType == "" {
		resourceType = "azure_entity"
	}
	if resourceID == "" {
		resourceID = resourceName
	}
	hostname, sourceIP, destinationIP, fileName, fileHash := entities(p.Entities)
	subscriptionID := firstNonEmpty(subscriptionFromID(connector.Str(a.ID)), subscriptionFromID(resourceID), extendedProperty(p, "subscriptionId", "subscription_id"))
	region := firstNonEmpty(locationFromID(connector.Str(a.ID)), locationFromID(resourceID))
	tactic := ""
	if p.Intent != nil && *p.Intent != armsecurity.IntentUnknown {
		tactic = string(*p.Intent)
	}
	technique := ""
	if len(p.Techniques) > 0 {
		technique = connector.Str(p.Techniques[0])
	}
	if technique == "" && len(p.SubTechniques) > 0 {
		technique = connector.Str(p.SubTechniques[0])
	}

	alert := model.Alert{
		ExternalID:       externalID,
		Title:            title,
		Description:      connector.Str(p.Description),
		Severity:         mapSeverity(p.Severity),
		OriginalSeverity: severityString(p.Severity),
		VendorStatus:     strings.ToLower(statusString(p.Status)),
		EventTime:        eventTime,
		FirstSeenAt:      firstSeen,
		LastSeenAt:       lastSeen,
		OriginalTime:     formatTime(p.TimeGeneratedUTC),
		Product:          firstNonEmpty(connector.Str(p.ProductName), connector.Str(p.VendorName), "Microsoft Defender for Cloud"),
		AlertType:        connector.Str(p.AlertType),
		Region:           region,
		CloudAccountUID:  subscriptionID,
		Resource: model.Resource{
			ID:   resourceID,
			Name: resourceName,
			Type: resourceType,
		},
		SourceIP:      sourceIP,
		DestinationIP: destinationIP,
		Actor:         firstNonEmpty(hostname, resourceName),
		Tactic:        tactic,
		Technique:     technique,
		Raw:           append(json.RawMessage(nil), raw...),
	}
	alert.Observables = observables(alert, fileName, fileHash)
	if evidence := evidence(p); evidence != nil {
		alert.Evidences = []model.Evidence{*evidence}
	}
	alert.Unmapped = unmapped(p)
	return alert, nil
}

func mapSeverity(severity *armsecurity.AlertSeverity) model.Severity {
	if severity == nil {
		return model.SeverityUnknown
	}
	switch strings.ToLower(string(*severity)) {
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	case "informational":
		return model.SeverityInformational
	default:
		return model.SeverityUnknown
	}
}

func severityString(severity *armsecurity.AlertSeverity) string {
	if severity == nil {
		return ""
	}
	return string(*severity)
}

func statusString(status *armsecurity.AlertStatus) string {
	if status == nil {
		return ""
	}
	return string(*status)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstTime(values ...*time.Time) time.Time {
	for _, v := range values {
		if v != nil && !v.IsZero() {
			return v.UTC()
		}
	}
	return time.Time{}
}

func formatTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func systemCreatedAt(data *armsecurity.SystemData) *time.Time {
	if data == nil {
		return nil
	}
	return data.CreatedAt
}

func azureResourceID(p *armsecurity.AlertProperties) string {
	for _, identifier := range p.ResourceIdentifiers {
		if resource, ok := identifier.(*armsecurity.AzureResourceIdentifier); ok {
			if id := connector.Str(resource.AzureResourceID); id != "" {
				return id
			}
		}
	}
	return ""
}

func subscriptionFromID(id string) string {
	return segmentAfter(id, "/subscriptions/")
}

func locationFromID(id string) string {
	return segmentAfter(id, "/locations/")
}

func segmentAfter(value, marker string) string {
	lower := strings.ToLower(value)
	index := strings.Index(lower, strings.ToLower(marker))
	if index < 0 {
		return ""
	}
	rest := value[index+len(marker):]
	if end := strings.Index(rest, "/"); end >= 0 {
		return rest[:end]
	}
	return rest
}

func nameFromResourceID(id string) string {
	id = strings.TrimRight(id, "/")
	if index := strings.LastIndex(id, "/"); index >= 0 {
		return id[index+1:]
	}
	return id
}

func resourceTypeFromID(id string) string {
	lower := strings.ToLower(id)
	index := strings.LastIndex(lower, "/providers/")
	if index < 0 {
		return ""
	}
	parts := strings.Split(strings.Trim(id[index+len("/providers/"):], "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

func extendedProperty(p *armsecurity.AlertProperties, keys ...string) string {
	for _, key := range keys {
		for actual, value := range p.ExtendedProperties {
			if strings.EqualFold(actual, key) && value != nil {
				return *value
			}
		}
	}
	return ""
}

func entities(items []*armsecurity.AlertEntity) (hostname, sourceIP, destinationIP, fileName, fileHash string) {
	for _, item := range items {
		if item == nil {
			continue
		}
		entityType := strings.ToLower(connector.Str(item.Type))
		for key, raw := range item.AdditionalProperties {
			value, ok := raw.(string)
			if !ok || strings.TrimSpace(value) == "" {
				continue
			}
			switch strings.ToLower(key) {
			case "hostname", "devicename", "dnsname":
				if hostname == "" {
					hostname = value
				}
			case "address", "ipaddress":
				if strings.Contains(entityType, "ip") && sourceIP == "" {
					sourceIP = value
				}
			case "sourceaddress", "sourceip", "source_ip":
				if sourceIP == "" {
					sourceIP = value
				}
			case "destinationaddress", "destinationip", "destination_ip":
				if destinationIP == "" {
					destinationIP = value
				}
			case "filepath", "filename":
				if fileName == "" {
					fileName = value
				}
			case "sha256":
				if fileHash == "" {
					fileHash = value
				}
			}
		}
	}
	return hostname, sourceIP, destinationIP, fileName, fileHash
}

func observables(alert model.Alert, fileName, fileHash string) []model.Observable {
	out := make([]model.Observable, 0, 7)
	seen := map[string]bool{}
	add := func(name string, typeID int, value string) {
		if value == "" || seen[name+"|"+value] {
			return
		}
		seen[name+"|"+value] = true
		out = append(out, model.Observable{Name: name, TypeID: typeID, Value: value})
	}
	add("resources.uid", ocsf.ObservableResourceUID, alert.Resource.ID)
	add("src_endpoint.ip", ocsf.ObservableIPAddress, alert.SourceIP)
	add("dst_endpoint.ip", ocsf.ObservableIPAddress, alert.DestinationIP)
	add("cloud.account.uid", ocsf.ObservableResourceUID, alert.CloudAccountUID)
	add("hostname", ocsf.ObservableHostname, alert.Actor)
	add("file.name", ocsf.ObservableFileName, fileName)
	add("file.hash.sha256", ocsf.ObservableFileHash, fileHash)
	return out
}

func evidence(p *armsecurity.AlertProperties) *model.Evidence {
	data := map[string]any{}
	if len(p.Entities) > 0 {
		data["entities"] = p.Entities
	}
	if len(p.ResourceIdentifiers) > 0 {
		data["resource_identifiers"] = p.ResourceIdentifiers
	}
	if len(p.ExtendedProperties) > 0 {
		data["extended_properties"] = p.ExtendedProperties
	}
	if p.SupportingEvidence != nil {
		data["supporting_evidence"] = p.SupportingEvidence
	}
	if len(p.RemediationSteps) > 0 {
		data["remediation_steps"] = p.RemediationSteps
	}
	if p.AlertURI != nil {
		data["alert_uri"] = *p.AlertURI
	}
	if p.Intent != nil {
		data["intent"] = string(*p.Intent)
	}
	if len(p.Techniques) > 0 {
		data["techniques"] = p.Techniques
	}
	if len(data) == 0 {
		return nil
	}
	return &model.Evidence{Type: "azure.defender", Data: data}
}

func unmapped(p *armsecurity.AlertProperties) map[string]any {
	extra := map[string]any{}
	set := func(key string, value *string) {
		if value != nil && strings.TrimSpace(*value) != "" {
			extra[key] = *value
		}
	}
	set("correlation_key", p.CorrelationKey)
	set("alert_uri", p.AlertURI)
	set("product_component", p.ProductComponentName)
	set("vendor", p.VendorName)
	set("version", p.Version)
	if p.Intent != nil && *p.Intent != armsecurity.IntentUnknown {
		extra["intent"] = string(*p.Intent)
	}
	if p.IsIncident != nil {
		extra["is_incident"] = *p.IsIncident
	}
	if len(p.ResourceIdentifiers) > 0 {
		extra["resource_identifiers"] = p.ResourceIdentifiers
	}
	if len(p.ExtendedProperties) > 0 {
		extra["extended_properties"] = p.ExtendedProperties
	}
	if len(p.RemediationSteps) > 0 {
		extra["remediation_steps"] = p.RemediationSteps
	}
	if len(p.Techniques) > 0 {
		extra["techniques"] = p.Techniques
	}
	if len(p.SubTechniques) > 0 {
		extra["sub_techniques"] = p.SubTechniques
	}
	return extra
}
