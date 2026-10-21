package aliyun

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/ocsf"
	sas "github.com/alibabacloud-go/sas-20181203/v3/client"
)

// Normalize maps one Alibaba Cloud SAS alert payload onto the vendor-neutral
// model. OCSF assembly happens in the ingest engine so that all providers share
// exactly one schema serializer.
func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	var a sas.DescribeSuspEventsResponseBodySuspEvents
	if err := json.Unmarshal(raw, &a); err != nil {
		return model.Alert{}, fmt.Errorf("decode aliyun alert: %w", err)
	}

	externalID := ""
	if a.Id != nil {
		externalID = strconv.FormatInt(*a.Id, 10)
	}
	if externalID == "" {
		externalID = connector.FirstNonEmpty(connector.Str(a.AlarmUniqueInfo), connector.Str(a.UniqueInfo))
	}
	if externalID == "" {
		return model.Alert{}, fmt.Errorf("aliyun source record has no native ID")
	}

	firstSeen, lastSeen := alertTimes(&a)
	eventTime := firstSeen

	resource := model.Resource{
		ID:   connector.FirstNonEmpty(connector.Str(a.InstanceId), connector.Str(a.Uuid)),
		Name: connector.FirstNonEmpty(connector.Str(a.InstanceName), connector.Str(a.ContainerImageName), connector.Str(a.K8sClusterName), connector.Str(a.Uuid)),
		Type: resourceType(&a),
	}
	if connector.Str(a.ContainerId) != "" {
		resource.ID = connector.Str(a.ContainerId)
		resource.Name = connector.FirstNonEmpty(connector.Str(a.K8sPodName), connector.Str(a.ContainerImageName), resource.ID)
	} else if resource.Type == "kubernetes_cluster" {
		resource.ID = connector.Str(a.K8sClusterId)
		resource.Name = connector.FirstNonEmpty(connector.Str(a.K8sClusterName), resource.ID)
	}

	sourceIP := extractSourceIP(a.Details)
	alert := model.Alert{
		ExternalID:       externalID,
		FindingKind:      model.FindingDetection,
		Title:            connector.FirstNonEmpty(connector.Str(a.Name), connector.Str(a.AlarmEventNameDisplay), connector.Str(a.AlarmEventName), "Alibaba Cloud security alert"),
		Description:      connector.Str(a.Desc),
		Severity:         mapSeverity(connector.Str(a.Level)),
		OriginalSeverity: connector.Str(a.Level),
		VendorStatus:     connector.SourceScalar(raw, "/EventStatus"),
		EventTime:        eventTime,
		FirstSeenAt:      firstSeen,
		LastSeenAt:       lastSeen,
		OriginalTime:     connector.Str(a.OccurrenceTime),
		Product:          "SAS",
		AlertType:        connector.FirstNonEmpty(connector.Str(a.AlarmEventTypeDisplay), connector.Str(a.AlarmEventType), connector.Str(a.EventSubType)),
		Resource:         resource,
		SourceIP:         sourceIP,
		Tactic:           tactic(&a),
		CloudAccountUID:  cloudAccountUID(&a),
		Raw:              append(json.RawMessage(nil), raw...),
	}

	alert.Observables = observables(&a, alert)
	for _, resource := range []model.Resource{
		resource,
		{ID: connector.FirstNonEmpty(connector.Str(a.InstanceId), connector.Str(a.Uuid)), Name: connector.Str(a.InstanceName), Type: "host"},
		{ID: connector.Str(a.ContainerId), Name: connector.Str(a.ContainerImageName), Type: "container"},
		{ID: connector.Str(a.K8sClusterId), Name: connector.Str(a.K8sClusterName), Type: "kubernetes_cluster"},
	} {
		if resource.ID == "" {
			continue
		}
		found := false
		for _, existing := range alert.Resources {
			if existing.ID == resource.ID {
				found = true
				break
			}
		}
		if !found {
			alert.Resources = append(alert.Resources, resource)
		}
	}
	alert.Evidences = evidences(&a)
	if extra := unmapped(&a); len(extra) > 0 {
		alert.Unmapped = map[string]any{"aliyun_sas": extra}
	}
	return alert, nil
}

func alertTimes(a *sas.DescribeSuspEventsResponseBodySuspEvents) (time.Time, time.Time) {
	first := time.Time{}
	if a.OccurrenceTimeStamp != nil && *a.OccurrenceTimeStamp > 0 {
		first = time.UnixMilli(*a.OccurrenceTimeStamp).UTC()
	} else if t, ok := connector.ParseVendorTime(connector.Str(a.OccurrenceTime)); ok {
		first = t
	}

	last := time.Time{}
	if a.LastTimeStamp != nil && *a.LastTimeStamp > 0 {
		last = time.UnixMilli(*a.LastTimeStamp).UTC()
	} else if t, ok := connector.ParseVendorTime(connector.Str(a.LastTime)); ok {
		last = t
	}
	return first, last
}

func mapSeverity(level string) model.Severity {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "serious", "critical", "severe", "urgent":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "suspicious", "medium", "moderate":
		return model.SeverityMedium
	case "remind", "low":
		return model.SeverityLow
	case "info", "informational":
		return model.SeverityInformational
	default:
		return model.SeverityUnknown
	}
}

func cloudAccountUID(a *sas.DescribeSuspEventsResponseBodySuspEvents) string {
	if a.SourceAliUid == nil || *a.SourceAliUid == 0 {
		return ""
	}
	return strconv.FormatInt(*a.SourceAliUid, 10)
}

func resourceType(a *sas.DescribeSuspEventsResponseBodySuspEvents) string {
	switch {
	case connector.Str(a.ContainerId) != "":
		return "container"
	case connector.Str(a.K8sClusterId) != "":
		return "kubernetes_cluster"
	case connector.Str(a.InstanceId) != "" || connector.Str(a.Uuid) != "":
		return "host"
	default:
		return ""
	}
}

func tactic(a *sas.DescribeSuspEventsResponseBodySuspEvents) string {
	ids := make([]string, 0, len(a.TacticItems))
	for _, item := range a.TacticItems {
		if item == nil {
			continue
		}
		if id := connector.Str(item.TacticId); id != "" {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, ",")
}

func observables(a *sas.DescribeSuspEventsResponseBodySuspEvents, alert model.Alert) []model.Observable {
	out := make([]model.Observable, 0, 5)
	add := func(name string, typeID int, value string) {
		if value != "" {
			out = append(out, model.Observable{Name: name, TypeID: typeID, Value: value})
		}
	}
	add("src_endpoint.ip", ocsf.ObservableIPAddress, alert.SourceIP)
	add("dst_endpoint.ip", ocsf.ObservableIPAddress, alert.DestinationIP)
	add("resources.uid", ocsf.ObservableResourceUID, alert.Resource.ID)
	add("resources.uid", ocsf.ObservableResourceUID, connector.Str(a.Uuid))
	add("resources.uid", ocsf.ObservableResourceUID, connector.Str(a.ContainerId))
	add("resources.uid", ocsf.ObservableResourceUID, connector.Str(a.K8sClusterId))
	add("resources.uid", ocsf.ObservableResourceUID, connector.Str(a.K8sNodeId))
	add("resource.public_ip", ocsf.ObservableIPAddress, connector.Str(a.InternetIp))
	add("resource.private_ip", ocsf.ObservableIPAddress, connector.Str(a.IntranetIp))
	return out
}

func evidences(a *sas.DescribeSuspEventsResponseBodySuspEvents) []model.Evidence {
	out := make([]model.Evidence, 0, len(a.Details))
	for _, d := range a.Details {
		if d == nil {
			continue
		}
		data := map[string]any{}
		if v := connector.FirstNonEmpty(connector.Str(d.NameDisplay), connector.Str(d.Type)); v != "" {
			data["name"] = v
		}
		if v := connector.Str(d.Value); v != "" {
			data["value"] = v
		}
		if v := connector.Str(d.ValueDisplay); v != "" && v != connector.Str(d.Value) {
			data["display"] = v
		}
		if len(data) == 0 {
			continue
		}
		out = append(out, model.Evidence{Type: "aliyun.sas.detail", Data: data})
	}
	return out
}

// Only exact source-address labels are accepted; free-text descriptions do not
// establish traffic direction. Asset public/private IPs stay neutral observables.
func extractSourceIP(details []*sas.DescribeSuspEventsResponseBodySuspEventsDetails) string {
	for _, d := range details {
		if d == nil {
			continue
		}
		isSource := func(label string) bool {
			switch strings.ToLower(strings.TrimSpace(label)) {
			case "source ip", "src_ip", "src ip", "source_ip", "源ip", "来源ip", "攻击源ip":
				return true
			}
			return false
		}
		if !isSource(connector.Str(d.NameDisplay)) && !isSource(connector.Str(d.Type)) {
			continue
		}
		value := connector.FirstNonEmpty(connector.Str(d.ValueDisplay), connector.Str(d.Value))
		if net.ParseIP(value) == nil {
			continue
		}
		return value
	}
	return ""
}

func unmapped(a *sas.DescribeSuspEventsResponseBodySuspEvents) map[string]any {
	extra := map[string]any{}
	set := func(key, value string) {
		if value != "" {
			extra[key] = value
		}
	}
	set("uuid", connector.Str(a.Uuid))
	set("alarm_unique_info", connector.Str(a.AlarmUniqueInfo))
	set("unique_info", connector.Str(a.UniqueInfo))
	set("security_event_ids", connector.Str(a.SecurityEventIds))
	set("stages", connector.Str(a.Stages))
	set("data_source", connector.Str(a.DataSource))
	set("alarm_event_name", connector.Str(a.AlarmEventName))
	set("alarm_event_type", connector.Str(a.AlarmEventType))
	set("event_sub_type", connector.Str(a.EventSubType))
	set("cluster_id", connector.FirstNonEmpty(connector.Str(a.K8sClusterId), connector.Str(a.ClusterId)))
	set("cluster_name", connector.Str(a.K8sClusterName))
	set("namespace", connector.Str(a.K8sNamespace))
	set("pod_name", connector.Str(a.K8sPodName))
	set("container_id", connector.Str(a.ContainerId))
	set("container_image", connector.Str(a.ContainerImageName))
	if a.EventStatus != nil {
		extra["event_status"] = *a.EventStatus
	}
	if len(a.TacticItems) > 0 {
		tactics := make([]map[string]string, 0, len(a.TacticItems))
		for _, item := range a.TacticItems {
			if item == nil {
				continue
			}
			tactics = append(tactics, map[string]string{
				"id":   connector.Str(item.TacticId),
				"name": connector.Str(item.TacticDisplayName),
			})
		}
		extra["tactics"] = tactics
	}
	if len(a.MarkList) > 0 {
		marks := make([]string, 0, len(a.MarkList))
		for _, m := range a.MarkList {
			if m != nil && *m != "" {
				marks = append(marks, *m)
			}
		}
		extra["marks"] = marks
	}
	return extra
}
