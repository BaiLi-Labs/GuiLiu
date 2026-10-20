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
		externalID = connector.HashRaw(raw)
	}

	firstSeen, lastSeen := alertTimes(&a)
	eventTime := lastSeen
	if eventTime.IsZero() {
		eventTime = firstSeen
	}

	resource := model.Resource{
		ID:   connector.FirstNonEmpty(connector.Str(a.InstanceId), connector.Str(a.Uuid)),
		Name: connector.FirstNonEmpty(connector.Str(a.InstanceName), connector.Str(a.ContainerImageName), connector.Str(a.K8sClusterName), connector.Str(a.Uuid)),
		Type: resourceType(&a),
	}

	sourceIP := extractSourceIP(a.Details)
	alert := model.Alert{
		ExternalID:       externalID,
		Title:            connector.FirstNonEmpty(connector.Str(a.Name), connector.Str(a.AlarmEventNameDisplay), connector.Str(a.AlarmEventName), "Alibaba Cloud security alert"),
		Description:      connector.Str(a.Desc),
		Severity:         mapSeverity(connector.Str(a.Level)),
		OriginalSeverity: connector.Str(a.Level),
		VendorStatus:     mapStatus(connector.Int32(a.EventStatus)),
		EventTime:        eventTime,
		FirstSeenAt:      firstSeen,
		LastSeenAt:       lastSeen,
		OriginalTime:     connector.Str(a.OccurrenceTime),
		Product:          "SAS",
		AlertType:        connector.FirstNonEmpty(connector.Str(a.AlarmEventTypeDisplay), connector.Str(a.AlarmEventType), connector.Str(a.EventSubType)),
		Resource:         resource,
		SourceIP:         sourceIP,
		DestinationIP:    connector.FirstNonEmpty(connector.Str(a.InternetIp), connector.Str(a.IntranetIp)),
		Tactic:           tactic(&a),
		CloudAccountUID:  cloudAccountUID(&a),
		Raw:              append(json.RawMessage(nil), raw...),
	}

	alert.Observables = observables(&a, alert)
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
	} else {
		last = first
	}
	if first.IsZero() {
		first = last
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

func mapStatus(status int32) string {
	switch status {
	case 0:
		return ""
	case 1:
		return "unhandled"
	case 2:
		return "fixed"
	case 3:
		return "ignored"
	case 4:
		return "deleted"
	case 5:
		return "handled"
	case 6:
		return "expired"
	default:
		return "status_" + strconv.FormatInt(int64(status), 10)
	}
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

// extractSourceIP looks for the attacker address among the free-form Details
// list, whose keys are localized human labels.
func extractSourceIP(details []*sas.DescribeSuspEventsResponseBodySuspEventsDetails) string {
	for _, d := range details {
		if d == nil {
			continue
		}
		label := strings.ToLower(connector.Str(d.NameDisplay) + " " + connector.Str(d.Type))
		if !containsAny(label, "source ip", "src_ip", "src ip", "remote ip", "源ip", "来源ip", "攻击源", "客户端ip", "对端ip") {
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

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
