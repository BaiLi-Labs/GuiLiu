package huawei

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/ocsf"
	secmastermodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/secmaster/v1/model"
)

func normalizeAlert(a *secmastermodel.ListAlertRsp, raw json.RawMessage) model.Alert {
	externalID := connector.FirstNonEmpty(connector.Str(a.Id), connector.Str(a.OriginId))
	if externalID == "" {
		externalID = ""
	}
	firstSeen, _ := connector.ParseVendorTime(connector.Str(a.FirstObservedTime))
	lastSeen, _ := connector.ParseVendorTime(connector.Str(a.LastObservedTime))
	created, _ := connector.ParseVendorTime(connector.Str(a.CreateTime))
	updated, _ := connector.ParseVendorTime(connector.Str(a.UpdateTime))
	eventTime := firstSeen

	alert := model.Alert{
		ExternalID:       externalID,
		FindingKind:      model.FindingDetection,
		SourceCreatedAt:  created,
		SourceUpdatedAt:  updated,
		Title:            connector.FirstNonEmpty(connector.Str(a.Title), alertTypeLabel(a), "Huawei Cloud security alert"),
		Description:      connector.Str(a.Description),
		Severity:         mapSeverity(a),
		OriginalSeverity: severityText(a),
		VendorStatus:     handleStatusText(a),
		EventTime:        eventTime,
		FirstSeenAt:      firstSeen,
		LastSeenAt:       lastSeen,
		OriginalTime:     connector.Str(a.FirstObservedTime),
		Product:          productName(a),
		AlertType:        alertTypeLabel(a),
		Region:           connector.Str(a.RegionId),
		CloudAccountUID:  connector.Str(a.DomainId),
		Actor:            connector.Str(a.Actor),
		Raw:              append(json.RawMessage(nil), raw...),
	}

	if a.NetworkList != nil {
		for i := range *a.NetworkList {
			n := &(*a.NetworkList)[i]
			if alert.SourceIP == "" {
				alert.SourceIP = connector.Str(n.SrcIp)
			}
			if alert.DestinationIP == "" {
				alert.DestinationIP = connector.Str(n.DestIp)
			}
		}
	}
	if a.ResourceList != nil {
		for _, r := range *a.ResourceList {
			alert.Resources = append(alert.Resources, model.Resource{
				ID: connector.Str(r.Id), Name: connector.Str(r.Name),
				Type: connector.FirstNonEmpty(strings.ToLower(connector.Str(r.Type)), "resource"),
			})
		}
	}
	if len(alert.Resources) > 0 {
		alert.Resource = alert.Resources[0]
	}

	if a.Count != nil && *a.Count >= 0 {
		n := int64(*a.Count)
		alert.OccurrenceCount = &n
		alert.OccurrenceScope = "huawei.secmaster.alert_count"
	}
	alert.Observables = observables(a, alert)
	if ev := evidence(a); ev != nil {
		alert.Evidences = []model.Evidence{*ev}
	}
	alert.Unmapped = map[string]any{"huawei_secmaster": unmapped(a)}
	return alert
}

func mapSeverity(a *secmastermodel.ListAlertRsp) model.Severity {
	switch strings.ToLower(severityText(a)) {
	case "tips":
		return model.SeverityInformational
	case "low":
		return model.SeverityLow
	case "medium":
		return model.SeverityMedium
	case "high":
		return model.SeverityHigh
	case "fatal":
		return model.SeverityFatal
	default:
		return model.SeverityUnknown
	}
}

func severityText(a *secmastermodel.ListAlertRsp) string {
	if a.Severity == nil {
		return ""
	}
	return a.Severity.Value()
}

func handleStatusText(a *secmastermodel.ListAlertRsp) string {
	if a.HandleStatus == nil {
		return ""
	}
	return a.HandleStatus.Value()
}

func alertTypeLabel(a *secmastermodel.ListAlertRsp) string {
	if a.AlertType == nil {
		return ""
	}
	return connector.JoinNonEmpty("/", connector.Str(a.AlertType.Category), connector.Str(a.AlertType.AlertType))
}

func productName(a *secmastermodel.ListAlertRsp) string {
	if a.DataSource != nil {
		if name := connector.FirstNonEmpty(connector.Str(a.DataSource.ProductName), connector.Str(a.DataSource.ProductFeature)); name != "" {
			return name
		}
	}
	return "SecMaster"
}

func observables(a *secmastermodel.ListAlertRsp, alert model.Alert) []model.Observable {
	out := make([]model.Observable, 0, 6)
	add := func(name string, typeID int, value string) {
		if value != "" {
			out = append(out, model.Observable{Name: name, TypeID: typeID, Value: value})
		}
	}
	add("src_endpoint.ip", ocsf.ObservableIPAddress, alert.SourceIP)
	add("dst_endpoint.ip", ocsf.ObservableIPAddress, alert.DestinationIP)
	add("resources.uid", ocsf.ObservableResourceUID, alert.Resource.ID)
	for _, r := range alert.Resources {
		add("resources.uid", ocsf.ObservableResourceUID, r.ID)
	}
	if a.NetworkList != nil {
		for i := range *a.NetworkList {
			n := &(*a.NetworkList)[i]
			add("src_endpoint.ip", ocsf.ObservableIPAddress, connector.Str(n.SrcIp))
			add("dst_endpoint.ip", ocsf.ObservableIPAddress, connector.Str(n.DestIp))
			add("src_endpoint.domain", 0, connector.Str(n.SrcDomain))
			add("dst_endpoint.domain", 0, connector.Str(n.DestDomain))
		}
	}
	if a.FileInfo != nil {
		for _, f := range *a.FileInfo {
			add("file.hash.md5", ocsf.ObservableFileHash, connector.Str(f.FileMd5))
			add("file.hash.sha256", ocsf.ObservableFileHash, connector.Str(f.FileSha256))
			add("file.hash", ocsf.ObservableFileHash, connector.Str(f.FileHash))
			add("file.name", ocsf.ObservableFileName, connector.Str(f.FilePath))
		}
	}
	if a.UserInfo != nil {
		for _, u := range *a.UserInfo {
			add("user.name", ocsf.ObservableUserName, connector.Str(u.UserName))
			add("user.uid", ocsf.ObservableResourceUID, connector.Str(u.UserId))
		}
	}
	return out
}

func evidence(a *secmastermodel.ListAlertRsp) *model.Evidence {
	data := map[string]any{}
	if a.NetworkList != nil {
		data["network_list"] = a.NetworkList
	}
	if a.ResourceList != nil {
		data["resource_list"] = a.ResourceList
	}
	if a.Malware != nil {
		data["malware"] = a.Malware
	}
	if a.Process != nil {
		data["process"] = a.Process
	}
	if a.FileInfo != nil {
		data["file_info"] = a.FileInfo
	}
	if a.UserInfo != nil {
		data["user_info"] = a.UserInfo
	}
	if a.Remediation != nil {
		data["remediation"] = a.Remediation
	}
	if len(data) == 0 {
		return nil
	}
	return &model.Evidence{Type: "huawei.secmaster", Data: data}
}

func firstTime(times ...time.Time) time.Time {
	for _, t := range times {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

func unmapped(a *secmastermodel.ListAlertRsp) map[string]any {
	out := map[string]any{}
	if a.VerificationState != nil {
		out["verification_state"] = a.VerificationState.Value()
	}
	if a.Confidence != nil {
		out["confidence"] = *a.Confidence
	}
	if a.Criticality != nil {
		out["criticality"] = *a.Criticality
	}
	if a.Count != nil {
		out["count"] = *a.Count
	}
	if a.SourceUrl != nil {
		out["source_url"] = *a.SourceUrl
	}
	if a.CloseReason != nil {
		out["close_reason"] = a.CloseReason.Value()
	}
	if a.WorkspaceId != nil {
		out["workspace_id"] = *a.WorkspaceId
	}
	if a.DataSource != nil {
		out["data_source"] = a.DataSource
	}
	return out
}
