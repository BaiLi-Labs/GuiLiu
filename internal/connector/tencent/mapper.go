package tencent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/ocsf"
	csip "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/csip/v20221121"
)

// Normalize maps one Tencent CSIP alert payload onto the vendor-neutral model.
// The engine adds OCSF and storage metadata afterwards, so this function stays
// deterministic and can be replayed against historical raw alerts.
func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	var a csip.AlertInfo
	if err := json.Unmarshal(raw, &a); err != nil {
		return model.Alert{}, fmt.Errorf("decode tencent alert: %w", err)
	}

	externalID := connector.Str(a.ID)
	if externalID == "" {
		externalID = connector.Str(a.Key)
	}
	if externalID == "" {
		return model.Alert{}, fmt.Errorf("tencent source record has no native ID")
	}

	firstSeen, _ := connector.ParseVendorTime(connector.Str(a.CreateTime))
	lastSeen, _ := connector.ParseVendorTime(connector.Str(a.UpdateTime))
	eventTime := firstSeen

	alert := model.Alert{
		ExternalID:       externalID,
		FindingKind:      model.FindingDetection,
		Title:            connector.FirstNonEmpty(connector.Str(a.Name), "Tencent Cloud security alert"),
		Description:      connector.FirstNonEmpty(connector.Str(a.RiskInvestigation), connector.Str(a.UrgentSuggestion), connector.Str(a.RiskTreatment)),
		Severity:         mapSeverity(connector.Uint64(a.Level)),
		OriginalSeverity: connector.SourceScalar(raw, "/Level"),
		VendorStatus:     connector.SourceScalar(raw, "/Status"),
		EventTime:        eventTime,
		FirstSeenAt:      firstSeen,
		LastSeenAt:       lastSeen,
		OriginalTime:     connector.Str(a.CreateTime),
		Product:          sourceProduct(connector.Str(a.Source)),
		AlertType:        connector.JoinNonEmpty("/", connector.Str(a.Type), connector.Str(a.SubType)),
		CloudAccountUID:  connector.FirstNonEmpty(connector.Str(a.Uin), connector.Str(a.AppID)),
		Raw:              append(json.RawMessage(nil), raw...),
	}

	if a.Attacker != nil {
		alert.SourceIP = connector.FirstNonEmpty(connector.Str(a.Attacker.IP), connector.Str(a.Attacker.OriginIP))
		alert.SourceLocation = connector.Str(a.Attacker.Address)
		alert.SourceCountry = connector.Str(a.Attacker.Country)
	}
	if alert.SourceIP == "" && a.ExtraInfo != nil {
		alert.SourceIP = connector.Str(a.ExtraInfo.SourceIP)
	}
	if a.Victim != nil {
		alert.DestinationIP = connector.Str(a.Victim.IP)
		// RoleInfo.Name is documented as an enterprise name, not an asset name,
		// so it never becomes resource.name. It stays available in the vendor
		// evidence and raw payload. The host name comes from CVM asset data.
		// RoleInfo.Account is kept out of resource.account_uid as well: the
		// observed value is an AppID, while account_uid is a UIN, so projecting
		// it would invent a cross-account identity that cannot be matched.
		alert.Resource = connector.NamedResource(
			connector.Str(a.Victim.InstanceID),
			assetType(connector.Int64(a.Victim.AssetType)),
			"",
			connector.Str(a.Victim.Domain), connector.Str(a.Victim.IP), connector.Str(a.Victim.InstanceID),
		)
		alert.Resource.DeclaredName = connector.Str(a.Victim.Name)
	}
	alert.ResponseAction = connector.Str(a.ProcessType)

	if a.ExtraInfo != nil {
		alert.RuleID = connector.Str(a.ExtraInfo.StrategyID)
	}
	if a.Count != nil && *a.Count <= 9223372036854775807 {
		n := int64(*a.Count)
		alert.OccurrenceCount = &n
		alert.OccurrenceScope = "tencent.csip.alert_count"
	}
	alert.Observables = observables(&a, alert)
	if ev := evidence(&a); ev != nil {
		alert.Evidences = []model.Evidence{*ev}
	}
	if extra := unmapped(&a); len(extra) > 0 {
		alert.Unmapped = map[string]any{"tencent_csip": extra}
	}
	return alert, nil
}

func mapSeverity(level uint64) model.Severity {
	switch level {
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
	default:
		return model.SeverityUnknown
	}
}

func assetType(t int64) string {
	switch t {
	case 1:
		return "host"
	case 2:
		return "domain"
	case 3:
		return "network"
	default:
		return ""
	}
}

func sourceProduct(source string) string {
	switch strings.ToUpper(strings.TrimSpace(source)) {
	case "CSIP":
		return "Cloud Security Center"
	case "CWP":
		return "Host Security (CWP)"
	case "CFW":
		return "Cloud Firewall (CFW)"
	case "WAF":
		return "Web Application Firewall (WAF)"
	case "":
		return ""
	default:
		return source
	}
}

func observables(a *csip.AlertInfo, alert model.Alert) []model.Observable {
	collector := connector.NewObservableCollector(alert.Raw)
	add := collector.Add
	add("src_endpoint.ip", ocsf.ObservableIPAddress, alert.SourceIP, "/Attacker/IP", "/Attacker/OriginIP", "/ExtraInfo/SourceIP")
	add("dst_endpoint.ip", ocsf.ObservableIPAddress, alert.DestinationIP, "/Victim/IP")
	add("resources.uid", ocsf.ObservableResourceUID, alert.Resource.ID, "/Victim/InstanceID")
	if a.Attacker != nil {
		add("src_endpoint.ip", ocsf.ObservableIPAddress, connector.Str(a.Attacker.OriginIP), "/Attacker/OriginIP")
		add("attacker.domain", 0, connector.Str(a.Attacker.Domain), "/Attacker/Domain")
		add("file.hash.md5", ocsf.ObservableFileHash, connector.Str(a.Attacker.MD5), "/Attacker/MD5")
		add("file.name", ocsf.ObservableFileName, connector.Str(a.Attacker.FileName), "/Attacker/FileName")
	}
	if a.Victim != nil {
		add("victim.host_ip", ocsf.ObservableIPAddress, connector.Str(a.Victim.HostIP), "/Victim/HostIP")
		add("victim.origin_ip", ocsf.ObservableIPAddress, connector.Str(a.Victim.OriginIP), "/Victim/OriginIP")
		add("resources.uid", ocsf.ObservableResourceUID, connector.Str(a.Victim.ContainerID), "/Victim/ContainerID")
	}
	if extra := a.ExtraInfo; extra != nil {
		add("user.name", ocsf.ObservableUserName, connector.Str(extra.LoginUserName), "/ExtraInfo/LoginUserName")
		add("file.hash.md5", ocsf.ObservableFileHash, connector.Str(extra.FileMD5), "/ExtraInfo/FileMD5")
		add("file.hash.md5", ocsf.ObservableFileHash, connector.Str(extra.MaliciousProcessFileMD5), "/ExtraInfo/MaliciousProcessFileMD5")
		add("file.hash.md5", ocsf.ObservableFileHash, connector.Str(extra.ProcessMD5), "/ExtraInfo/ProcessMD5")
		add("file.name", ocsf.ObservableFileName, connector.Str(extra.FileName), "/ExtraInfo/FileName")
		add("src_endpoint.ip", ocsf.ObservableIPAddress, connector.Str(extra.SourceIP), "/ExtraInfo/SourceIP")
	}
	return collector.Values()
}

func evidence(a *csip.AlertInfo) *model.Evidence {
	data := map[string]any{}
	if a.ExtraInfo != nil {
		data["extra_info"] = a.ExtraInfo
	}
	if a.Attacker != nil {
		data["attacker"] = a.Attacker
	}
	if a.Victim != nil {
		data["victim"] = a.Victim
	}
	if v := connector.Str(a.EvidencePath); v != "" {
		data["path"] = v
	}
	if v := connector.Str(a.EvidenceLocation); v != "" {
		data["location"] = v
	}
	if v := connector.Str(a.EvidenceData); v != "" {
		if decoded, err := base64.StdEncoding.DecodeString(v); err == nil && utf8.Valid(decoded) {
			text, truncated := connector.Truncate(string(decoded), 16384)
			data["data"] = text
			if truncated {
				data["truncated"] = true
			}
		} else {
			text, truncated := connector.Truncate(v, 16384)
			data["data_base64"] = text
			if truncated {
				data["truncated"] = true
			}
		}
	}
	if len(data) == 0 {
		return nil
	}
	return &model.Evidence{Type: "tencent.csip", Data: data}
}

func unmapped(a *csip.AlertInfo) map[string]any {
	extra := map[string]any{}
	set := func(key, value string) {
		if value != "" {
			extra[key] = value
		}
	}
	set("uin", connector.Str(a.Uin))
	set("app_id", connector.Str(a.AppID))
	set("nick_name", connector.Str(a.NickName))
	set("source", connector.Str(a.Source))
	set("type", connector.Str(a.Type))
	set("sub_type", connector.Str(a.SubType))
	set("log_type", connector.Str(a.LogType))
	set("process_type", connector.Str(a.ProcessType))
	set("key", connector.Str(a.Key))
	set("date", connector.Str(a.Date))
	set("urgent_suggestion", connector.Str(a.UrgentSuggestion))
	set("remediation_suggestion", connector.Str(a.RemediationSuggestion))
	set("log_search", connector.Str(a.LogSearch))
	if a.Count != nil {
		extra["count"] = *a.Count
	}
	if a.Action != nil {
		extra["action"] = *a.Action
	}
	return extra
}
