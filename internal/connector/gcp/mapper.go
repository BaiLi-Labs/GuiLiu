package gcp

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/ocsf"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func normalizeFinding(f *securitycenterpb.Finding, raw json.RawMessage) model.Alert {
	externalID := connector.FirstNonEmpty(f.GetName(), f.GetCanonicalName())
	eventTime := timestamp(f.GetEventTime())
	severity := mapSeverity(f.GetSeverity().String())
	resource := resourceFromName(f.GetResourceName())
	project := projectFromFinding(f)

	alert := model.Alert{
		ExternalID:       externalID,
		FindingKind:      model.FindingOther,
		SourceCreatedAt:  timestamp(f.GetCreateTime()),
		Title:            connector.FirstNonEmpty(f.GetCategory(), sourceString(f, "finding_name", "title", "description"), "GCP Security Command Center finding"),
		Description:      connector.FirstNonEmpty(f.GetDescription(), sourceString(f, "description")),
		Severity:         severity,
		OriginalSeverity: connector.SourceScalar(raw, "/finding/severity", "/severity"),
		VendorStatus:     connector.SourceScalar(raw, "/finding/state", "/state"),
		EventTime:        eventTime,
		OriginalTime:     formatTimestamp(f.GetEventTime()),
		Product:          connector.FirstNonEmpty(sourceString(f, "source", "scanner_name", "product"), "Security Command Center"),
		AlertType:        connector.FirstNonEmpty(f.GetCategory(), f.GetFindingClass().String()),
		Region:           regionFromResource(f.GetResourceName()),
		CloudAccountUID:  project,
		Resource:         resource,
		Raw:              append(json.RawMessage(nil), raw...),
	}
	switch f.GetFindingClass().String() {
	case "THREAT":
		alert.FindingKind = model.FindingDetection
	case "VULNERABILITY":
		alert.FindingKind = model.FindingVulnerability
	}
	if m := f.GetMitreAttack(); m != nil {
		if tactic := m.GetPrimaryTactic().String(); !strings.Contains(tactic, "UNSPECIFIED") {
			alert.Tactic = tactic
		}
		if techniques := m.GetPrimaryTechniques(); len(techniques) > 0 {
			alert.Technique = strings.Join(enumStrings(techniques), ",")
		}
	}
	if connections := f.GetConnections(); len(connections) > 0 && connections[0] != nil {
		alert.SourceIP = connections[0].GetSourceIp()
		alert.DestinationIP = connections[0].GetDestinationIp()
	}
	if alert.SourceIP == "" {
		alert.SourceIP = sourceString(f, "source_ip", "src_ip")
	}
	if alert.DestinationIP == "" {
		alert.DestinationIP = sourceString(f, "destination_ip", "dest_ip")
	}
	alert.Observables = observables(f, alert)
	if ev := evidence(f); ev != nil {
		alert.Evidences = []model.Evidence{*ev}
	}
	alert.Unmapped = map[string]any{"gcp_scc": map[string]any{
		"parent":         f.GetParent(),
		"canonical_name": f.GetCanonicalName(),
		"finding_class":  f.GetFindingClass().String(),
		"external_uri":   f.GetExternalUri(),
		"mute":           f.GetMute().String(),
		"next_steps":     f.GetNextSteps(),
	}}
	if v := f.GetVulnerability(); v != nil && alert.FindingKind == model.FindingVulnerability {
		if cve := v.GetCve(); cve != nil && cve.GetId() != "" {
			alert.Unmapped["ocsf_vulnerabilities"] = []any{map[string]any{"cve": map[string]any{"uid": cve.GetId()}}}
		}
	}
	return alert
}

func mapSeverity(severity string) model.Severity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

func observables(f *securitycenterpb.Finding, alert model.Alert) []model.Observable {
	collector := connector.NewObservableCollector(alert.Raw)
	add := collector.Add
	add("resources.uid", ocsf.ObservableResourceUID, alert.Resource.ID, "/resourceName")
	add("src_endpoint.ip", ocsf.ObservableIPAddress, alert.SourceIP, "/sourceProperties/source_ip", "/sourceProperties/src_ip")
	add("dst_endpoint.ip", ocsf.ObservableIPAddress, alert.DestinationIP, "/sourceProperties/destination_ip", "/sourceProperties/dest_ip")
	for i, connection := range f.GetConnections() {
		if connection == nil {
			continue
		}
		add("src_endpoint.ip", ocsf.ObservableIPAddress, connection.GetSourceIp(), fmt.Sprintf("/connections/%d/sourceIp", i))
		add("dst_endpoint.ip", ocsf.ObservableIPAddress, connection.GetDestinationIp(), fmt.Sprintf("/connections/%d/destinationIp", i))
	}
	if indicator := f.GetIndicator(); indicator != nil {
		for i, ip := range indicator.GetIpAddresses() {
			add("indicator.ip", ocsf.ObservableIPAddress, ip, fmt.Sprintf("/indicator/ipAddresses/%d", i))
		}
		for i, domain := range indicator.GetDomains() {
			add("indicator.domain", 0, domain, fmt.Sprintf("/indicator/domains/%d", i))
		}
	}
	add("cloud.account.uid", ocsf.ObservableResourceUID, alert.CloudAccountUID, "/sourceProperties/project_id")
	add("remote.ip", ocsf.ObservableIPAddress, sourceString(f, "remote_ip"), "/sourceProperties/remote_ip")
	add("local.ip", ocsf.ObservableIPAddress, sourceString(f, "local_ip"), "/sourceProperties/local_ip")
	add("hostname", ocsf.ObservableHostname, sourceString(f, "hostname", "instance_name", "resource_name"), "/sourceProperties/hostname", "/sourceProperties/instance_name", "/sourceProperties/resource_name")
	for i, file := range f.GetFiles() {
		if file == nil {
			continue
		}
		name := "file.hash.sha256"
		if file.GetPartiallyHashed() {
			name = "file.prefix_hash.sha256"
		}
		add(name, ocsf.ObservableFileHash, file.GetSha256(), fmt.Sprintf("/files/%d/sha256", i))
		add("file.name", ocsf.ObservableFileName, file.GetPath(), fmt.Sprintf("/files/%d/path", i))
	}
	if access := f.GetAccess(); access != nil {
		add("user.name", ocsf.ObservableUserName, access.GetPrincipalEmail(), "/access/principalEmail")
	}
	collector.AddRoot("resources.uid", ocsf.ObservableResourceUID, alert.Resource.ID, "/resource/name")
	collector.AddRoot("cloud.account.uid", ocsf.ObservableResourceUID, alert.CloudAccountUID, "/resource/gcpMetadata/project", "/resource/projectName")
	return collector.Values()
}

func evidence(f *securitycenterpb.Finding) *model.Evidence {
	data := map[string]any{}
	if len(f.GetSourceProperties()) > 0 {
		props := map[string]any{}
		for k, v := range f.GetSourceProperties() {
			if v != nil {
				props[k] = v.AsInterface()
			}
		}
		data["source_properties"] = props
	}
	if connections := f.GetConnections(); len(connections) > 0 {
		items := make([]map[string]any, 0, len(connections))
		for _, c := range connections {
			if c == nil {
				continue
			}
			items = append(items, map[string]any{
				"source_ip":        c.GetSourceIp(),
				"source_port":      c.GetSourcePort(),
				"destination_ip":   c.GetDestinationIp(),
				"destination_port": c.GetDestinationPort(),
				"protocol":         c.GetProtocol().String(),
			})
		}
		data["connections"] = items
	}
	if m := f.GetMitreAttack(); m != nil {
		data["mitre_attack"] = map[string]any{
			"tactic":     m.GetPrimaryTactic().String(),
			"techniques": enumStrings(m.GetPrimaryTechniques()),
			"version":    m.GetVersion(),
		}
	}
	if len(data) == 0 {
		return nil
	}
	return &model.Evidence{Type: "gcp.scc", Data: data}
}

func enumStrings[T interface{ String() string }](values []T) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, v.String())
	}
	return out
}

func sourceString(f *securitycenterpb.Finding, keys ...string) string {
	for _, key := range keys {
		if v, ok := f.GetSourceProperties()[key]; ok && v != nil {
			if s := valueString(v.AsInterface()); s != "" {
				return s
			}
		}
	}
	return ""
}

func valueString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case []any:
		for _, item := range x {
			if s := valueString(item); s != "" {
				return s
			}
		}
	}
	return ""
}

func timestamp(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime().UTC()
}

func formatTimestamp(ts *timestamppb.Timestamp) string {
	t := timestamp(ts)
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func resourceFromName(name string) model.Resource {
	if name == "" {
		return model.Resource{}
	}
	parts := strings.Split(strings.TrimPrefix(name, "//"), "/")
	resourceName := parts[len(parts)-1]
	resourceType := "gcp_resource"
	if len(parts) >= 2 {
		resourceType = parts[len(parts)-2]
	}
	return model.Resource{ID: name, Name: resourceName, Type: resourceType}
}

func regionFromResource(name string) string {
	parts := strings.Split(strings.TrimPrefix(name, "//"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "regions" || parts[i] == "zones" || parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}

func projectFromFinding(f *securitycenterpb.Finding) string {
	if p := sourceString(f, "project_id", "project", "projectId"); p != "" {
		return p
	}
	parts := strings.Split(strings.TrimPrefix(f.GetResourceName(), "//"), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "projects" {
			return parts[i+1]
		}
	}
	return ""
}
