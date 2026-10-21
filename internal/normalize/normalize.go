// Package normalize converts the vendor-neutral alert model into an OCSF
// Detection Finding. Keeping this in one place means every connector emits the
// same schema, while vendor-specific details live in Unmapped.
package normalize

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/ocsf"
)

// Info describes the source product and must be stable for a connector. It is
// embedded into every finding so consumers can tell where the data came from.
type Info struct {
	VendorName    string
	ProductName   string
	ProductUID    string
	LogProvider   string
	MapperVersion string
}

// Build projects explicit source semantics into OCSF when class and event time are known.
func Build(a model.Alert, acct model.Account, info Info) (json.RawMessage, error) {
	if len(a.OCSF) > 0 {
		return append(json.RawMessage(nil), a.OCSF...), nil
	}
	if OmissionReason(a) != "" {
		return nil, nil
	}
	classUID, className := model.FindingClass(a.FindingKind)

	unmapped := map[string]any{}
	for k, v := range a.Unmapped {
		unmapped[k] = v
	}
	putIf(unmapped, "source_product", a.Product)
	putIf(unmapped, "original_severity", a.OriginalSeverity)
	putIf(unmapped, "vendor_status", a.VendorStatus)
	putIf(unmapped, "mapper_version", info.MapperVersion)
	putIf(unmapped, "normalizer_version", "3")
	putIf(unmapped, "source_ip", a.SourceIP)
	putIf(unmapped, "destination_ip", a.DestinationIP)
	putIf(unmapped, "tactic", a.Tactic)
	putIf(unmapped, "technique", a.Technique)
	if a.Resource.ID != "" || a.Resource.Name != "" {
		unmapped["asset"] = map[string]any{
			"id":   a.Resource.ID,
			"name": a.Resource.Name,
			"type": a.Resource.Type,
		}
	}

	provider := info.VendorName
	if provider == "" {
		provider = acct.Provider
	}
	region := a.Region
	if region == "" {
		region = acct.Region
	}
	accountUID := firstNonEmpty(a.CloudAccountUID, acct.AccountUID)

	product := ocsf.Product{
		VendorName: provider,
		Name:       info.ProductName,
		UID:        info.ProductUID,
	}
	if a.Product != "" && a.Product != info.ProductName {
		product.Feature = &ocsf.Feature{Name: a.Product, UID: a.Product}
	}

	finding := ocsf.Finding{
		ClassUID:     classUID,
		ClassName:    className,
		CategoryUID:  ocsf.CategoryUID,
		CategoryName: ocsf.CategoryName,
		ActivityID:   0,
		ActivityName: "Unknown",
		TypeUID:      classUID * 100,
		SeverityID:   int(a.Severity),
		Severity:     a.Severity.Caption(),
		Time:         unixMilli(a.EventTime),
		StartTime:    unixMilli(a.FirstSeenAt),
		EndTime:      unixMilli(a.LastSeenAt),
		Message:      a.Title,
		Metadata: ocsf.Metadata{
			Profiles:     []string{"cloud"},
			Version:      ocsf.SchemaVersion,
			Product:      product,
			UID:          a.ExternalID,
			EventCode:    a.AlertType,
			OriginalTime: a.OriginalTime,
			LogProvider:  firstNonEmpty(info.LogProvider, provider),
			LogName:      a.Product,
			ModifiedTime: unixMilli(a.SourceUpdatedAt),
		},
		FindingInfo: ocsf.FindingInfo{
			UID:           a.ExternalID,
			Title:         a.Title,
			Desc:          a.Description,
			Types:         types(a),
			FirstSeenTime: unixMilli(a.FirstSeenAt),
			LastSeenTime:  unixMilli(a.LastSeenAt),
			CreatedTime:   unixMilli(a.SourceCreatedAt),
			ModifiedTime:  unixMilli(a.SourceUpdatedAt),
		},
		Cloud: ocsf.Cloud{
			Provider: provider,
			Region:   region,
			Account: &ocsf.Account{
				UID:  accountUID,
				Name: acct.Name,
				Type: provider + " Account",
			},
		},
	}
	resources := a.Resources
	if len(resources) == 0 {
		resources = []model.Resource{a.Resource}
	}
	for _, r := range resources {
		if r.ID == "" && r.Name == "" {
			continue
		}
		finding.Resources = append(finding.Resources, ocsf.Resource{
			UID:    r.ID,
			Name:   r.Name,
			Type:   r.Type,
			Region: region,
		})
	}
	finding.FindingInfo.Attacks = buildAttacks(a)

	if a.FindingKind == model.FindingVulnerability {
		if v, ok := a.Unmapped["ocsf_vulnerabilities"]; ok {
			finding.Vulnerabilities = v
		}
	}
	finding.Observables = buildObservables(a)
	finding.Evidences = buildEvidences(a)
	if len(unmapped) > 0 {
		finding.Unmapped = unmapped
	}

	return json.Marshal(finding)
}

// OmissionReason keeps an incomplete class projection out of the OCSF payload
// while retaining the canonical facts and source record for queries.
func OmissionReason(a model.Alert) string {
	if len(a.OCSF) > 0 {
		return ""
	}
	if a.EventTime.IsZero() {
		return "source_event_time_missing"
	}
	switch a.FindingKind {
	case model.FindingDetection:
		return ""
	case model.FindingVulnerability:
		if a.Unmapped["ocsf_vulnerabilities"] == nil {
			return "source_vulnerability_details_missing"
		}
		return ""
	case model.FindingCompliance, model.FindingIncident:
		// These classes require dedicated payloads (compliance, incident profile
		// and finding_info_list). Native OCSF is already preserved above.
		return "source_class_projection_unavailable"
	default:
		return "source_class_unmapped"
	}
}

var tacticID = regexp.MustCompile(`^TA[0-9]{4}$`)
var techniqueID = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

func buildAttacks(a model.Alert) []ocsf.Attack {
	var tactics []*ocsf.Tactic
	var techniques []*ocsf.Technique
	seen := map[string]bool{}
	for _, value := range strings.Split(a.Tactic, ",") {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		t := &ocsf.Tactic{Name: value}
		if tacticID.MatchString(value) {
			t.UID, t.Name = value, ""
		}
		tactics = append(tactics, t)
	}
	for _, value := range strings.Split(a.Technique, ",") {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		t := &ocsf.Technique{Name: value}
		if techniqueID.MatchString(value) {
			t.UID, t.Name = value, ""
		}
		techniques = append(techniques, t)
	}
	// Do not invent relationships between multiple tactics and techniques.
	if len(tactics) == 1 && len(techniques) == 1 {
		return []ocsf.Attack{{Tactic: tactics[0], Technique: techniques[0]}}
	}
	var out []ocsf.Attack
	for _, t := range tactics {
		out = append(out, ocsf.Attack{Tactic: t})
	}
	for _, t := range techniques {
		out = append(out, ocsf.Attack{Technique: t})
	}
	return out
}

func buildObservables(a model.Alert) []ocsf.Observable {
	seen := map[string]struct{}{}
	out := make([]ocsf.Observable, 0, len(a.Observables)+3)
	add := func(o ocsf.Observable) {
		if o.Value == "" {
			return
		}
		if o.Type == "" {
			o.Type = ocsf.ObservableTypeName(o.TypeID)
		}
		key := fmt.Sprintf("%d|%s|%s", o.TypeID, o.Name, o.Value)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, o)
	}
	for _, o := range a.Observables {
		add(ocsf.Observable{Name: o.Name, Type: o.Type, TypeID: o.TypeID, Value: o.Value})
	}
	add(ocsf.Observable{Name: "src_endpoint.ip", TypeID: ocsf.ObservableIPAddress, Value: a.SourceIP})
	add(ocsf.Observable{Name: "dst_endpoint.ip", TypeID: ocsf.ObservableIPAddress, Value: a.DestinationIP})
	add(ocsf.Observable{Name: "resources.uid", TypeID: ocsf.ObservableResourceUID, Value: a.Resource.ID})
	return out
}

func buildEvidences(a model.Alert) []ocsf.Evidence {
	out := make([]ocsf.Evidence, 0, len(a.Evidences))
	for _, e := range a.Evidences {
		if len(e.Data) == 0 {
			continue
		}
		data := map[string]any{}
		if e.Type != "" {
			data["type"] = e.Type
		}
		for k, v := range e.Data {
			data[k] = v
		}
		out = append(out, ocsf.Evidence{Data: data})
	}
	return out
}

func types(a model.Alert) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range []string{a.AlertType, a.Product} {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func putIf(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	}
}

func unixMilli(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
