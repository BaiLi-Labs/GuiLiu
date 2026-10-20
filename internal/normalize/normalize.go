// Package normalize converts the vendor-neutral alert model into an OCSF
// Detection Finding. Keeping this in one place means every connector emits the
// same schema, while vendor-specific details live in Unmapped.
package normalize

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/ocsf"
)

// Info describes the source product and must be stable for a connector. It is
// embedded into every finding so consumers can tell where the data came from.
type Info struct {
	VendorName     string
	ProductName    string
	ProductUID     string
	ProductVersion string
	LogProvider    string
	MapperVersion  string
}

// Build emits an OCSF Detection Finding for a normalized alert.
func Build(a model.Alert, acct model.Account, info Info) (json.RawMessage, error) {
	unmapped := map[string]any{}
	for k, v := range a.Unmapped {
		unmapped[k] = v
	}
	putIf(unmapped, "source_product", a.Product)
	putIf(unmapped, "original_severity", a.OriginalSeverity)
	putIf(unmapped, "vendor_status", a.VendorStatus)
	putIf(unmapped, "mapper_version", info.MapperVersion)
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
	accountUID := firstNonEmpty(a.CloudAccountUID, acct.AccountUID, acct.ID)

	product := ocsf.Product{
		VendorName: provider,
		Name:       info.ProductName,
		UID:        info.ProductUID,
		Version:    info.ProductVersion,
	}
	if a.Product != "" && a.Product != info.ProductName {
		product.Feature = &ocsf.Feature{Name: a.Product, UID: a.Product}
	}

	finding := ocsf.DetectionFinding{
		ClassUID:     ocsf.ClassUID,
		ClassName:    ocsf.ClassName,
		CategoryUID:  ocsf.CategoryUID,
		CategoryName: ocsf.CategoryName,
		ActivityID:   ocsf.ActivityCreate,
		ActivityName: ocsf.ActivityCreateName,
		TypeUID:      ocsf.TypeUIDFindingCreate,
		SeverityID:   int(a.Severity),
		Severity:     a.Severity.Caption(),
		Time:         unixMilli(a.EventTime),
		StartTime:    unixMilli(a.FirstSeenAt),
		EndTime:      unixMilli(a.LastSeenAt),
		Message:      a.Title,
		IsAlert:      true,
		Metadata: ocsf.Metadata{
			Version:      ocsf.SchemaVersion,
			Product:      product,
			UID:          a.ExternalID,
			EventCode:    a.AlertType,
			OriginalTime: a.OriginalTime,
			LogProvider:  firstNonEmpty(info.LogProvider, provider),
			LogName:      a.Product,
			ModifiedTime: unixMilli(a.LastSeenAt),
		},
		FindingInfo: ocsf.FindingInfo{
			UID:           a.ExternalID,
			Title:         a.Title,
			Desc:          a.Description,
			Types:         types(a),
			FirstSeenTime: unixMilli(a.FirstSeenAt),
			LastSeenTime:  unixMilli(a.LastSeenAt),
			CreatedTime:   unixMilli(a.FirstSeenAt),
			ModifiedTime:  unixMilli(a.LastSeenAt),
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
	if a.Resource.ID != "" || a.Resource.Name != "" {
		finding.Resources = []ocsf.Resource{{
			UID:    a.Resource.ID,
			Name:   a.Resource.Name,
			Type:   a.Resource.Type,
			Role:   "Target",
			Region: region,
		}}
	}
	if a.Tactic != "" || a.Technique != "" {
		attack := ocsf.Attack{Version: "1.0"}
		if a.Tactic != "" {
			attack.Tactic = &ocsf.Tactic{Name: a.Tactic}
			if strings.HasPrefix(a.Tactic, "TA") {
				attack.Tactic.UID = a.Tactic
				attack.Tactic.Name = ""
			}
		}
		if a.Technique != "" {
			attack.Technique = &ocsf.Technique{Name: a.Technique}
			if strings.HasPrefix(a.Technique, "T") {
				attack.Technique.UID = a.Technique
				attack.Technique.Name = ""
			}
		}
		finding.FindingInfo.Attacks = []ocsf.Attack{attack}
	}

	finding.Observables = buildObservables(a)
	finding.Evidences = buildEvidences(a)
	if len(unmapped) > 0 {
		finding.Unmapped = unmapped
	}

	return json.Marshal(finding)
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
		key := o.Type + "|" + o.Value
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
