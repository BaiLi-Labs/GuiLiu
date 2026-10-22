package connector

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// MappingSpec is executable documentation of the inputs consumed by a mapper.
// Ordered paths express precedence; wildcards expand to concrete JSON pointers.
type MappingSpec struct {
	Field     string   `json:"field"`
	Paths     []string `json:"source_paths"`
	Transform string   `json:"transform"`
}

func MappingFor(provider string) []MappingSpec {
	fields := map[string]map[string]string{
		"tencent": {
			"external_id": "/ID,/Key", "rule_id": "/ExtraInfo/StrategyID",
			"event_time": "/CreateTime", "first_seen_at": "/CreateTime", "last_seen_at": "/UpdateTime",

			"severity": "/Level", "original_severity": "/Level", "vendor_status": "/Status",
			"account_uid": "/Uin,/AppID", "product": "/Source", "alert_type": "/Type,/SubType",
			"title": "/Name", "description": "/RiskInvestigation,/UrgentSuggestion,/RiskTreatment",
			"source_ip": "/Attacker/IP,/Attacker/OriginIP,/ExtraInfo/SourceIP", "destination_ip": "/Victim/IP",
			"source_location": "/Attacker/Address", "source_country": "/Attacker/Country", "response_action": "/ProcessType",
			"resource":             "/Victim/InstanceID,/Victim/Name,/Victim/Domain,/Victim/IP,/Victim/AssetType",
			"resource.account_uid": "/Victim/Account", "resource.source": "/Victim/Name", "occurrence_count": "/Count",
		},
		"aliyun": {
			"external_id": "/Id,/AlarmUniqueInfo,/UniqueInfo",
			"event_time":  "/OccurrenceTimeStamp,/OccurrenceTime", "first_seen_at": "/OccurrenceTimeStamp,/OccurrenceTime", "last_seen_at": "/LastTimeStamp,/LastTime",
			"severity": "/Level", "original_severity": "/Level", "vendor_status": "/EventStatus",
			"account_uid": "/SourceAliUid", "alert_type": "/AlarmEventTypeDisplay,/AlarmEventType,/EventSubType",
			"title": "/Name,/AlarmEventNameDisplay,/AlarmEventName", "description": "/Desc",
			"source_ip": "/Details/*/NameDisplay,/Details/*/Type,/Details/*/ValueDisplay,/Details/*/Value",
			"resource":  "/InstanceId,/Uuid,/ContainerId,/K8sClusterId,/InstanceName,/K8sPodName,/ContainerImageName,/K8sClusterName",
			"resources": "/InstanceId,/Uuid,/ContainerId,/K8sClusterId", "tactic": "/TacticItems/*,/Stages",
			"resource.source": "/InstanceName,/K8sPodName,/ContainerImageName,/K8sClusterName",
		},
		"huawei": {
			"external_id": "/id,/origin_id", "event_time": "/first_observed_time", "first_seen_at": "/first_observed_time", "last_seen_at": "/last_observed_time",
			"source_created_at": "/create_time", "source_updated_at": "/update_time",
			"severity": "/severity,/criticality", "original_severity": "/severity,/criticality", "vendor_status": "/handle_status",
			"account_uid": "/domain_id", "region": "/region_id", "product": "/data_source", "alert_type": "/alert_type",
			"title": "/title,/alert_type", "description": "/description", "actor": "/actor",
			"source_ip": "/network_list/*/src_ip", "destination_ip": "/network_list/*/dest_ip", "resources": "/resource_list/*", "resource": "/resource_list/0", "occurrence_count": "/count",
			"resource.source": "/resource_list/0/name",
		},
		"aws": {
			"external_id": "/finding_info/uid,/metadata/uid", "rule_id": "/finding_info/analytic/uid",
			"event_time": "/time,/time_dt", "first_seen_at": "/finding_info/first_seen_time,/finding_info/first_seen_time_dt", "last_seen_at": "/finding_info/last_seen_time,/finding_info/last_seen_time_dt",
			"source_created_at": "/finding_info/created_time,/finding_info/created_time_dt", "source_updated_at": "/finding_info/modified_time,/finding_info/modified_time_dt",
			"severity": "/severity_id,/severity", "original_severity": "/severity,/severity_id", "vendor_status": "/status,/status_id",
			"finding_kind": "/class_uid", "account_uid": "/cloud/account/uid", "region": "/cloud/region", "product": "/metadata/product/name",
			"alert_type": "/finding_info/types,/metadata/event_code,/class_name", "title": "/finding_info/title", "description": "/finding_info/desc",
			"resources": "/resources/*", "resource": "/resources/0", "resource.source": "/resources/0/name", "source_ip": "/observables/*,/evidences/*/src_endpoint/ip", "destination_ip": "/observables/*,/evidences/*/dst_endpoint/ip",
		},
		"gcp": {
			"external_id": "/name,/canonicalName", "event_time": "/eventTime", "source_created_at": "/createTime",
			"severity": "/severity", "original_severity": "/severity", "vendor_status": "/state", "finding_kind": "/findingClass",
			"product": "/sourceProperties/source,/sourceProperties/scanner_name,/sourceProperties/product", "alert_type": "/category,/findingClass", "title": "/category,/sourceProperties/title", "description": "/description,/sourceProperties/description",
			"resource": "/resourceName", "resource.source": "/resource/displayName", "account_uid": "/sourceProperties/project_id,/resourceName", "region": "/resourceName",
			"source_ip": "/connections/*/sourceIp,/sourceProperties/source_ip,/sourceProperties/src_ip", "destination_ip": "/connections/*/destinationIp,/sourceProperties/destination_ip,/sourceProperties/dest_ip",
			"tactic": "/mitreAttack/primaryTactic", "technique": "/mitreAttack/primaryTechniques",
		},
		"azure": {
			"external_id": "/properties/systemAlertId,/name,/id", "rule_id": "/properties/alertType", "event_time": "/properties/timeGeneratedUtc", "first_seen_at": "/properties/startTimeUtc", "last_seen_at": "/properties/endTimeUtc",
			"source_created_at": "/systemData/createdAt", "source_updated_at": "/systemData/lastModifiedAt",
			"severity": "/properties/severity", "original_severity": "/properties/severity", "vendor_status": "/properties/status",
			"account_uid": "/id,/properties/resourceIdentifiers/*/azureResourceId", "region": "/id,/properties/resourceIdentifiers/*/azureResourceId",
			"product": "/properties/productName,/properties/vendorName", "alert_type": "/properties/alertType", "title": "/properties/alertDisplayName,/properties/alertType", "description": "/properties/description",
			"resource": "/properties/resourceIdentifiers/*,/properties/compromisedEntity", "resource.source": "/properties/compromisedEntity", "resources": "/properties/resourceIdentifiers/*",
			"source_ip": "/properties/entities/*/sourceAddress,/properties/entities/*/sourceIp,/properties/entities/*/source_ip", "destination_ip": "/properties/entities/*/destinationAddress,/properties/entities/*/destinationIp,/properties/entities/*/destination_ip",
			"tactic": "/properties/intent", "technique": "/properties/techniques,/properties/subTechniques",
		},
	}
	transforms := map[string]string{"severity": "versioned_vendor_severity_map", "vendor_status": "preserve_source_value", "event_time": "parse_source_time_utc", "first_seen_at": "parse_source_time_utc", "last_seen_at": "parse_source_time_utc", "source_created_at": "parse_source_time_utc", "source_updated_at": "parse_source_time_utc", "finding_kind": "explicit_source_class_map", "source_ip": "explicit_source_role_only", "destination_ip": "explicit_destination_role_only", "source_location": "preserve_source_value", "source_country": "preserve_source_value", "response_action": "preserve_source_value", "resource.account_uid": "preserve_source_value", "resource.source": "declared_name_or_identifier"}
	out := []MappingSpec{}
	for field, paths := range fields[provider] {
		transform := transforms[field]
		if transform == "" {
			transform = "ordered_source_projection"
		}
		out = append(out, MappingSpec{Field: field, Paths: strings.Split(paths, ","), Transform: transform})
	}
	// Stable output is part of the mapping documentation contract.
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

func ApplyProvenance(a *model.Alert, provider string, acct model.Account) {
	var raw any
	dec := json.NewDecoder(strings.NewReader(string(a.Raw)))
	dec.UseNumber()
	if dec.Decode(&raw) != nil {
		return
	}
	a.Provenance = map[string]model.FieldOrigin{
		"source_api":         {Source: "connector", Paths: []string{"/source_api"}, Transform: "connector_api_contract"},
		"source_api_version": {Source: "connector", Paths: []string{"/api_version"}, Transform: "connector_api_contract"},
		"raw_hash":           {Source: "record", Paths: []string{""}, Transform: "sha256_exact_bytes"},
	}
	prefix := sourceObjectPrefix(raw)
	for _, spec := range MappingFor(provider) {
		paths := []string{}
		for _, path := range spec.Paths {
			paths = append(paths, expandPointer(raw, strings.Split(strings.TrimPrefix(prefix+path, "/"), "/"), "")...)
		}
		if len(paths) > 0 {
			a.Provenance[spec.Field] = model.FieldOrigin{Source: "record", Paths: paths, Transform: spec.Transform}
		}
	}
	if provider == "gcp" {
		for field, paths := range map[string][]string{"resource": {"/resource/name", "/resource/displayName", "/resource/type"}, "region": {"/resource/location"}, "account_uid": {"/resource/gcpMetadata/project", "/resource/projectName"}} {
			found := []string{}
			for _, p := range paths {
				found = append(found, expandPointer(raw, strings.Split(strings.TrimPrefix(p, "/"), "/"), "")...)
			}
			if len(found) > 0 {
				a.Provenance[field] = model.FieldOrigin{Source: "record", Paths: found, Transform: "resource_enrichment_precedence"}
			}
		}
	}
	if provider == "azure" && a.Resource.AccountUID != "" {
		// The owning subscription is an explicit segment of the resource ID
		// already recorded under resource, never an inferred tenant.
		if origin, ok := a.Provenance["resource"]; ok {
			origin.Transform += ":resource_id_segment"
			a.Provenance["resource.account_uid"] = origin
		}
	}
	if a.CloudAccountUID == "" && acct.AccountUID != "" {
		a.Provenance["account_uid"] = model.FieldOrigin{Source: "configuration", Paths: []string{"/account_uid"}, Transform: "configured_cloud_account_uid"}
	}
	if a.Region == acct.Region && acct.Region != "" {
		if _, ok := a.Provenance["region"]; !ok {
			a.Provenance["region"] = model.FieldOrigin{Source: "configuration", Paths: []string{"/region"}, Transform: "configured_scope"}
		}
	}
	if _, ok := a.Provenance["finding_kind"]; !ok {
		a.Provenance["finding_kind"] = model.FieldOrigin{Source: "connector", Paths: []string{"/product_uid"}, Transform: "source_api_record_class"}
	}
	for i, o := range a.Observables {
		paths := append([]string(nil), o.SourcePaths...)
		key := fmt.Sprintf("observables/%d/value", i)
		if len(paths) > 0 {
			a.Provenance[key] = model.FieldOrigin{Source: "record", Paths: paths, Transform: "typed_source_value"}
			if o.Name == "src_endpoint.ip" && o.Value == a.SourceIP {
				a.Provenance["source_ip"] = a.Provenance[key]
			}
			if o.Name == "dst_endpoint.ip" && o.Value == a.DestinationIP {
				a.Provenance["destination_ip"] = a.Provenance[key]
			}
			continue
		}
		// Some typed values are deterministic projections, such as a subscription
		// UID inside an Azure resource ID, rather than literal JSON leaf values.
		field := map[string]string{"cloud.account.uid": "account_uid", "resources.uid": "resource"}[o.Name]
		if origin, ok := a.Provenance[field]; ok {
			origin.Transform += ":observable_projection"
			a.Provenance[key] = origin
		}
	}
}

func expandPointer(value any, parts []string, path string) []string {
	if len(parts) == 0 {
		if value == nil || value == "" {
			return nil
		}
		return []string{path}
	}
	head := parts[0]
	out := []string{}
	switch v := value.(type) {
	case map[string]any:
		key := strings.ReplaceAll(strings.ReplaceAll(head, "~1", "/"), "~0", "~")
		if x, ok := v[key]; ok {
			out = append(out, expandPointer(x, parts[1:], path+"/"+head)...)
		}
	case []any:
		if head == "*" {
			for i, x := range v {
				out = append(out, expandPointer(x, parts[1:], path+"/"+strconv.Itoa(i))...)
			}
		} else if i, err := strconv.Atoi(head); err == nil && i >= 0 && i < len(v) {
			out = append(out, expandPointer(v[i], parts[1:], path+"/"+head)...)
		}
	}
	return out
}
