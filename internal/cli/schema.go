package cli

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

func responseSchema(command string) map[string]any {
	values := map[string]any{
		"alerts": alertListResponse{}, "alert": view.Alert{}, "groups": groupListResponse{},
		"changes": changePage{}, "stats": statsResponse{}, "coverage": model.Coverage{},
		"revisions": revisionPageResponse{}, "context": query.AssetContext{},
		"assets": assetListResponse{}, "asset": model.Asset{}, "lookup": assetLookupResponse{},
		"findings": assetFindingsResponse{}, "providers": providersResponse{},
		"mapping": mappingResponse{}, "failures": failuresResponse{},
	}
	var schema map[string]any
	if command == "component" {
		schema = map[string]any{"description": "Exact saved source JSON bytes; vendor-defined structure, not normalized or projected."}
	} else if command == "health" {
		schema = map[string]any{"oneOf": []any{typeSchema(reflect.TypeOf(healthResponse{})), typeSchema(reflect.TypeOf(accountHealthResponse{}))}}
	} else {
		schema = typeSchema(reflect.TypeOf(values[command]))
	}
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	if command == "groups" {
		schema["properties"].(map[string]any)["summary"].(map[string]any)["description"] = "Present as an object only for asset, name_asset, vpc, subnet, security_group and nic grouping; null for signature, source and type_asset. Counts describe overlapping group memberships, not attacks."
	}
	return schema
}

func ndjsonType(command string) reflect.Type {
	values := map[string]any{"alerts": view.Alert{}, "groups": model.AlertGroup{}, "changes": model.AlertChange{}, "revisions": view.Revision{}, "assets": model.Asset{}, "findings": view.Alert{}, "providers": connector.Descriptor{}, "mapping": connector.MappingSpec{}, "failures": failureRecord{}}
	return reflect.TypeOf(values[command])
}

func ndjsonSchema(command string) map[string]any {
	if typ := ndjsonType(command); typ != nil {
		return typeSchema(typ)
	}
	return nil
}

// Describe actual JSON field names and types without maintaining a second
// handwritten field catalog. Maps and source payloads stay open-ended.
func typeSchema(t reflect.Type) map[string]any {
	if t == nil || t == reflect.TypeOf(json.RawMessage{}) {
		return map[string]any{}
	}
	if t == reflect.TypeOf(time.Time{}) {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	nullable := func(v map[string]any) map[string]any {
		return map[string]any{"anyOf": []any{v, map[string]any{"type": "null"}}}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return nullable(typeSchema(t.Elem()))
	case reflect.Interface:
		return map[string]any{}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice:
		return nullable(map[string]any{"type": "array", "items": typeSchema(t.Elem())})
	case reflect.Array:
		return map[string]any{"type": "array", "items": typeSchema(t.Elem())}
	case reflect.Map:
		return nullable(map[string]any{"type": "object", "additionalProperties": typeSchema(t.Elem())})
	case reflect.Struct:
		props := map[string]any{}
		required := []string{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := strings.Split(f.Tag.Get("json"), ",")
			if tag[0] == "-" {
				continue
			}
			if f.Anonymous && tag[0] == "" {
				embedded := typeSchema(f.Type)
				for k, v := range embedded["properties"].(map[string]any) {
					props[k] = v
				}
				required = append(required, embedded["required"].([]string)...)
				continue
			}
			name := tag[0]
			if name == "" {
				name = f.Name
			}
			props[name] = typeSchema(f.Type)
			if len(tag) == 1 || !strings.Contains(strings.Join(tag[1:], ","), "omitempty") {
				required = append(required, name)
			}
		}
		for key, note := range fieldNotes(t) {
			if property, ok := props[key].(map[string]any); ok {
				property["description"] = note
			}
		}
		return map[string]any{"type": "object", "properties": props, "required": required}
	}
	return map[string]any{}
}

func fieldNotes(t reflect.Type) map[string]string {
	switch t {
	case reflect.TypeOf(view.Alert{}):
		return map[string]string{
			"occurrence_count": "Source-reported occurrence count; null means not supplied, not zero or one. May cover a source-defined lifetime, not the requested query window. Counts from different records/scopes may overlap; not an attack count.",
			"occurrence_scope": "Source-specific meaning of occurrence_count. Equal scope labels alone do not establish non-overlap or cross-product comparability.",
		}
	case reflect.TypeOf(model.Coverage{}):
		return map[string]string{
			"complete":          "Mechanical collection check: bounded request within saved source query bounds, enabled account and healthy sync without unresolved mapping failures. Not an event-delivery guarantee, usability score or security verdict.",
			"snapshot_sequence": "Pins observed matching Findings only. Collection metadata describes current saved sync state.",
		}
	case reflect.TypeOf(model.AccountCoverage{}):
		return map[string]string{
			"coverage_start":            "Start bound of the first successfully completed source query window. Not MIN(event_time), not a finding cursor or oldest retained event.",
			"watermark":                 "End bound of the last fully completed source query window; read together with time_basis and limitations.",
			"observed_events":           "Count and event_time bounds of matching stored Findings at snapshot_sequence. Null bounds for no known event times; empty results do not establish collection coverage.",
			"outside_completed_windows": "Requested timestamp bounds outside the completed source query envelope. Durations are not missing-event counts or percentages; source time_basis may differ from query time_field.",
			"pending_window":            "Source query window not yet fully paged and committed. Null if no pending window is recorded. Source pagination tokens are never returned.",
		}
	case reflect.TypeOf(model.FieldDistribution{}):
		return map[string]string{
			"distinct_count": "Distinct nonempty exact field values (day/severity tuples for severity_day), not distinct object identities.",
			"missing_count":  "Matching Findings where this field is absent or the empty string. Whitespace and case are preserved.",
			"top":            "Ordered by count descending, then exact key and severity ascending for ties. Source IP uses the explicit source_ip field, not all IP observables.",
			"other_count":    "Findings with nonempty values outside the returned top list. top counts + other_count + missing_count = statistics.total.",
		}
	case reflect.TypeOf(model.AlertGroup{}):
		return map[string]string{
			"finding_count": "Number of member Findings, not revision count or attack occurrence count.",
			"max_severity":  "Maximum source-mapped display severity among group members; not a new risk assessment.",
			"top_titles":    "Up to five source title samples with exact counts; not a complete title inventory.",
		}
	}
	return nil
}

// compactFields provides shallow discovery; full nested structure is opt-in.
func compactFields(schema map[string]any) map[string]string {
	props, _ := schema["properties"].(map[string]any)
	out := map[string]string{}
	for name, value := range props {
		p, _ := value.(map[string]any)
		kind, _ := p["type"].(string)
		if kind == "" {
			kind = "nullable or source-defined; see --schema"
		}
		out[name] = kind
	}
	return out
}
