package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"unicode"
)

var credentials = regexp.MustCompile(`(?i)(?:\bBearer\s+\S+|\bgl[ks]_[A-Za-z0-9_-]+|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bAKID[A-Za-z0-9]{24,}|\bLTAI[A-Za-z0-9]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]+|-----BEGIN[^\n]*PRIVATE KEY-----|(?:password|secret|token|credential)\s*[:=]\s*\S+)`)

// Text bounds and scrubs structured identifiers. Free text is fingerprinted
// separately; arbitrary request bodies and headers are never accepted here.
func Text(value string) string {
	if credentials.MatchString(value) {
		return "[redacted]"
	}
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > 512 {
		return string(runes[:512]) + "[truncated]"
	}
	return value
}

func fingerprint(v any) any {
	raw, _ := json.Marshal(v)
	return map[string]any{"redacted": true, "sha256": fmt.Sprintf("%x", sha256.Sum256(raw)), "bytes": len(raw)}
}

var parameterKeys = strings.Fields("top_by top_n provider account_id account_uid region resource_id resource_type resource asset_id alert_id rule_id product severity status vendor_status finding_kind time_field start end since range limit offset after_id cursor asset_snapshot_sequence vendor_title snapshot_sequence revision before_revision before_sequence group_by group_key src_ip dst_ip source_ip destination_ip ip asset alert_type observable_type observable_value sort component username enabled expires_in_days request_id user_id api_key_id surface operation tool outcome q keyword host user filters index id raw_hash routing")

func object(v reflect.Value) reflect.Value {
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}
func field(v reflect.Value, name string) reflect.Value {
	v = object(v)
	if !v.IsValid() {
		return reflect.Value{}
	}
	if v.Kind() == reflect.Map && v.Type().Key().Kind() == reflect.String {
		return object(v.MapIndex(reflect.ValueOf(name).Convert(v.Type().Key())))
	}
	if v.Kind() == reflect.Struct {
		typ := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if strings.Split(typ.Field(i).Tag.Get("json"), ",")[0] == name && typ.Field(i).IsExported() {
				return object(v.Field(i))
			}
		}
	}
	return reflect.Value{}
}
func scalar(v reflect.Value) any {
	v = object(v)
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.String:
		return Text(v.String())
	case reflect.Bool:
		return v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint()
	case reflect.Float32, reflect.Float64:
		return v.Float()
	}
	return nil
}
func paramValue(v reflect.Value) any {
	v = object(v)
	if !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Slice || v.Kind() == reflect.Array {
		out := []any{}
		for i := 0; i < v.Len() && i < 8; i++ {
			out = append(out, scalar(v.Index(i)))
		}
		if v.Len() > 8 {
			out = append(out, "[truncated]")
		}
		return out
	}
	return scalar(v)
}

// Parameters is an allowlist, not a recursive dump with a few secret keys removed.
// Keywords and group objects can contain arbitrary source text, so retain only
// their fingerprints. Structured IP/asset/time filters remain directly readable.
func Parameters(input any) map[string]any {
	out := map[string]any{}
	root := reflect.ValueOf(input)
	for _, key := range parameterKeys {
		v := field(root, key)
		if !v.IsValid() {
			continue
		}
		if key == "q" || key == "keyword" || key == "vendor_title" || key == "group_key" || key == "filters" || key == "host" || key == "user" || key == "routing" || (key == "cursor" && v.Kind() == reflect.String) {
			out[key] = fingerprint(v.Interface())
			continue
		}
		if value := paramValue(v); value != nil {
			out[key] = value
		}
	}
	return bounded(out, 16384)
}

func bounded(v map[string]any, max int) map[string]any {
	raw, err := json.Marshal(v)
	if err != nil {
		return map[string]any{"omitted": "unsupported_value"}
	}
	if len(raw) > max {
		return map[string]any{"omitted": "size_limit", "sha256": fmt.Sprintf("%x", sha256.Sum256(raw))}
	}
	return v
}

// Summary records result references and counters, never record bodies. Entries
// are capped and explicitly marked if a large result cannot be fully listed.
func Summary(input any) map[string]any {
	out := map[string]any{}
	root := reflect.ValueOf(input)
	for _, key := range strings.Fields("id alert_id asset_id revision sequence raw_hash total has_more asset_snapshot_sequence snapshot_sequence next_cursor status cache_seconds") {
		if value := scalar(field(root, key)); value != nil {
			out[key] = value
		}
	}
	for _, key := range strings.Fields("alerts assets changes groups accounts revisions events") {
		list := field(root, key)
		if !list.IsValid() || list.Kind() != reflect.Slice {
			continue
		}
		items := []map[string]any{}
		for i := 0; i < list.Len() && i < 200; i++ {
			entry := map[string]any{}
			for _, name := range strings.Fields("id alert_id asset_id revision sequence raw_hash resource_id count finding_count") {
				if value := scalar(field(list.Index(i), name)); value != nil {
					entry[name] = value
				}
			}
			if key := field(list.Index(i), "key"); key.IsValid() {
				entry["group_key"] = fingerprint(key.Interface())
			}
			if key == "events" {
				ref := map[string]any{}
				for _, name := range strings.Fields("account_id index id raw_hash") {
					if value := scalar(field(field(list.Index(i), "evidence"), name)); value != nil {
						ref[name] = value
					}
				}
				entry["evidence"] = ref
			}
			items = append(items, entry)
		}
		out[key] = map[string]any{"returned_count": list.Len(), "references": items, "truncated": list.Len() > 200}
	}
	for _, key := range strings.Fields("api_key asset account alert event user attempt refresh") {
		v := field(root, key)
		if !v.IsValid() {
			continue
		}
		ref := map[string]any{}
		for _, name := range strings.Fields("id user_id asset_id alert_id resource_id revision raw_hash status") {
			if value := scalar(field(v, name)); value != nil {
				ref[name] = value
			}
		}
		if len(ref) > 0 {
			out[key] = ref
		}
	}
	if code := scalar(field(field(root, "error"), "code")); code != nil {
		out["error_code"] = code
	}
	return bounded(out, 65536)
}
