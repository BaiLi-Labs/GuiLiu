package cli

import (
	"encoding/json"
	"reflect"
	"strings"
)

func (o *outputOptions) tableFields() string {
	if o.NDJSON {
		return ""
	}
	return o.Fields
}

func validateProjection(command, fields string) error {
	typ := ndjsonType(command)
	if typ == nil {
		return usagef("--ndjson field projection is not supported for %s", command)
	}
	seen := []string{}
	for _, raw := range strings.Split(fields, ",") {
		path := strings.TrimSpace(raw)
		current := typ
		for _, part := range strings.Split(path, ".") {
			for current.Kind() == reflect.Pointer {
				current = current.Elem()
			}
			if current.Kind() != reflect.Struct || part == "" {
				return usagef("unknown JSON field path %q; see --describe", path)
			}
			var next reflect.Type
			for i := 0; i < current.NumField(); i++ {
				field := current.Field(i)
				if field.IsExported() && part != "-" && strings.Split(field.Tag.Get("json"), ",")[0] == part {
					next = field.Type
					break
				}
			}
			if next == nil {
				return usagef("unknown JSON field path %q; see --describe", path)
			}
			current = next
		}
		for _, prev := range seen {
			if strings.HasPrefix(path, prev+".") || strings.HasPrefix(prev, path+".") {
				return usagef("overlapping JSON field paths %q and %q", prev, path)
			}
		}
		seen = append(seen, path)
	}
	return nil
}

// RawMessage keeps integers and evidence JSON intact through projection.
func projectJSON(data []byte, fields string) (map[string]any, error) {
	out := map[string]any{}
	for _, raw := range strings.Split(fields, ",") {
		parts := strings.Split(strings.TrimSpace(raw), ".")
		value := json.RawMessage(data)
		for _, part := range parts {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(value, &object); err != nil {
				return nil, err
			}
			value = object[part]
			if len(value) == 0 {
				value = json.RawMessage("null")
			}
		}
		object := out
		for _, part := range parts[:len(parts)-1] {
			next, ok := object[part].(map[string]any)
			if !ok {
				next = map[string]any{}
				object[part] = next
			}
			object = next
		}
		object[parts[len(parts)-1]] = value
	}
	return out, nil
}
