package mcp

import (
	"encoding/json"
	"fmt"
)

// Validate the small schema vocabulary used by our tools before any handler
// runs. Defaults remain in handlers; required fields never acquire defaults.
func validateToolArgs(schema map[string]any, args map[string]any) error {
	for _, name := range requiredNames(schema["required"]) {
		if _, ok := args[name]; !ok {
			return fmt.Errorf("%s is required", name)
		}
	}
	props, _ := schema["properties"].(map[string]any)
	for name, value := range args {
		p, ok := props[name].(map[string]any)
		if !ok {
			return fmt.Errorf("unsupported argument: %s", name)
		}
		if err := validateValue(name, value, p); err != nil {
			return err
		}
	}
	return nil
}

func requiredNames(value any) []string {
	if names, ok := value.([]string); ok {
		return names
	}
	return nil
}

func validateValue(name string, value any, schema map[string]any) error {
	switch schema["type"] {
	case "string":
		text, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s must be a string", name)
		}
		if choices, ok := schema["enum"].([]string); ok {
			found := false
			for _, choice := range choices {
				if text == choice {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("invalid %s", name)
			}
		}
	case "integer":
		switch value.(type) {
		case json.Number, float64, int, int64:
		default:
			return fmt.Errorf("%s must be an integer", name)
		}
		n, err := parseInteger(value)
		if err != nil {
			return fmt.Errorf("%s must be an integer", name)
		}
		for bound, low := range map[string]bool{"minimum": true, "maximum": false} {
			if raw, exists := schema[bound]; exists {
				limit, e := parseInteger(raw)
				if e != nil {
					return fmt.Errorf("invalid schema for %s", name)
				}
				if low && n < limit || !low && n > limit {
					return fmt.Errorf("%s is outside its allowed range", name)
				}
			}
		}
	case "object":
		values, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be an object", name)
		}
		if child, ok := schema["additionalProperties"].(map[string]any); ok {
			for key, v := range values {
				if err := validateValue(name+"."+key, v, child); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
