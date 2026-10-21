package connector

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ReadSourceBody rejects oversized/truncated JSON rather than silently keeping
// a partial source record. RawMessage extraction preserves unknown properties
// and exact number spellings before any SDK model is involved.
func ReadSourceBody(r io.Reader) (json.RawMessage, error) {
	const max = 64 << 20
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if len(data) > max {
		return nil, fmt.Errorf("source response exceeds 64 MiB")
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("source response is not complete JSON")
	}
	return data, nil
}

// SourceScalar returns the first explicitly present string or number at the
// supplied JSON pointers. Missing fields remain unknown, including SDK enum
// fields that would otherwise take a default value when absent.
func SourceScalar(raw json.RawMessage, pointers ...string) string {
	for _, pointer := range pointers {
		value := raw
		for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
			var object map[string]json.RawMessage
			if json.Unmarshal(value, &object) != nil {
				value = nil
				break
			}
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			value = object[part]
		}
		var text string
		if json.Unmarshal(value, &text) == nil && text != "" {
			return text
		}
		var number json.Number
		if json.Unmarshal(value, &number) == nil && number != "" {
			return number.String()
		}
	}
	return ""
}
