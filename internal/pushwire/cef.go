package pushwire

import (
	"fmt"
	"strings"
)

// CEF is a decoded Common Event Format record. Header and extension values are
// kept verbatim; no field is renamed or dropped.
type CEF struct {
	Version       string            `json:"version"`
	DeviceVendor  string            `json:"device_vendor"`
	DeviceProduct string            `json:"device_product"`
	DeviceVersion string            `json:"device_version"`
	SignatureID   string            `json:"signature_id"`
	Name          string            `json:"name"`
	Severity      string            `json:"severity"`
	Extension     map[string]string `json:"extension"`
	Raw           string            `json:"raw"`
}

// ParseCEF decodes a CEF line. It accepts a line that starts with "CEF:" either
// at the beginning or after a syslog prefix.
func ParseCEF(line string) (CEF, error) {
	raw := strings.TrimRight(line, "\r\n")
	start := strings.Index(raw, "CEF:")
	if start < 0 {
		return CEF{}, fmt.Errorf("not a CEF record: missing CEF: prefix")
	}
	raw = raw[start:]
	body := raw[len("CEF:"):]
	header := make([]string, 0, 7)
	var rest string
	for len(header) < 7 {
		value, tail, ok := cutEscaped(body, '|')
		if !ok {
			return CEF{}, fmt.Errorf("CEF record has %d header fields, want 7", len(header))
		}
		header = append(header, unescapeCEF(value))
		body = tail
	}
	rest = body
	cef := CEF{
		Version:       header[0],
		DeviceVendor:  header[1],
		DeviceProduct: header[2],
		DeviceVersion: header[3],
		SignatureID:   header[4],
		Name:          header[5],
		Severity:      header[6],
		Extension:     parseExtension(rest),
		Raw:           raw,
	}
	return cef, nil
}

// cutEscaped splits s at the first unescaped separator.
func cutEscaped(s string, sep byte) (string, string, bool) {
	escaped := false
	for i := 0; i < len(s); i++ {
		switch {
		case escaped:
			escaped = false
		case s[i] == '\\':
			escaped = true
		case s[i] == sep:
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func unescapeCEF(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	escaped := false
	for i := 0; i < len(s); i++ {
		if escaped {
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			default:
				b.WriteByte(s[i])
			}
			escaped = false
			continue
		}
		if s[i] == '\\' {
			escaped = true
			continue
		}
		b.WriteByte(s[i])
	}
	if escaped {
		b.WriteByte('\\')
	}
	return b.String()
}

// parseExtension splits "k=v k2=v2" pairs. A CEF value may contain spaces, so a
// new pair starts only at a token that looks like key=.
func parseExtension(s string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(s) {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) {
			break
		}
		keyStart := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= len(s) || s[i] != '=' || i == keyStart {
			// Not a key/value pair; skip the token.
			for i < len(s) && s[i] != ' ' {
				i++
			}
			continue
		}
		key := s[keyStart:i]
		i++ // '='
		valueStart := i
		for i < len(s) {
			if s[i] == ' ' && looksLikePairStart(s[i+1:]) {
				break
			}
			i++
		}
		out[key] = unescapeCEF(s[valueStart:i])
	}
	return out
}

func looksLikePairStart(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '=':
			return i > 0
		case s[i] == ' ':
			return false
		}
	}
	return false
}
