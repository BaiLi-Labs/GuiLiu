// Package pushwire parses transport envelopes used by security products that
// push records instead of exposing a polling API: syslog (RFC 5424 / RFC 3164)
// and CEF. Parsing is transport-level only; it never assigns vendor semantics.
package pushwire

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Message is one decoded syslog frame.
type Message struct {
	Facility       int    `json:"facility"`
	Severity       int    `json:"severity"`
	Version        int    `json:"version,omitempty"`
	Timestamp      string `json:"timestamp,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	AppName        string `json:"app_name,omitempty"`
	ProcID         string `json:"proc_id,omitempty"`
	MsgID          string `json:"msg_id,omitempty"`
	StructuredData string `json:"structured_data,omitempty"`
	Message        string `json:"message"`
	Legacy         bool   `json:"legacy,omitempty"`
}

var rfc3164Head = regexp.MustCompile(`^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s?(.*)$`)
var rfc3164Tag = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9_.\-/]*)(\[\d+\])?:\s?(.*)$`)

// ParseSyslog decodes an RFC 5424 or RFC 3164 frame. It returns an error only
// when the frame has no valid priority field, because an unrecognizable body is
// still a legitimate message from an unknown appliance.
func ParseSyslog(raw []byte) (Message, error) {
	text := strings.TrimRight(string(raw), "\r\n")
	if len(text) == 0 {
		return Message{}, fmt.Errorf("empty syslog frame")
	}
	if text[0] != '<' {
		return Message{}, fmt.Errorf("syslog frame missing priority")
	}
	end := strings.IndexByte(text, '>')
	if end < 2 || end > 4 {
		return Message{}, fmt.Errorf("syslog frame has an invalid priority")
	}
	pri, err := strconv.Atoi(text[1:end])
	if err != nil || pri < 0 || pri > 191 {
		return Message{}, fmt.Errorf("syslog frame has an invalid priority")
	}
	msg := Message{Facility: pri / 8, Severity: pri % 8}
	rest := text[end+1:]
	if rest == "" {
		return msg, nil
	}
	if isRFC5424Version(rest) {
		parseRFC5424(rest, &msg)
		return msg, nil
	}
	parseRFC3164(rest, &msg)
	return msg, nil
}

func isRFC5424Version(s string) bool {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i > 0 && i <= 2 && i < len(s) && s[i] == ' '
}

func parseRFC5424(s string, msg *Message) {
	rest := s
	fields := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		idx := strings.IndexByte(rest, ' ')
		if idx < 0 {
			msg.Message = rest
			return
		}
		fields = append(fields, rest[:idx])
		rest = rest[idx+1:]
	}
	version, _ := strconv.Atoi(fields[0])
	msg.Version = version
	msg.Timestamp = nilValue(fields[1])
	msg.Hostname = nilValue(fields[2])
	msg.AppName = nilValue(fields[3])
	msg.ProcID = nilValue(fields[4])
	// rest is "MSGID [SD] MSG" or "MSGID - MSG".
	idx := strings.IndexByte(rest, ' ')
	if idx < 0 {
		msg.MsgID = nilValue(rest)
		return
	}
	msg.MsgID = nilValue(rest[:idx])
	msg.StructuredData, msg.Message = splitStructuredData(rest[idx+1:])
}

// splitStructuredData separates the SD element from MSG. A missing SD is the
// literal "-". Bracketed SD may contain spaces and escaped brackets.
func splitStructuredData(s string) (string, string) {
	s = strings.TrimLeft(s, " ")
	if s == "" {
		return "", ""
	}
	if s[0] == '-' {
		return "", strings.TrimLeft(s[1:], " ")
	}
	if s[0] != '[' {
		return "", s
	}
	depth := 0
	escaped := false
	for i := 0; i < len(s); i++ {
		switch {
		case escaped:
			escaped = false
		case s[i] == '\\':
			escaped = true
		case s[i] == '[':
			depth++
		case s[i] == ']':
			depth--
			if depth == 0 {
				return s[:i+1], strings.TrimLeft(s[i+1:], " ")
			}
		}
	}
	return s, ""
}

func parseRFC3164(s string, msg *Message) {
	msg.Legacy = true
	match := rfc3164Head.FindStringSubmatch(s)
	if match == nil {
		msg.Message = s
		return
	}
	msg.Timestamp = match[1] + " " + match[2] + " " + match[3]
	msg.Hostname = match[4]
	rest := match[5]
	if tag := rfc3164Tag.FindStringSubmatch(rest); tag != nil {
		msg.AppName = tag[1]
		if tag[2] != "" {
			msg.ProcID = strings.Trim(tag[2], "[]")
		}
		msg.Message = tag[3]
		return
	}
	msg.Message = rest
}

func nilValue(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// NormalizeTimestamp renders a syslog timestamp as RFC 3339 UTC when possible.
// RFC 3164 timestamps carry no year or zone; they are returned verbatim so the
// vendor mapper can decide instead of GuiLiu inventing a year.
func NormalizeTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC().Format(time.RFC3339Nano)
		}
	}
	return value
}
