package dsensor

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
)

func httpError(status int, body []byte) error {
	code := "http_" + strconv.Itoa(status)
	message := ""
	var payload struct {
		Err string `json:"err"`
		Msg string `json:"msg"`
	}
	if json.Unmarshal(body, &payload) == nil {
		if payload.Err != "" {
			code = sanitizeCode(payload.Err)
		}
		message = connector.FirstNonEmpty(payload.Msg, payload.Err)
	}
	return &connector.Error{
		Provider: providerID, SourceAPI: "event_alarm/list", HTTPStatus: status,
		Kind: httpKind(status), Code: code, Message: truncate(message),
	}
}

// apiError classifies a business error returned inside HTTP 200.
func apiError(code, message string) error {
	text := strings.TrimSpace(code)
	lower := strings.ToLower(text)
	kind := connector.KindPermanent
	switch {
	case strings.Contains(lower, "unauthorized"), strings.Contains(lower, "token"),
		strings.Contains(lower, "auth"), strings.Contains(lower, "login"):
		kind = connector.KindAuth
	case strings.Contains(lower, "permission"), strings.Contains(lower, "forbidden"),
		strings.Contains(lower, "denied"):
		kind = connector.KindPermission
	case strings.Contains(lower, "rate limit"), strings.Contains(lower, "too many"):
		kind = connector.KindThrottled
	}
	return &connector.Error{
		Provider: providerID, SourceAPI: "event_alarm/list",
		Kind: kind, Code: sanitizeCode(text), Message: truncate(connector.FirstNonEmpty(message, text)),
	}
}

func httpKind(status int) connector.ErrorKind {
	switch {
	case status == http.StatusUnauthorized:
		return connector.KindAuth
	case status == http.StatusForbidden:
		return connector.KindPermission
	case status == http.StatusNotFound:
		return connector.KindNotFound
	case status == http.StatusTooManyRequests:
		return connector.KindThrottled
	case status == http.StatusRequestTimeout || status >= 500:
		return connector.KindTransient
	default:
		return connector.KindPermanent
	}
}

func sanitizeCode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "api_error"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if len(out) > 100 {
		out = out[:100]
	}
	if out == "" {
		return "api_error"
	}
	return out
}

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
