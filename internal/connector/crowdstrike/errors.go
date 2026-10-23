package crowdstrike

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
)

// apiError classifies an HTTP failure. Falcon returns a structured errors
// array; the numeric code is used when present, otherwise the HTTP status
// alone decides retryability.
func apiError(status int, body []byte, api string) error {
	code := "cs_" + strconv.Itoa(status)
	message := ""
	var payload struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(body, &payload) == nil {
		if len(payload.Errors) > 0 {
			if payload.Errors[0].Code != 0 {
				code = "cs_" + strconv.Itoa(payload.Errors[0].Code)
			}
			message = payload.Errors[0].Message
		}
		if payload.Error != "" {
			code = sanitizeCode(payload.Error)
			message = payload.ErrorDescription
		}
	}
	return &connector.Error{
		Provider: providerID, SourceAPI: api, HTTPStatus: status,
		Kind: httpKind(status), Code: code, Message: truncate(message),
	}
}

// apiErrors handles a 200 response that still carries a structured error.
func apiErrors(code int, message string) error {
	return &connector.Error{
		Provider: providerID, SourceAPI: "Falcon Alerts v2", Kind: connector.KindPermanent,
		Code: "cs_" + strconv.Itoa(code), Message: truncate(message),
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
		return "cs_error"
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
		return "cs_error"
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
