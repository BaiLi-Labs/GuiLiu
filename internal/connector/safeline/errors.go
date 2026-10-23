package safeline

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
)

// safelineHTTPError classifies transport failures. The appliance uses plain
// HTTP status codes, so the mapping is direct and never depends on prose.
func safelineHTTPError(status int, body []byte) error {
	kind := connector.KindPermanent
	switch {
	case status == http.StatusUnauthorized:
		kind = connector.KindAuth
	case status == http.StatusForbidden:
		kind = connector.KindPermission
	case status == http.StatusNotFound:
		kind = connector.KindNotFound
	case status == http.StatusTooManyRequests:
		kind = connector.KindThrottled
	case status == http.StatusRequestTimeout || status >= 500:
		kind = connector.KindTransient
	}
	message := ""
	var envelope struct {
		Err *string `json:"err"`
		Msg any     `json:"msg"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.Err != nil {
		message = *envelope.Err
	}
	return &connector.Error{
		Provider: providerID, SourceAPI: "FilterV2API", HTTPStatus: status,
		Kind: kind, Code: httpCode(status), Message: truncate(message),
	}
}

// safelineAPIError classifies a business error returned inside HTTP 200.
func safelineAPIError(code string, data, msg json.RawMessage) error {
	text := strings.TrimSpace(code)
	lower := strings.ToLower(text)
	kind := connector.KindPermanent
	switch {
	case strings.Contains(lower, "unauthorized"), strings.Contains(lower, "token"), strings.Contains(lower, "auth"):
		kind = connector.KindAuth
	case strings.Contains(lower, "permission"), strings.Contains(lower, "forbidden"), strings.Contains(lower, "denied"):
		kind = connector.KindPermission
	case strings.Contains(lower, "not_found"), strings.Contains(lower, "not found"):
		kind = connector.KindNotFound
	case isParameterErrorText(lower):
		kind = connector.KindPermanent
	}
	return &connector.Error{
		Provider: providerID, SourceAPI: "FilterV2API", Kind: kind,
		Code: "api_error", Message: truncate(text + " " + messageText(msg, data)),
	}
}

func isParameterErrorText(lower string) bool {
	return strings.Contains(lower, "invalid_param") ||
		strings.Contains(lower, "invalid_filter_key") ||
		strings.Contains(lower, "unknown parameter") ||
		strings.Contains(lower, "unexpected parameter")
}

func messageText(msg, data json.RawMessage) string {
	var text string
	if json.Unmarshal(msg, &text) == nil && text != "" {
		return text
	}
	var object struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(msg, &object) == nil && object.Text != "" {
		return object.Text
	}
	if len(data) > 0 && len(data) < 512 {
		return string(data)
	}
	return ""
}

func httpCode(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "http_401"
	case http.StatusForbidden:
		return "http_403"
	case http.StatusNotFound:
		return "http_404"
	case http.StatusTooManyRequests:
		return "http_429"
	default:
		return "http_error"
	}
}

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
