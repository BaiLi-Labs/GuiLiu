package cloudflare

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
)

// httpError classifies a non-200 response. Cloudflare returns REST-shaped
// errors even from the GraphQL endpoint.
func httpError(status int, body []byte) error {
	code := "cf_" + strconv.Itoa(status)
	message := ""
	var payload struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil {
		if len(payload.Errors) > 0 {
			if payload.Errors[0].Code != 0 {
				code = "cf_" + strconv.Itoa(payload.Errors[0].Code)
			}
			message = payload.Errors[0].Message
		}
		if payload.Error != "" {
			code = sanitizeCode(payload.Error)
			message = payload.Error
		}
	}
	return &connector.Error{
		Provider: providerID, SourceAPI: "GraphQL firewallEventsAdaptive", HTTPStatus: status,
		Kind: httpKind(status), Code: code, Message: truncate(message),
	}
}

// graphQLErrorOf classifies an error delivered inside HTTP 200.
func graphQLErrorOf(err graphQLError) error {
	message := strings.TrimSpace(err.Message)
	lower := strings.ToLower(message)
	code := sanitizeCode(err.Extensions.Code)
	if code == "" {
		code = "graphql_error"
	}
	kind := connector.KindPermanent
	switch {
	case strings.Contains(lower, "authentication"), strings.Contains(lower, "unauthorized"),
		strings.Contains(lower, "invalid token"), strings.Contains(lower, "not logged in"):
		kind = connector.KindAuth
	case strings.Contains(lower, "not authorized"), strings.Contains(lower, "permission"),
		strings.Contains(lower, "forbidden"), strings.Contains(lower, "access denied"):
		kind = connector.KindPermission
	case strings.Contains(lower, "rate limit"), strings.Contains(lower, "too many requests"):
		kind = connector.KindThrottled
	}
	return &connector.Error{
		Provider: providerID, SourceAPI: "GraphQL firewallEventsAdaptive",
		Kind: kind, Code: code, Message: truncate(message),
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
		return ""
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
	return out
}

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
