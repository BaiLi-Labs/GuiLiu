package defender

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
)

// graphError classifies Microsoft Graph failures. Graph reports authorization
// problems as 403 with a precise code, so the code is preserved and the kind
// tells the operator whether consent or a role assignment is missing.
func graphError(status int, body []byte) error {
	code := "graph_" + http.StatusText(status)
	message := ""
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil {
		if payload.Error.Code != "" {
			code = sanitizeCode(payload.Error.Code)
		}
		message = payload.Error.Message
	}
	return &connector.Error{
		Provider: providerID, SourceAPI: "Graph alerts_v2", HTTPStatus: status,
		Kind: httpKind(status, code), Code: code, Message: truncate(message),
	}
}

func httpKind(status int, code string) connector.ErrorKind {
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
	}
	switch strings.ToLower(code) {
	case "invalidauthenticationtoken", "expiredauthenticationtoken", "unauthenticated":
		return connector.KindAuth
	case "authorization_requestdenied", "accessdenied", "forbidden":
		return connector.KindPermission
	}
	return connector.KindPermanent
}

func sanitizeCode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "graph_error"
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
		return "graph_error"
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
