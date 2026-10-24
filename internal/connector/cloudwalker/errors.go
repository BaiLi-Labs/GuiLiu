package cloudwalker

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
		Error *rpcError `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Error != nil {
		code = "rpc_" + strconv.Itoa(payload.Error.Code)
		message = payload.Error.Message
	}
	return &connector.Error{
		Provider: providerID, SourceAPI: "GetEventList", HTTPStatus: status,
		Kind: httpKind(status), Code: code, Message: truncate(message),
	}
}

func rpcErrorOf(err *rpcError) error {
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(err.Message)
	lower := strings.ToLower(message)
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
		Provider: providerID, SourceAPI: "GetEventList",
		Kind: kind, Code: "rpc_" + strconv.Itoa(err.Code), Message: truncate(message),
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

func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
