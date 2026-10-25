// Package cloudwalker implements the Chaitin CloudWalker (牧云) host security
// event connector.
//
// Contract source: the generated chaitin-cli sources (GPL-3.0, read as an
// interface reference only, no code copied):
//   - POST {endpoint}, JSON-RPC 2.0, Cookie API-Token=<key>
//   - one RPC method per event family, all named <Family>Service.GetEventList
//   - params count / offset / created_at []string / level []int
//
// Two things are NOT defined by the public sources and are therefore handled
// defensively:
//   - created_at element format; the CLI only forwards strings without
//     validating them, so time_format is a configuration knob
//   - the reply container name; replies are decoded into map[string]any and
//     formatted generically, so the container is discovered at runtime
//
// Alerts carry mapping_unverified until a real response is compared.
package cloudwalker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const (
	providerID    = "cloudwalker"
	mapperVersion = "cloudwalker-event/v0-unverified"
	apiVersion    = "jsonrpc-2.0"
	defaultQPS    = 2
	defaultPage   = 100
	defaultEvent  = "webshell_event"
)

// eventServices maps the CLI event family to its confirmed RPC service name.
var eventServices = map[string]string{
	"webshell_event":        "WebshellEventService",
	"memory_webshell_event": "MemoryWebshellEventService",
	"malware_event":         "MalwareEventService",
	"brute_force":           "BruteForceService",
	"port_scan":             "PortScanService",
	"abnormal_login_event":  "AbnormalLoginEventService",
	"revshell_event":        "RevshellEventService",
	"suspicious_operation":  "SuspiciousOperationService",
}

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "CloudWalker <Family>Service.GetEventList",
		ID:            providerID,
		Name:          "Chaitin CloudWalker",
		Vendor:        "Chaitin",
		Product:       "CloudWalker (牧云)",
		ProductUID:    "chaitin.cloudwalker",
		APIVersion:    apiVersion,
		DocsURL:       "https://github.com/chaitin/chaitin-cli/tree/main/products/cloudwalker",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "API Key", Required: true, Secret: true, Help: "以 Cookie API-Token 发送"},
		},
		OptionFields: []connector.OptionField{
			{Name: "endpoint", Label: "RPC endpoint", Required: true, Placeholder: "https://cloudwalker.example.com/rpc", Help: "自动补 /rpc 后缀"},
			{Name: "event_type", Label: "Event family", Placeholder: defaultEvent, Help: "每个账号仅采集一种事件，默认 webshell_event。采集多类事件请分别建账号。可选 webshell_event / memory_webshell_event / malware_event / brute_force / port_scan / abnormal_login_event / revshell_event / suspicious_operation"},
			{Name: "time_format", Label: "created_at format", Placeholder: "datetime", Help: "公开源码只透传字符串。可选 datetime（2006-01-02 15:04:05）、rfc3339、epoch_ms、epoch_s"},
			{Name: "insecure", Label: "Skip TLS verification", Placeholder: "false"},
		},
		Products: []connector.Product{
			{Code: "HostEvent", Name: "Host security events"},
		},
	}
}

// Connector reads one CloudWalker event family.
type Connector struct {
	endpoint   string
	token      string
	eventType  string
	service    string
	timeFormat string
	limiter    *connector.Limiter
	pageSize   int
	client     *http.Client
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Options["endpoint"]), "/")
	if endpoint == "" {
		return nil, connector.ConfigError(providerID, "endpoint is required")
	}
	if !strings.HasSuffix(endpoint, "/rpc") {
		endpoint += "/rpc"
	}
	token := strings.TrimSpace(cfg.Credential.AccessKeyID)
	if token == "" {
		return nil, connector.ConfigError(providerID, "API key is required")
	}
	eventType := strings.TrimSpace(cfg.Options["event_type"])
	if eventType == "" {
		eventType = defaultEvent
	}
	service, ok := eventServices[eventType]
	if !ok {
		return nil, connector.ConfigError(providerID, "unsupported event_type: "+eventType)
	}
	timeFormat := strings.ToLower(strings.TrimSpace(cfg.Options["time_format"]))
	switch timeFormat {
	case "", "datetime":
		timeFormat = "datetime"
	case "rfc3339", "epoch_ms", "epoch_s":
	default:
		return nil, connector.ConfigError(providerID, "time_format must be datetime, rfc3339, epoch_ms or epoch_s")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.EqualFold(strings.TrimSpace(cfg.Options["insecure"]), "true") {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Connector{
		endpoint:   endpoint,
		token:      token,
		eventType:  eventType,
		service:    service,
		timeFormat: timeFormat,
		limiter:    connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize:   connector.OptionInt(cfg.Options, "page_size", defaultPage),
		client:     &http.Client{Timeout: 60 * time.Second, Transport: transport},
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

func (c *Connector) Check(ctx context.Context) error {
	end := time.Now().UTC()
	_, err := c.Fetch(ctx, connector.Query{Start: end.Add(-1 * time.Hour), End: end, PageSize: 1})
	return err
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
	ID      string `json:"id"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
	ID      string          `json:"id"`
}

func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = c.pageSize
	}
	if pageSize > 500 {
		pageSize = 500
	}
	offset := 0
	if token := strings.TrimSpace(q.Token); token != "" {
		parsed, err := strconv.Atoi(token)
		if err != nil || parsed < 0 {
			return connector.Page{}, connector.ConfigError(providerID, "invalid page token")
		}
		offset = parsed
	}

	result, err := c.list(ctx, q, offset, pageSize)
	if err != nil {
		return connector.Page{}, err
	}
	items, total, err := extractEvents(result)
	if err != nil {
		return connector.Page{}, err
	}
	records := make([]connector.RawAlert, 0, len(items))
	for _, raw := range items {
		if len(raw) == 0 || string(raw) == "null" {
			return connector.Page{}, fmt.Errorf("cloudwalker returned an empty event")
		}
		records = append(records, connector.RawAlert{Raw: append(json.RawMessage(nil), raw...)})
	}
	more := len(records) > 0
	if total > 0 {
		more = more && offset+len(records) < total
	} else {
		more = more && len(records) >= pageSize
	}
	next := ""
	if more {
		next = strconv.Itoa(offset + len(records))
	}
	pageTotal := total
	if pageTotal == 0 {
		pageTotal = len(records)
	}
	return connector.Page{Records: records, NextToken: next, Total: pageTotal}, nil
}

func (c *Connector) list(ctx context.Context, q connector.Query, offset, count int) (json.RawMessage, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	params := map[string]any{
		"count":      count,
		"offset":     offset,
		"created_at": []string{c.timeValue(q.Start), c.timeValue(q.End)},
	}
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  c.service + ".GetEventList",
		Params:  params,
		ID:      strconv.FormatInt(time.Now().UnixNano(), 10),
	})
	if err != nil {
		return nil, fmt.Errorf("encode cloudwalker request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, connector.ConfigError(providerID, "invalid endpoint: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: "API-Token", Value: c.token})
	req.Header.Set("User-Agent", "GuiLiu/"+mapperVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, connector.WithSourceAPI(providerID, c.service+".GetEventList", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, connector.WithSourceAPI(providerID, c.service+".GetEventList", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, httpError(resp.StatusCode, payload)
	}
	var envelope rpcResponse
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("decode cloudwalker response: %w", err)
	}
	if envelope.Error != nil {
		return nil, rpcErrorOf(envelope.Error)
	}
	return envelope.Result, nil
}

func (c *Connector) timeValue(t time.Time) string {
	t = t.UTC()
	switch c.timeFormat {
	case "rfc3339":
		return t.Format(time.RFC3339)
	case "epoch_ms":
		return strconv.FormatInt(t.UnixMilli(), 10)
	case "epoch_s":
		return strconv.FormatInt(t.Unix(), 10)
	default:
		return t.Format("2006-01-02 15:04:05")
	}
}

// extractEvents discovers the reply container. CloudWalker replies are decoded
// into map[string]any and printed generically, so no schema is published.
func extractEvents(result json.RawMessage) ([]json.RawMessage, int, error) {
	if len(result) == 0 || string(result) == "null" {
		return nil, 0, nil
	}
	var items []json.RawMessage
	if json.Unmarshal(result, &items) == nil {
		return items, 0, nil // A bare page does not declare the full result count.
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(result, &object); err != nil {
		return nil, 0, fmt.Errorf("decode cloudwalker result: %w", err)
	}
	total := extractTotal(object)
	containers := []string{"data", "list", "events", "items", "records", "event_list"}
	for _, key := range containers {
		raw, ok := object[key]
		if !ok || len(raw) == 0 {
			continue
		}
		if json.Unmarshal(raw, &items) == nil {
			return items, total, nil
		}
		var nested map[string]json.RawMessage
		if json.Unmarshal(raw, &nested) == nil {
			if total == 0 {
				total = extractTotal(nested)
			}
			for _, inner := range containers {
				if value, ok := nested[inner]; ok {
					if json.Unmarshal(value, &items) == nil {
						return items, total, nil
					}
				}
			}
		}
	}
	return nil, 0, fmt.Errorf("unrecognized cloudwalker event result shape; update extractEvents with the real response container")
}

func extractTotal(object map[string]json.RawMessage) int {
	for _, key := range []string{"total", "total_count", "total_items"} {
		raw, ok := object[key]
		if !ok {
			continue
		}
		var number json.Number
		if json.Unmarshal(raw, &number) == nil {
			if parsed, err := strconv.Atoi(number.String()); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalize(raw, c.eventType)
}
