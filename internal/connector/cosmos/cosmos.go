// Package cosmos implements the Chaitin Cosmos / AISOC alarm connector.
//
// Contract source: the published chaitin-cli API definitions
// (products/cosmos/apis/alarm.json, GPL-3.0, read as an interface reference
// only, no code copied):
//   - POST {base}/pedestal/rpc, JSON-RPC 2.0
//   - Authorization: Bearer <JWT>, no prefix in the stored value
//   - params are named (no paramStyle array wrapping)
//   - AlarmService.GetAlarmList takes created_at as a millisecond range
//     string, plus count / offset
//
// The definition file declares an empty reply object, so the response shape is
// NOT part of the public contract. This connector therefore discovers the
// pagination container defensively and marks every normalized alert with
// mapping_unverified, so operators do not mistake a guessed field for a
// confirmed one. Replace the probe list with the real shape once a sample is
// available.
package cosmos

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
	providerID    = "cosmos"
	mapperVersion = "cosmos-alarm/v0-unverified"
	apiVersion    = "jsonrpc-2.0"
	rpcPath       = "/pedestal/rpc"
	alarmMethod   = "AlarmService.GetAlarmList"

	defaultQPS      = 2
	defaultPageSize = 100
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "AlarmService.GetAlarmList",
		ID:            providerID,
		Name:          "Chaitin Cosmos",
		Vendor:        "Chaitin",
		Product:       "Cosmos / AISOC",
		ProductUID:    "chaitin.cosmos",
		APIVersion:    apiVersion,
		DocsURL:       "https://github.com/chaitin/chaitin-cli/tree/main/products/cosmos",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "API Key (JWT)", Required: true, Secret: true, Help: "请求头为 Authorization: Bearer，Token 原文不要带 Bearer 前缀"},
		},
		OptionFields: []connector.OptionField{
			{Name: "endpoint", Label: "Cosmos URL", Required: true, Placeholder: "https://cosmos.example.com", Help: "不含 /pedestal/rpc 路径"},
			{Name: "insecure", Label: "Skip TLS verification", Placeholder: "false", Help: "仅自签证书环境使用"},
			{Name: "severity_from_level", Label: "Derive severity from alarm_level", Placeholder: "false", Help: "alarm_level 语义未在公开定义中写明。开启后按 1=critical..4=low 推导并标记为推导值"},
		},
		Products: []connector.Product{
			{Code: "Alarm", Name: "Unified alarms"},
		},
	}
}

// Connector talks to the Cosmos JSON-RPC endpoint.
type Connector struct {
	endpoint     string
	token        string
	severityFrom bool
	limiter      *connector.Limiter
	pageSize     int
	client       *http.Client
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Options["endpoint"]), "/")
	if endpoint == "" {
		return nil, connector.ConfigError(providerID, "endpoint is required")
	}
	token := strings.TrimSpace(cfg.Credential.AccessKeyID)
	if token == "" {
		return nil, connector.ConfigError(providerID, "API key is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.EqualFold(strings.TrimSpace(cfg.Options["insecure"]), "true") {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Connector{
		endpoint:     endpoint,
		token:        token,
		severityFrom: strings.EqualFold(strings.TrimSpace(cfg.Options["severity_from_level"]), "true"),
		limiter:      connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize:     connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
		client:       &http.Client{Timeout: 60 * time.Second, Transport: transport},
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
	if pageSize > 1000 {
		pageSize = 1000
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
	items, total, err := extractAlarms(result)
	if err != nil {
		return connector.Page{}, err
	}
	records := make([]connector.RawAlert, 0, len(items))
	for _, raw := range items {
		if len(raw) == 0 || string(raw) == "null" {
			return connector.Page{}, fmt.Errorf("cosmos returned an empty alarm")
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
	// The list method requires created_at or updated_at; the value is a
	// millisecond range string.
	params := map[string]any{
		"created_at": fmt.Sprintf("%d-%d", q.Start.UTC().UnixMilli(), q.End.UTC().UnixMilli()),
		"count":      count,
		"offset":     offset,
	}
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  alarmMethod,
		Params:  params,
		ID:      strconv.FormatInt(time.Now().UnixNano(), 10),
	})
	if err != nil {
		return nil, fmt.Errorf("encode cosmos request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+rpcPath, bytes.NewReader(body))
	if err != nil {
		return nil, connector.ConfigError(providerID, "invalid endpoint: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("User-Agent", "GuiLiu/"+mapperVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, connector.WithSourceAPI(providerID, "AlarmService.GetAlarmList", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, connector.WithSourceAPI(providerID, "AlarmService.GetAlarmList", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, httpError(resp.StatusCode, payload)
	}
	var envelope rpcResponse
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("decode cosmos response: %w", err)
	}
	if envelope.Error != nil {
		return nil, rpcErrorOf(envelope.Error)
	}
	return envelope.Result, nil
}

// extractAlarms discovers the pagination container. The public definition
// declares reply as an empty object, so the container name is unknown; the
// probes cover the shapes used by Chaitin's other services. An unrecognized
// shape is an error rather than an empty page, because silently reporting "no
// alarms" is the worst possible failure mode.
func extractAlarms(result json.RawMessage) ([]json.RawMessage, int, error) {
	if len(result) == 0 || string(result) == "null" {
		return nil, 0, nil
	}
	var items []json.RawMessage
	if json.Unmarshal(result, &items) == nil {
		return items, 0, nil // A bare page does not declare the full result count.
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(result, &object); err != nil {
		return nil, 0, fmt.Errorf("decode cosmos result: %w", err)
	}
	containers := []string{"data", "list", "alarms", "items", "records", "alarm_list", "result"}
	total := extractTotal(object)
	for _, key := range containers {
		raw, ok := object[key]
		if !ok || len(raw) == 0 {
			continue
		}
		if json.Unmarshal(raw, &items) == nil {
			return items, totalOrNested(total, raw), nil
		}
		var nested map[string]json.RawMessage
		if json.Unmarshal(raw, &nested) == nil {
			innerTotal := extractTotal(nested)
			for _, inner := range containers {
				if value, ok := nested[inner]; ok {
					if json.Unmarshal(value, &items) == nil {
						if total == 0 {
							total = innerTotal
						}
						return items, total, nil
					}
				}
			}
		}
	}
	return nil, 0, fmt.Errorf("unrecognized cosmos alarm result shape; update extractAlarms with the real response container")
}

// extractTotal only trusts explicit total fields. "count" is the page-size
// request parameter and may also mean "items in this page" in a reply, so
// treating it as a grand total would end pagination early.
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

func totalOrNested(total int, raw json.RawMessage) int {
	if total > 0 {
		return total
	}
	var nested map[string]json.RawMessage
	if json.Unmarshal(raw, &nested) == nil {
		return extractTotal(nested)
	}
	return 0
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalize(raw, c.severityFrom)
}
