// Package tanswer implements the Chaitin TAnswer (全悉) threat alert connector.
//
// Contract verified against the published chaitin-cli source (GPL-3.0, used as
// an interface reference only, no code copied):
//   - POST {base}/rpc, JSON-RPC 2.0, header Api-Token
//   - method AlarmService.SearchAlarmList
//   - params time_range_start / time_range_end in Unix milliseconds,
//     offset / count, save_history=false
//   - result {data:[...], total, page_total}
package tanswer

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
	providerID      = "tanswer"
	mapperVersion   = "tanswer-alarm/v1"
	apiVersion      = "jsonrpc-2.0"
	defaultQPS      = 2
	defaultPageSize = 100
	rpcPath         = "/rpc"
	alarmMethod     = "AlarmService.SearchAlarmList"
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "AlarmService.SearchAlarmList",
		ID:            providerID,
		Name:          "Chaitin TAnswer",
		Vendor:        "Chaitin",
		Product:       "TAnswer (全悉)",
		ProductUID:    "chaitin.tanswer",
		APIVersion:    apiVersion,
		DocsURL:       "https://github.com/chaitin/chaitin-cli/tree/main/products/tanswer",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "OpenAPI Token", Required: true, Secret: true, Help: "请求头为 Api-Token"},
		},
		OptionFields: []connector.OptionField{
			{Name: "endpoint", Label: "TAnswer URL", Required: true, Placeholder: "https://tanswer.example.com", Help: "不含 /rpc 路径"},
			{Name: "insecure", Label: "Skip TLS verification", Placeholder: "false"},
		},
		Products: []connector.Product{
			{Code: "Alarm", Name: "Threat alerts"},
		},
	}
}

// Connector talks to the TAnswer JSON-RPC endpoint.
type Connector struct {
	endpoint string
	token    string
	limiter  *connector.Limiter
	pageSize int
	client   *http.Client
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Options["endpoint"]), "/")
	if endpoint == "" {
		return nil, connector.ConfigError(providerID, "endpoint is required")
	}
	token := strings.TrimSpace(cfg.Credential.AccessKeyID)
	if token == "" {
		return nil, connector.ConfigError(providerID, "OpenAPI token is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.EqualFold(strings.TrimSpace(cfg.Options["insecure"]), "true") {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Connector{
		endpoint: endpoint,
		token:    token,
		limiter:  connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize: connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
		client:   &http.Client{Timeout: 60 * time.Second, Transport: transport},
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
	if pageSize > 100 {
		pageSize = 100
	}
	offset := 0
	if token := strings.TrimSpace(q.Token); token != "" {
		parsed, err := strconv.Atoi(token)
		if err != nil || parsed < 0 {
			return connector.Page{}, connector.ConfigError(providerID, "invalid page token")
		}
		offset = parsed
	}

	result, err := c.search(ctx, q, offset, pageSize)
	if err != nil {
		return connector.Page{}, err
	}
	records := make([]connector.RawAlert, 0, len(result.Data))
	for _, raw := range result.Data {
		if len(raw) == 0 || string(raw) == "null" {
			return connector.Page{}, fmt.Errorf("tanswer returned an empty alarm")
		}
		records = append(records, connector.RawAlert{Raw: append(json.RawMessage(nil), raw...)})
	}
	next := ""
	if offset+len(records) < result.Total && len(records) > 0 {
		next = strconv.Itoa(offset + len(records))
	}
	return connector.Page{Records: records, NextToken: next, Total: result.Total}, nil
}

type alarmResult struct {
	Data  []json.RawMessage `json:"data"`
	Total int               `json:"total"`
}

func (c *Connector) search(ctx context.Context, q connector.Query, offset, count int) (alarmResult, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return alarmResult{}, err
	}
	params := map[string]any{
		"time_range_start": q.Start.UTC().UnixMilli(),
		"time_range_end":   q.End.UTC().UnixMilli(),
		"offset":           offset,
		"count":            count,
		"save_history":     false,
	}
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		Method:  alarmMethod,
		Params:  params,
		ID:      strconv.FormatInt(time.Now().UnixNano(), 10),
	})
	if err != nil {
		return alarmResult{}, fmt.Errorf("encode tanswer request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+rpcPath, bytes.NewReader(body))
	if err != nil {
		return alarmResult{}, connector.ConfigError(providerID, "invalid endpoint: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Api-Token", c.token)
	req.Header.Set("User-Agent", "GuiLiu/"+mapperVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return alarmResult{}, connector.WithSourceAPI(providerID, "AlarmService.SearchAlarmList", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return alarmResult{}, connector.WithSourceAPI(providerID, "AlarmService.SearchAlarmList", err)
	}
	if resp.StatusCode != http.StatusOK {
		return alarmResult{}, httpError(resp.StatusCode, payload)
	}
	var envelope rpcResponse
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return alarmResult{}, fmt.Errorf("decode tanswer response: %w", err)
	}
	if envelope.Error != nil {
		return alarmResult{}, rpcErrorOf(envelope.Error)
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return alarmResult{}, nil
	}
	var result alarmResult
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return alarmResult{}, fmt.Errorf("decode tanswer result: %w", err)
	}
	return result, nil
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalize(raw)
}
