// Package dsensor implements the Chaitin D-Sensor (谛听) alarm event connector.
//
// Contract source: the D-Sensor OpenAPI document embedded in chaitin-cli
// (products/dsensor/internal/spec/openapi.json, GPL-3.0, read as an interface
// reference only, no code copied):
//   - POST /api/event/event_alarm/list
//   - header API-Token with the raw key
//   - body limit / offset / not_before / not_after plus four required order
//     fields and an optional status list
//   - envelope {data:{total,data[],unhandle_count,handle_count}, err, msg}
package dsensor

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
	providerID    = "dsensor"
	mapperVersion = "dsensor-alarm/v1"
	apiVersion    = "openapi"
	alarmPath     = "/api/event/event_alarm/list"

	defaultQPS      = 2
	defaultPageSize = 100
	defaultOrder    = "desc"
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "POST /api/event/event_alarm/list",
		ID:            providerID,
		Name:          "Chaitin D-Sensor",
		Vendor:        "Chaitin",
		Product:       "D-Sensor (谛听)",
		ProductUID:    "chaitin.dsensor",
		APIVersion:    apiVersion,
		DocsURL:       "https://github.com/chaitin/chaitin-cli/tree/main/products/dsensor",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "API Key", Required: true, Secret: true, Help: "请求头为 API-Token"},
		},
		OptionFields: []connector.OptionField{
			{Name: "endpoint", Label: "D-Sensor URL", Required: true, Placeholder: "https://dsensor.example.com"},
			{Name: "insecure", Label: "Skip TLS verification", Placeholder: "false"},
			{Name: "order", Label: "Sort direction", Placeholder: defaultOrder, Help: "公开 spec 未枚举排序取值。服务端拒绝时改为 asc 或 1"},
			{Name: "severity_from_level", Label: "Derive severity from risk_level", Placeholder: "false", Help: "risk_level 为 1-4，但公开定义未写明高低顺序。开启后按 1=low..4=critical 推导"},
		},
		Products: []connector.Product{
			{Code: "AlarmEvent", Name: "Alarm events"},
		},
	}
}

// Connector reads alarm events from D-Sensor.
type Connector struct {
	endpoint     string
	token        string
	order        string
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
	order := strings.TrimSpace(cfg.Options["order"])
	if order == "" {
		order = defaultOrder
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.EqualFold(strings.TrimSpace(cfg.Options["insecure"]), "true") {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Connector{
		endpoint:     endpoint,
		token:        token,
		order:        order,
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
	records := make([]connector.RawAlert, 0, len(result.Data))
	for _, raw := range result.Data {
		if len(raw) == 0 || string(raw) == "null" {
			return connector.Page{}, fmt.Errorf("dsensor returned an empty alarm")
		}
		records = append(records, connector.RawAlert{Raw: append(json.RawMessage(nil), raw...)})
	}
	next := ""
	if offset+len(records) < result.Total && len(records) > 0 {
		next = strconv.Itoa(offset + len(records))
	}
	return connector.Page{Records: records, NextToken: next, Total: result.Total}, nil
}

type alarmPage struct {
	Data          []json.RawMessage `json:"data"`
	Total         int               `json:"total"`
	UnhandleCount int               `json:"unhandle_count"`
	HandleCount   int               `json:"handle_count"`
}

type envelope struct {
	Data alarmPage `json:"data"`
	Err  string    `json:"err"`
	Msg  string    `json:"msg"`
}

func (c *Connector) list(ctx context.Context, q connector.Query, offset, count int) (alarmPage, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return alarmPage{}, err
	}
	// The four order fields and status are required by the schema even though
	// an empty status list means "no filter".
	body, err := json.Marshal(map[string]any{
		"status":                []int{},
		"id_order":              c.order,
		"last_alarm_time_order": c.order,
		"risk_level_order":      c.order,
		"status_order":          c.order,
		"limit":                 count,
		"offset":                offset,
		"not_before":            q.Start.UTC().Format(time.RFC3339),
		"not_after":             q.End.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return alarmPage{}, fmt.Errorf("encode dsensor request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+alarmPath, bytes.NewReader(body))
	if err != nil {
		return alarmPage{}, connector.ConfigError(providerID, "invalid endpoint: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("API-Token", c.token)
	req.Header.Set("User-Agent", "GuiLiu/"+mapperVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return alarmPage{}, connector.WithSourceAPI(providerID, "event_alarm/list", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return alarmPage{}, connector.WithSourceAPI(providerID, "event_alarm/list", err)
	}
	if resp.StatusCode != http.StatusOK {
		return alarmPage{}, httpError(resp.StatusCode, payload)
	}
	var parsed envelope
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return alarmPage{}, fmt.Errorf("decode dsensor response: %w", err)
	}
	if strings.TrimSpace(parsed.Err) != "" {
		return alarmPage{}, apiError(parsed.Err, parsed.Msg)
	}
	return parsed.Data, nil
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalize(raw, c.severityFrom)
}
