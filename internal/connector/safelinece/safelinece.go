// Package safelinece implements the Chaitin SafeLine Community Edition (雷池社区版)
// attack log connector.
//
// This is a different product from the commercial SafeLine connector: the
// community edition uses its own OpenAPI surface under /open/*, authenticates
// with X-SLCE-API-TOKEN and returns a much richer record (risk_level, rule_id,
// request/response bodies) than the commercial list scope.
//
// Contract source: products/safeline-ce/openapi.json in the public
// chaitin-cli repository (GPL-3.0, read as an interface reference only, no
// code copied).
package safelinece

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const (
	providerID      = "safeline-ce"
	mapperVersion   = "safeline-ce-detect-log/v1"
	apiVersion      = "openapi"
	recordsPath     = "/open/records"
	defaultQPS      = 2
	defaultPageSize = 100
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "GET /open/records",
		ID:            providerID,
		Name:          "Chaitin SafeLine CE",
		Vendor:        "Chaitin",
		Product:       "SafeLine Community Edition",
		ProductUID:    "chaitin.safeline.ce",
		APIVersion:    apiVersion,
		DocsURL:       "https://waf-ce.chaitin.cn/",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "API Token", Required: true, Secret: true, Help: "请求头为 X-SLCE-API-TOKEN"},
		},
		OptionFields: []connector.OptionField{
			{Name: "endpoint", Label: "SafeLine CE URL", Required: true, Placeholder: "https://waf.example.com:9443", Help: "社区版控制台地址，不含 /open 路径"},
			{Name: "insecure", Label: "Skip TLS verification", Placeholder: "false", Help: "社区版默认自签证书，内网测试可开启"},
			{Name: "severity_from_level", Label: "Derive severity from risk_level", Placeholder: "false", Help: "risk_level 为整数但公开 spec 未写明顺序。开启后按 1=low..4=critical 推导并标记"},
		},
		Products: []connector.Product{
			{Code: "DetectLog", Name: "Attack log"},
		},
	}
}

// Connector talks to the SafeLine CE OpenAPI.
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
		return nil, connector.ConfigError(providerID, "API token is required")
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

func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = c.pageSize
	}
	if pageSize > 100 {
		pageSize = 100
	}
	page := 1
	if token := strings.TrimSpace(q.Token); token != "" {
		parsed, err := strconv.Atoi(token)
		if err != nil || parsed < 1 {
			return connector.Page{}, connector.ConfigError(providerID, "invalid page token")
		}
		page = parsed
	}

	result, err := c.list(ctx, q, page, pageSize)
	if err != nil {
		return connector.Page{}, err
	}
	records := make([]connector.RawAlert, 0, len(result.Data))
	for _, raw := range result.Data {
		if len(raw) == 0 || string(raw) == "null" {
			return connector.Page{}, fmt.Errorf("safeline ce returned an empty record")
		}
		records = append(records, connector.RawAlert{Raw: append(json.RawMessage(nil), raw...)})
	}
	next := ""
	if page*pageSize < result.Total && len(records) > 0 {
		next = strconv.Itoa(page + 1)
	}
	return connector.Page{Records: records, NextToken: next, Total: result.Total}, nil
}

type recordPage struct {
	Data  []json.RawMessage `json:"data"`
	Total int               `json:"total"`
}

func (c *Connector) list(ctx context.Context, q connector.Query, page, pageSize int) (recordPage, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return recordPage{}, err
	}
	query := url.Values{}
	query.Set("page", strconv.Itoa(page))
	query.Set("page_size", strconv.Itoa(pageSize))
	// The wire time unit is Unix seconds.
	if !q.Start.IsZero() {
		query.Set("start", strconv.FormatInt(q.Start.Unix(), 10))
	}
	if !q.End.IsZero() {
		query.Set("end", strconv.FormatInt(q.End.Unix(), 10))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+recordsPath+"?"+query.Encode(), nil)
	if err != nil {
		return recordPage{}, connector.ConfigError(providerID, "invalid endpoint: "+err.Error())
	}
	req.Header.Set("X-SLCE-API-TOKEN", c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GuiLiu/"+mapperVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return recordPage{}, connector.WithSourceAPI(providerID, "GET /open/records", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return recordPage{}, connector.WithSourceAPI(providerID, "GET /open/records", err)
	}
	if resp.StatusCode != http.StatusOK {
		return recordPage{}, httpError(resp.StatusCode, payload)
	}

	var envelope struct {
		Err  string          `json:"err"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return recordPage{}, fmt.Errorf("decode safeline ce response: %w", err)
	}
	if strings.TrimSpace(envelope.Err) != "" {
		return recordPage{}, apiError(envelope.Err, envelope.Msg)
	}
	var result recordPage
	if err := json.Unmarshal(envelope.Data, &result); err != nil {
		return recordPage{}, fmt.Errorf("decode safeline ce page: %w", err)
	}
	return result, nil
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalize(raw, c.severityFrom)
}
