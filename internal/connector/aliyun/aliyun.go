// Package aliyun implements the Alibaba Cloud connector backed by Security
// Center (SAS) DescribeSuspEvents.
package aliyun

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	sas "github.com/alibabacloud-go/sas-20181203/v3/client"
	"github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
)

const (
	providerID      = "aliyun"
	mapperVersion   = "aliyun-sas/v5"
	defaultEndpoint = "sas.aliyuncs.com"
	defaultQPS      = 5
	defaultPageSize = 100
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "SAS DescribeSuspEvents",
		ID:            providerID,
		Name:          "Alibaba Cloud",
		Vendor:        "Alibaba Cloud",
		Product:       "Cloud Security Center (SAS)",
		ProductUID:    "aliyun.sas",
		APIVersion:    "2018-12-03",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "AccessKey ID", Required: true},
			{Name: "access_key_secret", Label: "AccessKey Secret", Required: true, Secret: true},
			{Name: "session_token", Label: "STS Token", Secret: true, Help: "Optional, for temporary credentials"},
		},
		OptionFields: []connector.OptionField{
			{Name: "status", Label: "告警状态过滤", Placeholder: "留空或 0=全部；1 未处理 / 2 已忽略 / 4 已处置", Help: "对应 DescribeSuspEvents.Status；默认显式传 0 查询全部状态"},
		},
		Products: []connector.Product{
			{Code: "SAS", Name: "Security Center (host, container, cloud platform)"},
		},
	}
}

// Connector talks to Alibaba Cloud Security Center.
type Connector struct {
	fetchJSON func(*sas.DescribeSuspEventsRequest, *service.RuntimeOptions) (json.RawMessage, error)
	limiter   *connector.Limiter
	pageSize  int
	status    string
}

// New builds an Alibaba Cloud connector from an account configuration.
func New(cfg connector.AccountConfig) (connector.Connector, error) {
	if cfg.Credential.AccessKeyID == "" || cfg.Credential.AccessKeySecret == "" {
		return nil, connector.ConfigError(providerID, "AccessKey ID and Secret are required")
	}
	endpoint := cfg.Options["endpoint"]
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	conf := &openapi.Config{
		AccessKeyId:     tea.String(cfg.Credential.AccessKeyID),
		AccessKeySecret: tea.String(cfg.Credential.AccessKeySecret),
		Endpoint:        tea.String(endpoint),
		Protocol:        tea.String("HTTPS"),
	}
	if cfg.Credential.SessionToken != "" {
		conf.SecurityToken = tea.String(cfg.Credential.SessionToken)
	}
	if cfg.Region != "" {
		conf.RegionId = tea.String(cfg.Region)
	}
	client, err := sas.NewClient(conf)
	if err != nil {
		return nil, connector.ConfigError(providerID, fmt.Sprintf("create client: %v", err))
	}
	return &Connector{
		fetchJSON: func(req *sas.DescribeSuspEventsRequest, runtime *service.RuntimeOptions) (json.RawMessage, error) {
			params := &openapi.Params{Action: tea.String("DescribeSuspEvents"), Version: tea.String("2018-12-03"), Protocol: tea.String("HTTPS"), Pathname: tea.String("/"), Method: tea.String("POST"), AuthType: tea.String("AK"), Style: tea.String("RPC"), ReqBodyType: tea.String("formData"), BodyType: tea.String("binary")}
			result, err := client.CallApi(params, &openapi.OpenApiRequest{Query: map[string]*string{"CurrentPage": req.CurrentPage, "PageSize": req.PageSize, "TimeStart": req.TimeStart, "TimeEnd": req.TimeEnd, "Lang": req.Lang, "Status": req.Status}}, runtime)
			if err != nil {
				return nil, err
			}
			body, ok := result["body"].(io.ReadCloser)
			if !ok {
				return nil, fmt.Errorf("Alibaba API returned no response stream")
			}
			defer body.Close()
			return connector.ReadSourceBody(body)
		},
		limiter:  connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize: connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
		status:   strings.TrimSpace(cfg.Options["status"]),
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

// Check performs a minimal query to validate credentials and permissions.
func (c *Connector) Check(ctx context.Context) error {
	end := time.Now().UTC()
	_, err := c.Fetch(ctx, connector.Query{
		Start:    end.Add(-1 * time.Hour),
		End:      end,
		PageSize: 1,
	})
	return err
}

// Fetch pulls one page of SuspEvents. SAS uses 1-based page numbers.
func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = c.pageSize
	}
	if pageSize > 100 {
		pageSize = 100
	}
	page := 1
	if q.Token != "" {
		v, err := strconv.Atoi(q.Token)
		if err != nil || v < 1 {
			return connector.Page{}, connector.ConfigError(providerID, "invalid page token")
		}
		page = v
	}

	if err := ctx.Err(); err != nil {
		return connector.Page{}, err
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return connector.Page{}, err
	}

	req := &sas.DescribeSuspEventsRequest{
		CurrentPage: tea.String(strconv.Itoa(page)),
		PageSize:    tea.String(strconv.Itoa(pageSize)),
		TimeStart:   tea.String(connector.FormatBeijing(q.Start)),
		TimeEnd:     tea.String(connector.FormatBeijing(q.End)),
		Lang:        tea.String("zh"),
		Status:      tea.String("0"), // Explicitly include every vendor status.
	}
	if c.status != "" {
		req.Status = tea.String(c.status)
	}
	// The generated SAS client has no context-aware method, so timeouts are
	// enforced at the transport level.
	runtime := &service.RuntimeOptions{
		ConnectTimeout: tea.Int(10000),
		ReadTimeout:    tea.Int(30000),
	}
	payload, err := c.fetchJSON(req, runtime)
	if err != nil {
		return connector.Page{}, connector.WithSourceAPI(providerID, "SAS DescribeSuspEvents", err)
	}
	var resp struct {
		TotalCount int               `json:"TotalCount"`
		SuspEvents []json.RawMessage `json:"SuspEvents"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		return connector.Page{}, fmt.Errorf("decode aliyun page: %w", err)
	}
	total := resp.TotalCount
	out := make([]connector.RawAlert, 0, len(resp.SuspEvents))
	for _, raw := range resp.SuspEvents {
		if len(raw) == 0 || string(raw) == "null" {
			return connector.Page{}, fmt.Errorf("aliyun returned a nil alert")
		}
		out = append(out, connector.RawAlert{Raw: raw})
	}
	if len(out) == 0 && (page-1)*pageSize < total {
		return connector.Page{}, fmt.Errorf("aliyun returned an empty page before total %d", total)
	}
	next := ""
	if page*pageSize < total && len(out) > 0 {
		next = strconv.Itoa(page + 1)
	}
	return connector.Page{Records: out, NextToken: next, Total: total}, nil
}
