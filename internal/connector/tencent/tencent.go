// Package tencent implements the Tencent Cloud connector backed by the Cloud
// Security Center (CSIP) DescribeAlertList API.
package tencent

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	csip "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/csip/v20221121"
)

const (
	providerID      = "tencent"
	mapperVersion   = "tencent-csip/v6"
	defaultEndpoint = "csip.tencentcloudapi.com"
	// The official limit is 3 requests/second. Use 2 QPS for headroom: a fixed
	// interval at exactly 3 QPS still allows four calls in a sliding second.
	defaultQPS      = 2
	defaultPageSize = 100
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "CSIP DescribeAlertList",
		ID:            providerID,
		Name:          "Tencent Cloud",
		Vendor:        "Tencent Cloud",
		Product:       "Cloud Security Center (CSIP)",
		ProductUID:    "tencent.csip",
		APIVersion:    "2022-11-21",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "SecretId", Required: true, Help: "Tencent Cloud API SecretId"},
			{Name: "access_key_secret", Label: "SecretKey", Required: true, Secret: true},
			{Name: "session_token", Label: "SessionToken", Secret: true, Help: "Optional, for temporary credentials"},
		},
		Products: []connector.Product{
			{Code: "CSIP", Name: "Cloud Security Center"},
			{Code: "CWP", Name: "Host Security"},
			{Code: "CFW", Name: "Cloud Firewall"},
			{Code: "WAF", Name: "Web Application Firewall"},
		},
	}
}

// Connector talks to Tencent Cloud CSIP.
type Connector struct {
	fetchJSON func(context.Context, *csip.DescribeAlertListRequest) (json.RawMessage, error)
	limiter   *connector.Limiter
	pageSize  int
}

// New builds a Tencent connector from an account configuration.
func New(cfg connector.AccountConfig) (connector.Connector, error) {
	if cfg.Credential.AccessKeyID == "" || cfg.Credential.AccessKeySecret == "" {
		return nil, connector.ConfigError(providerID, "SecretId and SecretKey are required")
	}
	endpoint := cfg.Options["endpoint"]
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	var cred common.CredentialIface
	if cfg.Credential.SessionToken != "" {
		cred = common.NewTokenCredential(cfg.Credential.AccessKeyID, cfg.Credential.AccessKeySecret, cfg.Credential.SessionToken)
	} else {
		cred = common.NewCredential(cfg.Credential.AccessKeyID, cfg.Credential.AccessKeySecret)
	}
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = endpoint
	cpf.HttpProfile.ReqTimeout = 30

	region := cfg.Region
	if region == "" {
		region = "ap-guangzhou"
	}
	client, err := csip.NewClient(cred, region, cpf)
	if err != nil {
		return nil, connector.ConfigError(providerID, fmt.Sprintf("create client: %v", err))
	}
	return &Connector{
		fetchJSON: func(ctx context.Context, req *csip.DescribeAlertListRequest) (json.RawMessage, error) {
			req.SetContext(ctx)
			response := &rawResponse{}
			if err := client.Send(req, response); err != nil {
				return nil, err
			}
			return response.Response, nil
		},
		limiter:  connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize: connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
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

// Fetch pulls one page of alerts. Tencent CSIP paginates by offset, so the
// token is simply the next offset.
func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = c.pageSize
	}
	if pageSize > 100 {
		pageSize = 100
	}
	var offset int64
	if q.Token != "" {
		v, err := strconv.ParseInt(q.Token, 10, 64)
		if err != nil {
			return connector.Page{}, connector.ConfigError(providerID, "invalid page token")
		}
		offset = v
	}

	if err := c.limiter.Wait(ctx); err != nil {
		return connector.Page{}, err
	}

	req := csip.NewDescribeAlertListRequest()
	req.Filter = &csip.Filter{
		Limit:     common.Int64Ptr(int64(pageSize)),
		Offset:    common.Int64Ptr(offset),
		StartTime: common.StringPtr(connector.FormatBeijing(q.Start)),
		EndTime:   common.StringPtr(connector.FormatBeijing(q.End)),
	}

	payload, err := c.fetchJSON(ctx, req)
	if err != nil {
		return connector.Page{}, connector.WithSourceAPI(providerID, "CSIP DescribeAlertList", err)
	}
	var resp struct {
		TotalCount int               `json:"TotalCount"`
		AlertList  []json.RawMessage `json:"AlertList"`
		ReturnCode int               `json:"ReturnCode"`
		ReturnMsg  string            `json:"ReturnMsg"`
	}
	if err := json.Unmarshal(payload, &resp); err != nil {
		return connector.Page{}, fmt.Errorf("decode tencent page: %w", err)
	}
	if resp.ReturnCode != 0 {
		return connector.Page{}, fmt.Errorf("Tencent API %d: %s", resp.ReturnCode, resp.ReturnMsg)
	}
	total := resp.TotalCount
	out := make([]connector.RawAlert, 0, len(resp.AlertList))
	for _, raw := range resp.AlertList {
		if len(raw) == 0 || string(raw) == "null" {
			return connector.Page{}, fmt.Errorf("tencent returned a nil alert")
		}
		out = append(out, connector.RawAlert{Raw: raw})
	}
	if len(out) == 0 && offset < int64(total) {
		return connector.Page{}, fmt.Errorf("tencent returned an empty page before total %d", total)
	}

	next := ""
	if offset+int64(len(out)) < int64(total) && len(out) > 0 {
		next = strconv.FormatInt(offset+int64(len(out)), 10)
	}
	return connector.Page{Records: out, NextToken: next, Total: total}, nil
}

type rawResponse struct {
	tchttp.BaseResponse
	Response json.RawMessage `json:"Response"`
}
