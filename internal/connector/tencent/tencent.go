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
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	csip "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/csip/v20221121"
)

const (
	providerID      = "tencent"
	mapperVersion   = "tencent-csip/v1"
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
	client   *csip.Client
	limiter  *connector.Limiter
	pageSize int
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
		client:   client,
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

	resp, err := c.client.DescribeAlertListWithContext(ctx, req)
	if err != nil {
		return connector.Page{}, connector.Classify(providerID, err)
	}
	if resp == nil || resp.Response == nil {
		return connector.Page{}, &connector.Error{Provider: providerID, Kind: connector.KindTransient, Code: "empty_response", Message: "empty response"}
	}
	if resp.Response.ReturnCode != nil && *resp.Response.ReturnCode != 0 {
		return connector.Page{}, &connector.Error{
			Provider: providerID,
			Kind:     connector.KindTransient,
			Code:     "api_error",
			Message:  connector.FirstNonEmpty(connector.Str(resp.Response.ReturnMsg), "API returned an error"),
		}
	}

	total := int(connector.Uint64(resp.Response.TotalCount))
	out := make([]connector.RawAlert, 0, len(resp.Response.AlertList))
	for _, item := range resp.Response.AlertList {
		raw, err := json.Marshal(item)
		if err != nil {
			continue
		}
		out = append(out, connector.RawAlert{Raw: raw})
	}

	next := ""
	if offset+int64(len(out)) < int64(total) && len(out) > 0 {
		next = strconv.FormatInt(offset+int64(len(out)), 10)
	}
	return connector.Page{Records: out, NextToken: next, Total: total}, nil
}
