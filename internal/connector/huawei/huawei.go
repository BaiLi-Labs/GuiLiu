// Package huawei implements the Huawei Cloud SecMaster connector using the
// ListAlerts alert-management API.
package huawei

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/region"
	secmaster "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/secmaster/v1"
	secmastermodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/secmaster/v1/model"
)

const (
	providerID      = "huawei"
	mapperVersion   = "huawei-secmaster/v1"
	defaultRegion   = "cn-north-4"
	defaultPageSize = 100
	defaultQPS      = 2
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		ID:            providerID,
		Name:          "Huawei Cloud",
		Vendor:        "Huawei Cloud",
		Product:       "SecMaster (安全云脑)",
		ProductUID:    "huawei.secmaster",
		APIVersion:    "v1",
		DocsURL:       "https://support.huaweicloud.com/api-secmaster/ListAlerts.html",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "Access Key ID", Required: true},
			{Name: "access_key_secret", Label: "Secret Access Key", Secret: true, Required: true},
			{Name: "session_token", Label: "Security Token", Secret: true, Help: "Optional, for temporary credentials"},
		},
		OptionFields: []connector.OptionField{
			{Name: "project_id", Label: "项目 ID", Required: true, Placeholder: "例如 0a1b2c3d4e5f...", Help: "华为云项目 ID，SecMaster 接口路径必需"},
			{Name: "workspace_id", Label: "工作空间 ID", Required: true, Placeholder: "SecMaster workspace ID", Help: "安全云脑工作空间 ID"},
		},
		Products: []connector.Product{
			{Code: "SecMaster", Name: "安全云脑"},
		},
	}
}

// Connector talks to Huawei Cloud SecMaster.
type Connector struct {
	client      *secmaster.SecMasterClient
	limiter     *connector.Limiter
	workspaceID string
	pageSize    int
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	if cfg.Credential.AccessKeyID == "" || cfg.Credential.AccessKeySecret == "" {
		return nil, connector.ConfigError(providerID, "Access Key ID and Secret Access Key are required")
	}
	projectID := cfg.Options["project_id"]
	workspaceID := cfg.Options["workspace_id"]
	if projectID == "" {
		return nil, connector.ConfigError(providerID, "project_id option is required")
	}
	if workspaceID == "" {
		return nil, connector.ConfigError(providerID, "workspace_id option is required")
	}
	regionID := cfg.Region
	if regionID == "" {
		regionID = defaultRegion
	}
	endpoint := cfg.Options["endpoint"]
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://secmaster.%s.myhuaweicloud.com", regionID)
	}
	credentials, err := auth.NewBasicCredentialsBuilder().
		WithAk(cfg.Credential.AccessKeyID).
		WithSk(cfg.Credential.AccessKeySecret).
		WithSecurityToken(cfg.Credential.SessionToken).
		WithProjectId(projectID).
		SafeBuild()
	if err != nil {
		return nil, connector.ConfigError(providerID, "build credentials: "+err.Error())
	}
	httpConfig := config.DefaultHttpConfig()
	httpConfig.Timeout = 30 * time.Second
	hcClient := secmaster.SecMasterClientBuilder().
		WithCredential(credentials).
		WithRegion(region.NewRegion(regionID, endpoint)).
		WithEndpoint(endpoint).
		WithHttpConfig(httpConfig).
		Build()
	return &Connector{
		client:      secmaster.NewSecMasterClient(hcClient),
		limiter:     connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		workspaceID: workspaceID,
		pageSize:    connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

func (c *Connector) Check(ctx context.Context) error {
	end := time.Now().UTC()
	_, err := c.Fetch(ctx, connector.Query{Start: end.Add(-time.Hour), End: end, PageSize: 1})
	return err
}

func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	if err := ctx.Err(); err != nil {
		return connector.Page{}, err
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return connector.Page{}, err
	}
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = c.pageSize
	}
	if pageSize > 100 {
		pageSize = 100
	}
	offset := int32(0)
	if q.Token != "" {
		v, err := strconv.Atoi(q.Token)
		if err != nil || v < 0 {
			return connector.Page{}, connector.ConfigError(providerID, "invalid page token")
		}
		offset = int32(v)
	}
	limit := int32(pageSize)
	sortBy := "create_time"
	order := secmastermodel.GetDataobjectSearchOrderEnum().ASC
	from := q.Start.UTC().Format("2006-01-02T15:04:05.000Z")
	to := q.End.UTC().Format("2006-01-02T15:04:05.000Z")
	req := &secmastermodel.ListAlertsRequest{
		ContentType: "application/json;charset=UTF-8",
		WorkspaceId: c.workspaceID,
		Body: &secmastermodel.DataobjectSearch{
			Limit:    &limit,
			Offset:   &offset,
			SortBy:   &sortBy,
			Order:    &order,
			FromDate: &from,
			ToDate:   &to,
		},
	}
	resp, err := c.client.ListAlerts(req)
	if err != nil {
		return connector.Page{}, connector.Classify(providerID, err)
	}
	if resp == nil {
		return connector.Page{}, connector.ConfigError(providerID, "empty response")
	}
	if resp.Code != nil && *resp.Code != "" && (resp.Success == nil || !*resp.Success) {
		msg := ""
		if resp.Message != nil {
			msg = *resp.Message
		}
		return connector.Page{}, connector.Classify(providerID, fmt.Errorf("%s: %s", *resp.Code, msg))
	}
	records := []connector.RawAlert{}
	if resp.Data != nil {
		for _, item := range *resp.Data {
			if item.DataObject == nil {
				continue
			}
			raw, err := json.Marshal(item.DataObject)
			if err != nil {
				return connector.Page{}, err
			}
			records = append(records, connector.RawAlert{Raw: raw})
		}
	}
	apiTotal := int(connector.Int32(resp.Total))
	nextOffset := int(offset) + len(records)
	total := apiTotal
	if total == 0 {
		total = nextOffset
	}
	next := ""
	if apiTotal > 0 {
		if nextOffset < apiTotal {
			next = strconv.Itoa(nextOffset)
		}
	} else if len(records) == pageSize {
		next = strconv.Itoa(nextOffset)
	}
	return connector.Page{Records: records, NextToken: next, Total: total}, nil
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	var a secmastermodel.ListAlertRsp
	if err := json.Unmarshal(raw, &a); err != nil {
		return model.Alert{}, fmt.Errorf("decode huawei alert: %w", err)
	}
	return normalizeAlert(&a, raw), nil
}
