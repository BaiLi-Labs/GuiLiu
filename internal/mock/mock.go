// Package mock provides offline cloud connectors backed by sanitized SDK-shaped
// fixtures. They are registered only in mock mode, so production deployments
// never advertise them.
package mock

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/aliyun"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/aws"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/gcp"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/huawei"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/tencent"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// ProviderID is kept for compatibility with older mock configs. Mock mode now
// replaces the production providers under their real IDs.
const ProviderID = "tencent"

//go:embed fixtures/tencent.json
var tencentFixture []byte

//go:embed fixtures/aliyun.json
var aliyunFixture []byte

//go:embed fixtures/huawei.json
var huaweiFixture []byte

//go:embed fixtures/aws.json
var awsFixture []byte

//go:embed fixtures/gcp.json
var gcpFixture []byte

type spec struct {
	id         string
	descriptor connector.Descriptor
	fixture    []byte
	normalize  func(json.RawMessage) (model.Alert, error)
}

var akCredential = []connector.CredentialField{
	{Name: "access_key_id", Label: "Access Key ID", Required: true},
	{Name: "access_key_secret", Label: "Secret Access Key", Secret: true, Required: true},
	{Name: "session_token", Label: "Session Token", Secret: true},
}

var awsCredential = []connector.CredentialField{
	{Name: "access_key_id", Label: "Access Key ID", Help: "留空使用 IAM Role / 默认凭据"},
	{Name: "access_key_secret", Label: "Secret Access Key", Secret: true, Help: "留空使用 IAM Role / 默认凭据"},
	{Name: "session_token", Label: "Session Token", Secret: true, Help: "可选，临时凭据"},
}

var aliyunOptions = []connector.OptionField{
	{Name: "status", Label: "告警状态过滤", Placeholder: "留空=全部；0 未处理 / 1 已处理 ..."},
}

var huaweiOptions = []connector.OptionField{
	{Name: "project_id", Label: "Project ID", Required: true, Placeholder: "例如 cn-north-4 项目 ID"},
	{Name: "workspace_id", Label: "Workspace ID", Required: true, Placeholder: "SecMaster 工作空间 ID"},
}

var gcpCredential = []connector.CredentialField{
	{Name: "service_account_json", Label: "Service Account JSON", Secret: true, Multiline: true, Help: "Mock 模式忽略；真实模式需要 SCC findings.list 权限"},
}

var gcpOptions = []connector.OptionField{
	{Name: "parent", Label: "SCC Parent", Required: true, Placeholder: "organizations/123456 或 projects/my-project"},
}

var specs = []spec{
	{
		id: "tencent",
		descriptor: mockDescriptor(
			"tencent", "Tencent Cloud", "Tencent Cloud",
			"Cloud Security Center (CSIP)", "tencent.csip", "tencent-csip/v1",
			[]connector.Product{
				{Code: "CSIP", Name: "Cloud Security Center"},
				{Code: "CWP", Name: "Host Security"},
				{Code: "CFW", Name: "Cloud Firewall"},
				{Code: "WAF", Name: "Web Application Firewall"},
			},
			akCredential, nil,
		),
		fixture:   tencentFixture,
		normalize: func(raw json.RawMessage) (model.Alert, error) { return (&tencent.Connector{}).Normalize(raw) },
	},
	{
		id: "aliyun",
		descriptor: mockDescriptor(
			"aliyun", "Alibaba Cloud", "Alibaba Cloud",
			"Cloud Security Center (SAS)", "aliyun.sas", "aliyun-sas/v1",
			[]connector.Product{{Code: "SAS", Name: "Cloud Security Center"}},
			akCredential, aliyunOptions,
		),
		fixture:   aliyunFixture,
		normalize: func(raw json.RawMessage) (model.Alert, error) { return (&aliyun.Connector{}).Normalize(raw) },
	},
	{
		id: "huawei",
		descriptor: mockDescriptor(
			"huawei", "Huawei Cloud", "Huawei Cloud",
			"SecMaster (安全云脑)", "huawei.secmaster", "huawei-secmaster/v1",
			[]connector.Product{
				{Code: "SecMaster", Name: "Security Master"},
				{Code: "HSS", Name: "Host Security"},
				{Code: "CFW", Name: "Cloud Firewall"},
				{Code: "WAF", Name: "Web Application Firewall"},
			},
			akCredential, huaweiOptions,
		),
		fixture:   huaweiFixture,
		normalize: func(raw json.RawMessage) (model.Alert, error) { return (&huawei.Connector{}).Normalize(raw) },
	},
	{
		id: "aws",
		descriptor: mockDescriptor(
			"aws", "AWS", "Amazon Web Services",
			"Security Hub", "aws.securityhub", "aws-securityhub-ocsf/v1",
			[]connector.Product{
				{Code: "SecurityHub", Name: "Security Hub"},
				{Code: "GuardDuty", Name: "GuardDuty"},
				{Code: "Inspector", Name: "Inspector"},
				{Code: "Macie", Name: "Macie"},
			},
			awsCredential, nil,
		),
		fixture:   awsFixture,
		normalize: func(raw json.RawMessage) (model.Alert, error) { return (&aws.Connector{}).Normalize(raw) },
	},
	{
		id: "gcp",
		descriptor: mockDescriptor(
			"gcp", "Google Cloud", "Google Cloud",
			"Security Command Center", "gcp.scc", "gcp-scc/v1",
			[]connector.Product{{Code: "SCC", Name: "Security Command Center"}},
			gcpCredential, gcpOptions,
		),
		fixture:   gcpFixture,
		normalize: func(raw json.RawMessage) (model.Alert, error) { return (&gcp.Connector{}).Normalize(raw) },
	},
}

var specByID = func() map[string]*spec {
	out := make(map[string]*spec, len(specs))
	for i := range specs {
		out[specs[i].id] = &specs[i]
	}
	return out
}()

func mockDescriptor(id, name, vendor, product, productUID, mapperVersion string, products []connector.Product, credential []connector.CredentialField, options []connector.OptionField) connector.Descriptor {
	return connector.Descriptor{
		ID:            id,
		Name:          name,
		Vendor:        vendor,
		Product:       product,
		ProductUID:    productUID,
		APIVersion:    "mock",
		MapperVersion: mapperVersion,
		Credential:    credential,
		OptionFields:  options,
		Products:      products,
	}
}

// Register adds every mock provider to a registry. Duplicate registrations are
// ignored so repeated app construction in tests stays safe.
func Register(reg *connector.Registry) {
	for i := range specs {
		_ = reg.Replace(specs[i].descriptor, New)
	}
}

// IsMockProvider reports whether a provider is one of the bundled mock sources.
func IsMockProvider(id string) bool {
	_, ok := specByID[id]
	return ok
}

// Connector serves one embedded fixture page without network access.
type Connector struct {
	spec     spec
	records  []connector.RawAlert
	pageSize int
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	s, ok := specByID[cfg.Provider]
	if !ok {
		return nil, connector.ConfigError(cfg.Provider, "unknown mock provider")
	}
	records, err := loadRecords(*s)
	if err != nil {
		return nil, connector.ConfigError(cfg.Provider, "load fixtures: "+err.Error())
	}
	return &Connector{
		spec:     *s,
		records:  records,
		pageSize: connector.OptionInt(cfg.Options, "page_size", 100),
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return c.spec.descriptor }

func (c *Connector) Check(context.Context) error { return nil }

func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	if err := ctx.Err(); err != nil {
		return connector.Page{}, err
	}
	offset := 0
	if q.Token != "" {
		v, err := strconv.Atoi(q.Token)
		if err != nil || v < 0 {
			return connector.Page{}, connector.ConfigError(c.spec.id, "invalid page token")
		}
		offset = v
	}
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = c.pageSize
	}
	if pageSize > 100 {
		pageSize = 100
	}
	if offset >= len(c.records) {
		return connector.Page{Total: len(c.records)}, nil
	}
	end := offset + pageSize
	if end > len(c.records) {
		end = len(c.records)
	}
	next := ""
	if end < len(c.records) {
		next = strconv.Itoa(end)
	}
	records := append([]connector.RawAlert(nil), c.records[offset:end]...)
	return connector.Page{Records: records, NextToken: next, Total: len(c.records)}, nil
}

// Normalize reuses the production mapper so every fixture exercises the same
// field conversion and OCSF path as a real SDK response.
func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return c.spec.normalize(raw)
}

var (
	stringTimeKeys = map[string]bool{
		"CreateTime":          true,
		"UpdateTime":          true,
		"Date":                true,
		"OccurrenceTime":      true,
		"LastTime":            true,
		"FirstObservedTime":   true,
		"LastObservedTime":    true,
		"ArriveTime":          true,
		"CloseTime":           true,
		"first_observed_time": true,
		"last_observed_time":  true,
		"create_time":         true,
		"update_time":         true,
		"arrive_time":         true,
		"close_time":          true,
		"eventTime":           true,
		"createTime":          true,
		"muteUpdateTime":      true,
	}
	millisTimeKeys = map[string]bool{
		"OccurrenceTimeStamp": true,
		"LastTimeStamp":       true,
		"OperateTime":         true,
		"time":                true,
		"created_time":        true,
		"first_seen_time":     true,
		"last_seen_time":      true,
		"modified_time":       true,
		"start_time":          true,
		"end_time":            true,
	}
)

func loadRecords(s spec) ([]connector.RawAlert, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(s.fixture, &items); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	out := make([]connector.RawAlert, 0, len(items))
	for i, item := range items {
		var obj any
		if err := json.Unmarshal(item, &obj); err != nil {
			return nil, fmt.Errorf("fixture %d: %w", i, err)
		}
		// Keep mock data inside the default 24h sync/query window and preserve
		// per-record ordering. Relative timestamps avoid stale fixtures.
		ts := now.Add(-time.Duration(20+i*47) * time.Minute)
		rewriteTimes(obj, ts)
		raw, err := json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("fixture %d: %w", i, err)
		}
		out = append(out, connector.RawAlert{Raw: raw})
	}
	return out, nil
}

func rewriteTimes(v any, ts time.Time) {
	switch x := v.(type) {
	case map[string]any:
		for key, child := range x {
			if stringTimeKeys[key] {
				x[key] = ts.Format(time.RFC3339)
				continue
			}
			if millisTimeKeys[key] {
				x[key] = ts.UnixMilli()
				continue
			}
			rewriteTimes(child, ts)
		}
	case []any:
		for _, child := range x {
			rewriteTimes(child, ts)
		}
	}
}
