// Package gcp implements the Google Cloud Security Command Center connector.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	providerID      = "gcp"
	mapperVersion   = "gcp-scc/v1"
	defaultPageSize = 100
	defaultQPS      = 5
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		ID:            providerID,
		Name:          "Google Cloud",
		Vendor:        "Google Cloud",
		Product:       "Security Command Center",
		ProductUID:    "gcp.scc",
		APIVersion:    "v1",
		DocsURL:       "https://cloud.google.com/security-command-center/docs/reference/rest/v1/organizations.sources.findings/list",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "service_account_json", Label: "Service Account JSON", Secret: true, Multiline: true, Help: "留空使用 ADC / Workload Identity；需要 SCC findings.list 权限"},
		},
		OptionFields: []connector.OptionField{
			{Name: "parent", Label: "SCC Parent", Required: true, Placeholder: "organizations/123456 或 projects/my-project", Help: "会自动追加 /sources/- 以查询全部来源"},
		},
		Products: []connector.Product{
			{Code: "SCC", Name: "Security Command Center"},
		},
	}
}

// Connector talks to Security Command Center.
type Connector struct {
	client   *securitycenter.Client
	findings securitycenterpb.SecurityCenterClient
	parent   string
	limiter  *connector.Limiter
	pageSize int
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	parent := strings.TrimSuffix(strings.TrimSpace(cfg.Options["parent"]), "/")
	if parent == "" {
		return nil, connector.ConfigError(providerID, "parent option is required (organizations/... or projects/...)")
	}
	if !strings.Contains(parent, "/sources/") {
		parent += "/sources/-"
	}
	var opts []option.ClientOption
	if raw := strings.TrimSpace(cfg.Credential.ServiceAccountJSON); raw != "" {
		if !json.Valid([]byte(raw)) {
			return nil, connector.ConfigError(providerID, "service_account_json is not valid JSON")
		}
		opts = append(opts, option.WithCredentialsJSON([]byte(raw)))
	}
	client, err := securitycenter.NewClient(context.Background(), opts...)
	if err != nil {
		return nil, connector.ConfigError(providerID, "create SCC client: "+err.Error())
	}
	return &Connector{
		client:   client,
		findings: securitycenterpb.NewSecurityCenterClient(client.Connection()),
		parent:   parent,
		limiter:  connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize: connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

func (c *Connector) Close() error { return c.client.Close() }

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
	if pageSize > 1000 {
		pageSize = 1000
	}
	filter := findingFilter(q.Start, q.End)
	resp, err := c.findings.ListFindings(ctx, &securitycenterpb.ListFindingsRequest{
		Parent:    c.parent,
		Filter:    filter,
		PageSize:  int32(pageSize),
		PageToken: q.Token,
	})
	if err != nil {
		return connector.Page{}, connector.Classify(providerID, err)
	}
	records := make([]connector.RawAlert, 0, len(resp.ListFindingsResults))
	for _, result := range resp.ListFindingsResults {
		if result.Finding == nil {
			continue
		}
		raw, err := protojson.Marshal(result.Finding)
		if err != nil {
			return connector.Page{}, fmt.Errorf("encode GCP finding: %w", err)
		}
		records = append(records, connector.RawAlert{Raw: raw})
	}
	return connector.Page{
		Records:   records,
		NextToken: resp.NextPageToken,
		Total:     int(resp.TotalSize),
	}, nil
}

func findingFilter(start, end time.Time) string {
	// Keep inactive findings in the window: a finding can be resolved between
	// two syncs, and filtering only ACTIVE would make that state change invisible.
	// GCP's event_time is creation/detection time rather than an update time, so
	// old findings that become INACTIVE still need a periodic full reconciliation
	// outside this incremental window.
	return fmt.Sprintf(`event_time >= %q AND event_time < %q`,
		start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	var finding securitycenterpb.Finding
	if err := protojson.Unmarshal(raw, &finding); err != nil {
		return model.Alert{}, fmt.Errorf("decode GCP finding: %w", err)
	}
	return normalizeFinding(&finding, raw), nil
}
