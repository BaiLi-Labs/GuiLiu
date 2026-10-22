// Package gcp implements the Google Cloud Security Command Center connector.
package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"google.golang.org/api/option"
	htransport "google.golang.org/api/transport/http"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	providerID      = "gcp"
	mapperVersion   = "gcp-scc/v5"
	defaultPageSize = 100
	defaultQPS      = 5
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "SCC ListFindings REST",
		ID:            providerID,
		Name:          "Google Cloud",
		Vendor:        "Google Cloud",
		Product:       "Security Command Center",
		ProductUID:    "gcp.scc",
		APIVersion:    "v2",
		DocsURL:       "https://cloud.google.com/security-command-center/docs/reference/rest/v2/organizations.sources.locations.findings/list",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "service_account_json", Label: "Service Account JSON", Secret: true, Multiline: true, Help: "留空使用 ADC / Workload Identity；需要 SCC findings.list 权限"},
		},
		OptionFields: []connector.OptionField{
			{Name: "parent", Label: "SCC Parent", Required: true, Placeholder: "organizations/123456 或 projects/my-project", Help: "会自动追加 /sources/- 以查询全部来源"},
			{Name: "api_version", Label: "SCC API Version", Placeholder: "v2", Help: "v2 (default), or v1 for legacy accounts"},
			{Name: "location", Label: "SCC Location", Placeholder: "global", Help: "SCC data location; default global. Configure each required location separately."},
		},
		Products: []connector.Product{
			{Code: "SCC", Name: "Security Command Center"},
		},
	}
}

// Connector talks to Security Command Center.
type Connector struct {
	client     *http.Client
	endpoint   string
	parent     string
	limiter    *connector.Limiter
	pageSize   int
	apiVersion string
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	version, parent, endpoint, err := queryScope(cfg.Options)
	if err != nil {
		return nil, connector.ConfigError(providerID, err.Error())
	}
	opts := []option.ClientOption{option.WithScopes("https://www.googleapis.com/auth/cloud-platform")}
	if endpoint != "" {
		opts = append(opts, option.WithEndpoint(endpoint))
	}
	if raw := strings.TrimSpace(cfg.Credential.ServiceAccountJSON); raw != "" {
		if !json.Valid([]byte(raw)) {
			return nil, connector.ConfigError(providerID, "service_account_json is not valid JSON")
		}
		opts = append(opts, option.WithCredentialsJSON([]byte(raw)))
	}
	c := &Connector{
		apiVersion: version,
		endpoint:   connector.FirstNonEmpty(endpoint, "https://securitycenter.googleapis.com"),
		parent:     parent,
		limiter:    connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize:   connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
	}
	c.client, _, err = htransport.NewClient(context.Background(), opts...)
	if c.client != nil {
		c.client.Timeout = 30 * time.Second
	}
	if !strings.HasPrefix(c.endpoint, "http") {
		c.endpoint = "https://" + strings.TrimSuffix(c.endpoint, ":443")
	}
	if err != nil {
		return nil, connector.ConfigError(providerID, "create SCC client: "+err.Error())
	}
	return c, nil
}

func (c *Connector) Info() connector.Descriptor {
	info := descriptor()
	if c.apiVersion != "" {
		info.APIVersion = c.apiVersion
	}
	return info
}

func (c *Connector) Close() error {
	if c.client != nil {
		c.client.CloseIdleConnections()
	}
	return nil
}

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
	params := url.Values{"filter": {findingFilter(q.Start, q.End)}, "pageSize": {strconv.Itoa(pageSize)}}
	if q.Token != "" {
		params.Set("pageToken", q.Token)
	}
	requestURL := strings.TrimRight(c.endpoint, "/") + "/" + c.apiVersion + "/" + c.parent + "/findings?" + params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return connector.Page{}, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return connector.Page{}, connector.WithSourceAPI(providerID, "SCC ListFindings REST", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return connector.Page{}, connector.HTTPError(providerID, "SCC ListFindings REST", resp)
	}
	payload, err := connector.ReadSourceBody(resp.Body)
	if err != nil {
		return connector.Page{}, err
	}
	var page struct {
		Results       []json.RawMessage `json:"listFindingsResults"`
		NextPageToken string            `json:"nextPageToken"`
		TotalSize     int               `json:"totalSize"`
	}
	if err := json.Unmarshal(payload, &page); err != nil {
		return connector.Page{}, err
	}
	records := make([]connector.RawAlert, 0, len(page.Results))
	for _, raw := range page.Results {
		var item struct {
			Finding json.RawMessage `json:"finding"`
		}
		if json.Unmarshal(raw, &item) != nil || len(item.Finding) == 0 || string(item.Finding) == "null" {
			return connector.Page{}, fmt.Errorf("GCP returned a result without a finding")
		}
		records = append(records, connector.RawAlert{Raw: raw})
	}
	return connector.Page{Records: records, NextToken: page.NextPageToken, Total: page.TotalSize}, nil
}

func findingFilter(start, end time.Time) string {
	// Keep inactive findings in the window: a finding can be resolved between
	// two syncs, and filtering only ACTIVE would make that state change invisible.
	// The SDK defines event_time as detection time, or the time of an update or
	// resolution. Mute/security-mark-only changes may have separate timestamps.
	return fmt.Sprintf(`event_time >= %q AND event_time < %q`,
		start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	var envelope struct {
		Finding json.RawMessage `json:"finding"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return model.Alert{}, fmt.Errorf("decode GCP finding: %w", err)
	}
	if envelope.Finding != nil {
		var result securitycenterpb.ListFindingsResponse_ListFindingsResult
		// Map shared typed fields; the complete REST source object stays in Raw.
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, &result); err != nil {
			return model.Alert{}, fmt.Errorf("decode GCP finding result: %w", err)
		}
		if result.Finding == nil {
			return model.Alert{}, fmt.Errorf("GCP result has no finding")
		}
		alert := normalizeFinding(result.Finding, raw)
		if resource := result.Resource; resource != nil {
			alert.Resource = connector.NamedResource(
				connector.FirstNonEmpty(resource.GetName(), alert.Resource.ID),
				connector.FirstNonEmpty(resource.GetType(), alert.Resource.Type),
				resource.GetDisplayName(),
				alert.Resource.Name,
			)
			alert.Region = connector.FirstNonEmpty(resource.GetLocation(), alert.Region)
			alert.CloudAccountUID = connector.FirstNonEmpty(resource.GetProjectName(), alert.CloudAccountUID)
			var resourceContext struct {
				Resource struct {
					GCPMetadata struct {
						Project string `json:"project"`
					} `json:"gcpMetadata"`
				} `json:"resource"`
			}
			if json.Unmarshal(raw, &resourceContext) == nil && resourceContext.Resource.GCPMetadata.Project != "" {
				alert.CloudAccountUID = resourceContext.Resource.GCPMetadata.Project
			}
			alert.Observables = observables(result.Finding, alert)
		}
		return alert, nil
	}
	// A standalone Finding is also accepted by offline mapper validation.
	var finding securitycenterpb.Finding
	if err := protojson.Unmarshal(raw, &finding); err != nil {
		return model.Alert{}, fmt.Errorf("decode GCP finding: %w", err)
	}
	return normalizeFinding(&finding, raw), nil
}
