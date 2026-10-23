// Package defender implements the Microsoft Defender XDR connector backed by
// the Microsoft Graph security alerts_v2 API. It is separate from the existing
// "azure" connector, which reads Defender for Cloud alerts from Azure Resource
// Manager: different API, different permission model, different alert shape.
package defender

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const (
	providerID      = "defender"
	mapperVersion   = "microsoft-defender-graph/v1"
	apiVersion      = "v1.0"
	defaultEndpoint = "https://graph.microsoft.com"
	defaultQPS      = 4
	defaultPageSize = 100
	alertsPath      = "/v1.0/security/alerts_v2"
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "Microsoft Graph security alerts_v2",
		ID:            providerID,
		Name:          "Microsoft Defender",
		Vendor:        "Microsoft",
		Product:       "Microsoft Defender XDR",
		ProductUID:    "microsoft.defender.xdr",
		APIVersion:    apiVersion,
		DocsURL:       "https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "Application (client) ID", Required: true},
			{Name: "access_key_secret", Label: "Client secret", Required: true, Secret: true},
		},
		OptionFields: []connector.OptionField{
			{Name: "tenant_id", Label: "Directory (tenant) ID", Required: true},
			{Name: "endpoint", Label: "Graph endpoint", Placeholder: defaultEndpoint, Help: "国际云使用默认值；该 Graph 安全接口不支持世纪互联中国云"},
		},
		Products: []connector.Product{
			{Code: "DefenderXDR", Name: "Defender XDR alerts"},
		},
	}
}

// Connector reads alerts from Microsoft Graph.
type Connector struct {
	credential azcore.TokenCredential
	endpoint   string
	scope      string
	limiter    *connector.Limiter
	pageSize   int
	client     *http.Client
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	clientID := strings.TrimSpace(cfg.Credential.AccessKeyID)
	clientSecret := cfg.Credential.AccessKeySecret
	tenantID := strings.TrimSpace(cfg.Options["tenant_id"])
	if clientID == "" || clientSecret == "" {
		return nil, connector.ConfigError(providerID, "Application ID and client secret are required")
	}
	if tenantID == "" {
		return nil, connector.ConfigError(providerID, "tenant_id is required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Options["endpoint"]), "/")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	credential, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, connector.ConfigError(providerID, "create Microsoft credential: "+err.Error())
	}
	return &Connector{
		credential: credential,
		endpoint:   endpoint,
		scope:      endpoint + "/.default",
		limiter:    connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize:   connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
		client:     &http.Client{Timeout: 60 * time.Second},
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

// Check validates the service principal, the tenant consent and the
// SecurityAlert.Read.All permission by reading a single alert.
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

	requestURL := strings.TrimSpace(q.Token)
	if requestURL == "" {
		query := url.Values{}
		query.Set("$top", strconv.Itoa(pageSize))
		if !q.Start.IsZero() && !q.End.IsZero() {
			// lastUpdateDateTime matches GuiLiu's incremental semantics: a status
			// change is a real change even when the alert was created earlier.
			query.Set("$filter", fmt.Sprintf(
				"lastUpdateDateTime ge %s and lastUpdateDateTime le %s",
				q.Start.UTC().Format(time.RFC3339), q.End.UTC().Format(time.RFC3339)))
		}
		requestURL = c.endpoint + alertsPath + "?" + query.Encode()
	}

	if err := c.limiter.Wait(ctx); err != nil {
		return connector.Page{}, err
	}
	token, err := c.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{c.scope}})
	if err != nil {
		return connector.Page{}, connector.WithSourceAPI(providerID, "Microsoft Identity token", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return connector.Page{}, connector.ConfigError(providerID, "invalid Graph request: "+err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GuiLiu/"+mapperVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return connector.Page{}, connector.WithSourceAPI(providerID, "Graph alerts_v2", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return connector.Page{}, connector.WithSourceAPI(providerID, "Graph alerts_v2", err)
	}
	if resp.StatusCode != http.StatusOK {
		return connector.Page{}, graphError(resp.StatusCode, body)
	}

	var payload struct {
		Value    []json.RawMessage `json:"value"`
		NextLink string            `json:"@odata.nextLink"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return connector.Page{}, fmt.Errorf("decode defender alerts: %w", err)
	}
	records := make([]connector.RawAlert, 0, len(payload.Value))
	for _, raw := range payload.Value {
		if len(raw) == 0 || string(raw) == "null" {
			return connector.Page{}, fmt.Errorf("defender returned an empty alert")
		}
		records = append(records, connector.RawAlert{Raw: append(json.RawMessage(nil), raw...)})
	}
	return connector.Page{Records: records, NextToken: payload.NextLink, Total: len(records)}, nil
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalize(raw)
}
