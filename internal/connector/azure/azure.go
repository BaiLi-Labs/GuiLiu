// Package azure implements the Microsoft Defender for Cloud connector using
// the Azure Resource Manager Security alerts API.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const (
	providerID      = "azure"
	mapperVersion   = "azure-defender/v3"
	apiVersion      = "2022-01-01"
	defaultEndpoint = "https://management.azure.com"
	defaultQPS      = 3
	alertsPath      = "/subscriptions/%s/providers/Microsoft.Security/alerts?api-version=" + apiVersion
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "Defender for Cloud ARM Alerts - List",
		ID:            providerID,
		Name:          "Microsoft Azure",
		Vendor:        "Microsoft",
		Product:       "Microsoft Defender for Cloud",
		ProductUID:    "azure.defender",
		APIVersion:    apiVersion,
		DocsURL:       "https://learn.microsoft.com/rest/api/defenderforcloud/alerts/list?view=rest-defenderforcloud-2022-01-01",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "Client ID", Help: "Service Principal Client ID；留空使用 DefaultAzureCredential / Managed Identity"},
			{Name: "access_key_secret", Label: "Client Secret", Secret: true, Help: "Service Principal Client Secret；与 Client ID、Tenant ID 一起使用"},
		},
		OptionFields: []connector.OptionField{
			{Name: "subscription_id", Label: "Subscription ID", Required: true, Placeholder: "Azure subscription UUID"},
			{Name: "tenant_id", Label: "Tenant ID", Placeholder: "使用 Client Secret 时必填"},
			{Name: "endpoint", Label: "ARM Endpoint", Placeholder: "默认 https://management.azure.com"},
		},
		Products: []connector.Product{
			{Code: "DefenderForCloud", Name: "Defender for Cloud"},
		},
	}
}

// Connector talks to the ARM Security alerts API.
type Connector struct {
	credential     azcore.TokenCredential
	subscriptionID string
	endpoint       string
	scope          string
	limiter        *connector.Limiter
	client         *http.Client
}

// New builds an Azure connector. It deliberately does not make a network call;
// credential validation happens in Check.
func New(cfg connector.AccountConfig) (connector.Connector, error) {
	subscriptionID := strings.TrimSpace(cfg.Options["subscription_id"])
	if subscriptionID == "" {
		subscriptionID = strings.TrimSpace(cfg.AccountUID)
	}
	if subscriptionID == "" {
		return nil, connector.ConfigError(providerID, "subscription_id option or account_uid is required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Options["endpoint"]), "/")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	clientID := strings.TrimSpace(cfg.Credential.AccessKeyID)
	clientSecret := cfg.Credential.AccessKeySecret
	tenantID := strings.TrimSpace(cfg.Options["tenant_id"])
	var credential azcore.TokenCredential
	var err error
	switch {
	case clientID == "" && clientSecret == "":
		credential, err = azidentity.NewDefaultAzureCredential(nil)
	case clientID == "" || clientSecret == "":
		return nil, connector.ConfigError(providerID, "Client ID and Client Secret must be provided together")
	case tenantID == "":
		return nil, connector.ConfigError(providerID, "tenant_id is required when Client Secret is used")
	default:
		credential, err = azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	}
	if err != nil {
		return nil, connector.ConfigError(providerID, "create Azure credential: "+err.Error())
	}
	return &Connector{
		credential:     credential,
		subscriptionID: subscriptionID,
		endpoint:       endpoint,
		scope:          endpoint + "/.default",
		limiter:        connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		client:         &http.Client{Timeout: 60 * time.Second},
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

func (c *Connector) Check(ctx context.Context) error {
	end := time.Now().UTC()
	_, err := c.Fetch(ctx, connector.Query{Start: end.Add(-time.Hour), End: end, PageSize: 1})
	return err
}

// Fetch pulls one ARM page. The ARM API exposes no server-side time filter, so
// records are filtered by their UTC timestamps after decoding. The nextLink is
// retained as the opaque page token.
func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	if err := ctx.Err(); err != nil {
		return connector.Page{}, err
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return connector.Page{}, err
	}
	requestURL := strings.TrimRight(c.endpoint, "/") + fmt.Sprintf(alertsPath, url.PathEscape(c.subscriptionID))
	if token := strings.TrimSpace(q.Token); token != "" {
		requestURL = token
	}
	token, err := c.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{c.scope}})
	if err != nil {
		return connector.Page{}, &connector.Error{
			Provider: providerID,
			Kind:     connector.KindAuth,
			Code:     "auth",
			Message:  "get Azure token: " + err.Error(),
			Err:      err,
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return connector.Page{}, connector.ConfigError(providerID, "invalid Azure request: "+err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GuiLiu/"+mapperVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return connector.Page{}, connector.Classify(providerID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return connector.Page{}, azureHTTPError(resp)
	}
	var payload struct {
		NextLink string            `json:"nextLink"`
		Value    []json.RawMessage `json:"value"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 64<<20))
	if err := dec.Decode(&payload); err != nil {
		return connector.Page{}, fmt.Errorf("decode Azure alerts: %w", err)
	}
	records := make([]connector.RawAlert, 0, len(payload.Value))
	for _, raw := range payload.Value {
		var alert armsecurity.Alert
		if err := json.Unmarshal(raw, &alert); err != nil {
			return connector.Page{}, fmt.Errorf("decode Azure alert: %w", err)
		}
		if !alertInWindow(&alert, q.Start, q.End) {
			continue
		}
		records = append(records, connector.RawAlert{Raw: append(json.RawMessage(nil), raw...)})
	}
	return connector.Page{Records: records, NextToken: payload.NextLink, Total: len(records)}, nil
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalizeAlert(raw)
}

func alertInWindow(a *armsecurity.Alert, start, end time.Time) bool {
	if start.IsZero() || end.IsZero() {
		return true
	}
	p := a.Properties
	if p == nil {
		return true
	}
	times := []*time.Time{p.TimeGeneratedUTC, p.StartTimeUTC, p.EndTimeUTC, p.ProcessingEndTimeUTC}
	hasTime := false
	for _, t := range times {
		if t == nil || t.IsZero() {
			continue
		}
		hasTime = true
		if !t.Before(start) && !t.After(end) {
			return true
		}
	}
	return !hasTime
}

func azureHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	msg := fmt.Sprintf("Azure alerts API %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return &connector.Error{Provider: providerID, Kind: connector.KindAuth, Code: "auth", Message: msg}
	case resp.StatusCode == http.StatusTooManyRequests:
		return &connector.Error{Provider: providerID, Kind: connector.KindThrottled, Code: "throttled", Message: msg}
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500:
		return &connector.Error{Provider: providerID, Kind: connector.KindTransient, Code: "transient", Message: msg}
	default:
		return connector.Classify(providerID, errors.New(msg))
	}
}
