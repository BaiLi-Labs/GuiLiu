// Package crowdstrike implements the CrowdStrike Falcon Alerts v2 connector.
// Authentication is OAuth2 client credentials; the alerts API is plain REST, so
// the client is written directly to keep every resource byte-preserving.
package crowdstrike

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const (
	providerID      = "crowdstrike"
	mapperVersion   = "crowdstrike-alerts-v2/v1"
	apiVersion      = "v2"
	defaultBaseURL  = "https://api.crowdstrike.com"
	defaultQPS      = 4
	defaultPageSize = 100
	alertsPath      = "/alerts/entities/alerts/v2"
	queryPath       = "/alerts/queries/alerts/v2"
	tokenPath       = "/oauth2/token"
	maxOffset       = 10000
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "Falcon Alerts v2",
		ID:            providerID,
		Name:          "CrowdStrike Falcon",
		Vendor:        "CrowdStrike",
		Product:       "Falcon Insight",
		ProductUID:    "crowdstrike.falcon",
		APIVersion:    apiVersion,
		DocsURL:       "https://developer.crowdstrike.com/",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "Client ID", Required: true, Help: "API client ID with Alerts:read scope"},
			{Name: "access_key_secret", Label: "Client Secret", Required: true, Secret: true},
		},
		OptionFields: []connector.OptionField{
			{Name: "base_url", Label: "API base URL", Placeholder: defaultBaseURL, Help: "按 Falcon 云区选择：US-1 默认，EU-1 为 https://api.eu-1.crowdstrike.com，US-2 为 https://api.us-2.crowdstrike.com"},
			{Name: "member_cid", Label: "Member CID", Help: "MSSP 子租户，可选"},
		},
		Products: []connector.Product{
			{Code: "Alerts", Name: "Falcon Alerts"},
		},
	}
}

// Connector talks to the Falcon alerts API.
type Connector struct {
	baseURL      string
	clientID     string
	clientSecret string
	memberCID    string
	limiter      *connector.Limiter
	pageSize     int
	client       *http.Client

	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	clientID := strings.TrimSpace(cfg.Credential.AccessKeyID)
	clientSecret := cfg.Credential.AccessKeySecret
	if clientID == "" || clientSecret == "" {
		return nil, connector.ConfigError(providerID, "Client ID and Client Secret are required")
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.Options["base_url"]), "/")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Connector{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		memberCID:    strings.TrimSpace(cfg.Options["member_cid"]),
		limiter:      connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize:     connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
		client:       &http.Client{Timeout: 60 * time.Second},
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

// Check validates the OAuth2 client and the Alerts read scope with one page.
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
	if pageSize > 500 {
		pageSize = 500
	}
	offset := 0
	if token := strings.TrimSpace(q.Token); token != "" {
		parsed, err := strconv.Atoi(token)
		if err != nil || parsed < 0 {
			return connector.Page{}, connector.ConfigError(providerID, "invalid page token")
		}
		offset = parsed
	}
	if offset >= maxOffset {
		return connector.Page{}, fmt.Errorf("crowdstrike alerts offset reached the API limit of %d", maxOffset)
	}

	token, err := c.accessToken(ctx)
	if err != nil {
		return connector.Page{}, err
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(pageSize))
	query.Set("offset", strconv.Itoa(offset))
	query.Set("sort", "timestamp|desc")
	if !q.Start.IsZero() && !q.End.IsZero() {
		query.Set("filter", fmt.Sprintf("timestamp:>'%s'+timestamp:<'%s'",
			q.Start.UTC().Format(time.RFC3339), q.End.UTC().Format(time.RFC3339)))
	}
	var payload struct {
		Meta struct {
			Pagination struct {
				Offset int `json:"offset"`
				Limit  int `json:"limit"`
				Total  int `json:"total"`
			} `json:"pagination"`
		} `json:"meta"`
		Resources []string `json:"resources"`
	}
	if err := c.request(ctx, http.MethodGet, queryPath+"?"+query.Encode(), token, nil, &payload); err != nil {
		return connector.Page{}, err
	}
	// Query returns IDs only. Fetch the full entities before committing this
	// page, so a failed detail request cannot advance the collection cursor.
	var details struct {
		Resources []json.RawMessage `json:"resources"`
	}
	if len(payload.Resources) > 0 {
		body, err := json.Marshal(map[string]any{"composite_ids": payload.Resources})
		if err != nil {
			return connector.Page{}, err
		}
		if err := c.request(ctx, http.MethodPost, alertsPath, token, body, &details); err != nil {
			return connector.Page{}, err
		}
		if len(details.Resources) != len(payload.Resources) {
			return connector.Page{}, fmt.Errorf("crowdstrike returned %d entities for %d alert IDs", len(details.Resources), len(payload.Resources))
		}
	}
	records := make([]connector.RawAlert, 0, len(details.Resources))
	for _, raw := range details.Resources {
		if len(raw) == 0 || string(raw) == "null" {
			return connector.Page{}, fmt.Errorf("crowdstrike returned an empty alert")
		}
		records = append(records, connector.RawAlert{Raw: append(json.RawMessage(nil), raw...)})
	}
	total := payload.Meta.Pagination.Total
	next := ""
	if offset+len(records) < total && len(records) > 0 {
		next = strconv.Itoa(offset + len(records))
	}
	return connector.Page{Records: records, NextToken: next, Total: total}, nil
}

func (c *Connector) request(ctx context.Context, method, path, token string, body []byte, target any) error {
	if err := c.limiter.Wait(ctx); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return connector.ConfigError(providerID, "invalid request URL: "+err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GuiLiu/"+mapperVersion)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.memberCID != "" {
		req.Header.Set("X-CS-Member-CID", c.memberCID)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return connector.WithSourceAPI(providerID, "Falcon Alerts v2", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return connector.WithSourceAPI(providerID, "Falcon Alerts v2", err)
	}
	if resp.StatusCode != http.StatusOK {
		return apiError(resp.StatusCode, payload, method+" "+strings.SplitN(path, "?", 2)[0])
	}
	var envelope struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return fmt.Errorf("decode crowdstrike response: %w", err)
	}
	if len(envelope.Errors) > 0 {
		return apiErrors(envelope.Errors[0].Code, envelope.Errors[0].Message)
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("decode crowdstrike response: %w", err)
	}
	return nil
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalize(raw)
}

// accessToken caches the OAuth2 token until shortly before expiry. The token
// endpoint is not part of the alerts quota, so it bypasses the limiter.
func (c *Connector) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && time.Now().Before(c.tokenExpiry.Add(-30*time.Second)) {
		token := c.token
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("grant_type", "client_credentials")
	if c.memberCID != "" {
		form.Set("member_cid", c.memberCID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+tokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return "", connector.ConfigError(providerID, "invalid token URL: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", connector.WithSourceAPI(providerID, "OAuth2 token", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", connector.WithSourceAPI(providerID, "OAuth2 token", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", apiError(resp.StatusCode, body, c.baseURL+tokenPath)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return "", fmt.Errorf("decode crowdstrike token: %w", err)
	}
	if token.AccessToken == "" {
		return "", &connector.Error{
			Provider: providerID, SourceAPI: "OAuth2 token", Kind: connector.KindAuth,
			Code: "missing_access_token", Message: "OAuth2 response did not contain an access token",
		}
	}
	expiry := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	if token.ExpiresIn <= 0 {
		expiry = time.Now().Add(5 * time.Minute)
	}

	c.mu.Lock()
	c.token, c.tokenExpiry = token.AccessToken, expiry
	c.mu.Unlock()
	return token.AccessToken, nil
}
