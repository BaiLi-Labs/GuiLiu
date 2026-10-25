// Package cloudflare implements the Cloudflare WAF Security Events connector
// backed by the GraphQL Analytics API (firewallEventsAdaptive dataset).
//
// Cloudflare exposes no SDK for GraphQL, so the client is a plain JSON POST.
// That is also what keeps each event byte-preserving for replay.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const (
	providerID      = "cloudflare"
	mapperVersion   = "cloudflare-firewall-events/v1"
	apiVersion      = "graphql"
	defaultEndpoint = "https://api.cloudflare.com/client/v4/graphql"
	defaultQPS      = 4
	defaultPageSize = 1000
	defaultChunk    = 6 * time.Hour
	minChunk        = time.Second
)

const eventsQuery = `query GuiliuFirewallEvents($zoneTag: string!, $filter: FirewallEventsAdaptiveFilter_InputObject, $limit: int!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(filter: $filter, limit: $limit, orderBy: [datetime_ASC]) {
        action
        source
        clientIP
        clientASN
        clientCountryName
        clientRequestPath
        clientRequestQuery
        userAgent
        datetime
        ruleId
      }
    }
  }
}`

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "GraphQL firewallEventsAdaptive",
		ID:            providerID,
		Name:          "Cloudflare",
		Vendor:        "Cloudflare",
		Product:       "WAF Security Events",
		ProductUID:    "cloudflare.waf",
		APIVersion:    apiVersion,
		DocsURL:       "https://developers.cloudflare.com/waf/analytics/security-events/",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "API Token", Required: true, Secret: true, Help: "需要 Zone Analytics Read 与 Zone WAF Read 权限"},
		},
		OptionFields: []connector.OptionField{
			{Name: "zone_id", Label: "Zone ID", Required: true, Help: "一个账号对应一个 zone；多 zone 请建立多个账号"},
			{Name: "endpoint", Label: "GraphQL endpoint", Placeholder: defaultEndpoint},
			{Name: "severity_from_action", Label: "Derive severity from action", Placeholder: "false", Help: "Cloudflare 不提供事件等级。设为 true 时按处置动作推导，映射会标记为推导值"},
		},
		Products: []connector.Product{
			{Code: "WAF", Name: "WAF Security Events"},
		},
	}
}

// Connector reads WAF security events for one zone.
type Connector struct {
	endpoint       string
	token          string
	zoneID         string
	severityAction bool
	limiter        *connector.Limiter
	pageSize       int
	client         *http.Client
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	token := strings.TrimSpace(cfg.Credential.AccessKeyID)
	if token == "" {
		return nil, connector.ConfigError(providerID, "API token is required")
	}
	zoneID := strings.TrimSpace(cfg.Options["zone_id"])
	if zoneID == "" {
		return nil, connector.ConfigError(providerID, "zone_id is required")
	}
	endpoint := strings.TrimSpace(cfg.Options["endpoint"])
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	return &Connector{
		endpoint:       endpoint,
		token:          token,
		zoneID:         zoneID,
		severityAction: strings.EqualFold(strings.TrimSpace(cfg.Options["severity_from_action"]), "true"),
		limiter:        connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize:       connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
		client:         &http.Client{Timeout: 60 * time.Second},
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

// Check reads one event from the last hour. A missing permission surfaces as a
// permission error rather than an empty result.
func (c *Connector) Check(ctx context.Context) error {
	end := time.Now().UTC()
	_, err := c.Fetch(ctx, connector.Query{Start: end.Add(-1 * time.Hour), End: end, PageSize: 1})
	return err
}

// pageToken describes the remaining part of the requested window. Cloudflare
// GraphQL has no offset cursor, so pagination advances over time slices. A
// slice that fills the page limit is halved instead of advancing, which keeps
// dense attack bursts from being silently truncated.
type pageToken struct {
	Start string `json:"s"`
	End   string `json:"e"`
	Next  string `json:"n"`
	Chunk int64  `json:"c"` // nanoseconds
}

func encodeToken(t pageToken) string {
	raw, _ := json.Marshal(t)
	return string(raw)
}

func decodeToken(s string, q connector.Query) (pageToken, error) {
	if strings.TrimSpace(s) == "" {
		return pageToken{
			Start: q.Start.UTC().Format(time.RFC3339Nano),
			End:   q.End.UTC().Format(time.RFC3339Nano),
			Next:  q.Start.UTC().Format(time.RFC3339Nano),
			Chunk: int64(defaultChunk),
		}, nil
	}
	var t pageToken
	if err := json.Unmarshal([]byte(s), &t); err != nil {
		return t, connector.ConfigError(providerID, "invalid page token")
	}
	if t.Chunk <= 0 {
		t.Chunk = int64(defaultChunk)
	}
	return t, nil
}

func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = c.pageSize
	}
	if pageSize > 10000 {
		pageSize = 10000
	}

	tok, err := decodeToken(q.Token, q)
	if err != nil {
		return connector.Page{}, err
	}
	windowStart, err := time.Parse(time.RFC3339Nano, tok.Start)
	if err != nil {
		return connector.Page{}, connector.ConfigError(providerID, "invalid window start in token")
	}
	windowEnd, err := time.Parse(time.RFC3339Nano, tok.End)
	if err != nil {
		return connector.Page{}, connector.ConfigError(providerID, "invalid window end in token")
	}
	next, err := time.Parse(time.RFC3339Nano, tok.Next)
	if err != nil {
		return connector.Page{}, connector.ConfigError(providerID, "invalid cursor in token")
	}
	chunk := time.Duration(tok.Chunk)
	if chunk < minChunk {
		chunk = minChunk
	}
	sliceEnd := next.Add(chunk)
	if sliceEnd.After(windowEnd) {
		sliceEnd = windowEnd
	}

	events, err := c.query(ctx, next, sliceEnd, pageSize)
	if err != nil {
		return connector.Page{}, err
	}

	records := make([]connector.RawAlert, 0, len(events))
	for _, raw := range events {
		if len(raw) == 0 || string(raw) == "null" {
			return connector.Page{}, fmt.Errorf("cloudflare returned an empty event")
		}
		records = append(records, connector.RawAlert{Raw: append(json.RawMessage(nil), raw...)})
	}

	tok.Start = windowStart.Format(time.RFC3339Nano)
	tok.End = windowEnd.Format(time.RFC3339Nano)
	if len(events) >= pageSize {
		if sliceEnd.Sub(next) <= minChunk {
			return connector.Page{}, &connector.Error{
				Provider: providerID, SourceAPI: "GraphQL firewallEventsAdaptive",
				Kind: connector.KindPermanent, Code: "window_saturated",
				Message: "result limit reached in the minimum time slice; collection cursor was not advanced; increase page_size",
			}
		}
		// The slice is saturated: narrow it and re-read the same range.
		narrowed := (sliceEnd.Sub(next) / 2).Truncate(time.Second)
		if narrowed < minChunk {
			narrowed = minChunk
		}
		tok.Chunk = int64(narrowed)
		tok.Next = next.Format(time.RFC3339Nano)
	} else {
		tok.Chunk = int64(defaultChunk)
		tok.Next = sliceEnd.Format(time.RFC3339Nano)
	}

	nextToken := ""
	if sliceEnd.Before(windowEnd) || tok.Next != windowEnd.Format(time.RFC3339Nano) {
		nextToken = encodeToken(tok)
	}
	return connector.Page{Records: records, NextToken: nextToken, Total: len(records)}, nil
}

type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

type graphQLError struct {
	Message    string `json:"message"`
	Extensions struct {
		Code string `json:"code"`
	} `json:"extensions"`
}

func (c *Connector) query(ctx context.Context, start, end time.Time, limit int) ([]json.RawMessage, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	body, err := json.Marshal(graphQLRequest{
		Query: eventsQuery,
		Variables: map[string]any{
			"zoneTag": c.zoneID,
			"limit":   limit,
			"filter": map[string]any{
				"datetime_geq": start.UTC().Format(time.RFC3339),
				"datetime_leq": end.UTC().Format(time.RFC3339),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encode cloudflare query: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, connector.ConfigError(providerID, "invalid endpoint: "+err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GuiLiu/"+mapperVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, connector.WithSourceAPI(providerID, "GraphQL firewallEventsAdaptive", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, connector.WithSourceAPI(providerID, "GraphQL firewallEventsAdaptive", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, httpError(resp.StatusCode, payload)
	}

	var parsed struct {
		Data struct {
			Viewer struct {
				Zones []struct {
					Events []json.RawMessage `json:"firewallEventsAdaptive"`
				} `json:"zones"`
			} `json:"viewer"`
		} `json:"data"`
		Errors []graphQLError `json:"errors"`
	}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil, fmt.Errorf("decode cloudflare response: %w", err)
	}
	if len(parsed.Errors) > 0 {
		return nil, graphQLErrorOf(parsed.Errors[0])
	}
	if len(parsed.Data.Viewer.Zones) == 0 {
		return nil, &connector.Error{
			Provider: providerID, SourceAPI: "GraphQL firewallEventsAdaptive",
			Kind: connector.KindPermission, Code: "zone_not_visible",
			Message: "the zone is not visible to this token (check zone_id and token scope)",
		}
	}
	return parsed.Data.Viewer.Zones[0].Events, nil
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalize(raw, c.severityAction, c.zoneID)
}
