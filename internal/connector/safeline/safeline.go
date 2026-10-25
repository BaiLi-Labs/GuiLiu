// Package safeline implements the Chaitin SafeLine (雷池) WAF connector using
// the Skyview FilterV2 API that chaitin-cli also targets.
//
// Verified against the published chaitin-cli source (GPL-3.0, used as an
// interface reference only, no code copied):
//   - endpoint GET /api/FilterV2API
//   - header API-Token with the raw token value
//   - scope log:detect_log:optim_limit
//   - query current_page / target_page / count, repeated tail_sort cursor
//   - envelope err / data{items,total} / msg
//   - list scope returns event_id, timestamp, src_ip, host, url_path,
//     attack_type, sort
//
// Still unverified on a live appliance: server-side time filters (only
// reachable through raw filter keys), the risk_level field and the numeric
// encoding of attack_type. Both are handled defensively.
package safeline

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const (
	providerID       = "safeline"
	mapperVersion    = "safeline-filterv2/v1"
	apiVersion       = "filterv2"
	defaultQPS       = 2
	defaultPageSize  = 100
	detectScope      = "log:detect_log:optim_limit"
	detailScope      = "log:detect_log:detail"
	detectPath       = "/api/FilterV2API"
	defaultDetailMax = 10
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "FilterV2API log:detect_log",
		ID:            providerID,
		Name:          "Chaitin SafeLine",
		Vendor:        "Chaitin",
		Product:       "SafeLine WAF",
		ProductUID:    "chaitin.safeline",
		APIVersion:    apiVersion,
		DocsURL:       "https://github.com/chaitin/chaitin-cli/tree/main/products/safeline",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "API Token", Required: true, Secret: true, Help: "雷池控制台生成的 OpenAPI Token，请求头为 API-Token"},
		},
		OptionFields: []connector.OptionField{
			{Name: "endpoint", Label: "SafeLine URL", Required: true, Placeholder: "https://waf.example.com", Help: "雷池控制台地址，不含 /api 路径"},
			{Name: "exclude_body", Label: "Exclude request body", Placeholder: "true", Help: "默认 true，减少响应体积；原始载荷仍完整保留返回的字段"},
			{Name: "insecure", Label: "Skip TLS verification", Placeholder: "false", Help: "雷池使用自签证书时设为 true"},
			{Name: "time_filter", Label: "Time filter", Placeholder: "auto", Help: "auto 先尝试 timestamp__gte/lte，服务端拒绝时自动降级为客户端窗口过滤；off 直接关闭"},
			{Name: "fetch_detail", Label: "Fetch per-event detail", Placeholder: "false", Help: "列表仅返回 7 个字段。开启后逐条调用 detail scope 才能拿到 risk_level、method 与处置动作，成本是每条事件一次请求。社区版实测 risk_level 为 1低/2中/3高，商业版未验证"},
			{Name: "detail_max_page", Label: "Detail requests per page", Placeholder: "10", Help: "每页最多补齐多少条详情，控制 QPS 消耗；未补齐的记录保留列表原始字段"},
		},
		Products: []connector.Product{
			{Code: "SafeLine", Name: "SafeLine WAF"},
			{Code: "DetectLog", Name: "Detection log"},
		},
	}
}

// Connector talks to the SafeLine Skyview API.
type Connector struct {
	endpoint    string
	token       string
	excludeBody bool
	timeFilter  bool
	fetchDetail bool
	detailMax   int
	limiter     *connector.Limiter
	pageSize    int
	client      *http.Client
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.Options["endpoint"]), "/")
	if endpoint == "" {
		return nil, connector.ConfigError(providerID, "endpoint is required")
	}
	token := strings.TrimSpace(cfg.Credential.AccessKeyID)
	if token == "" {
		token = strings.TrimSpace(cfg.Credential.AccessKeySecret)
	}
	if token == "" {
		return nil, connector.ConfigError(providerID, "API token is required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.EqualFold(strings.TrimSpace(cfg.Options["insecure"]), "true") {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Connector{
		endpoint:    endpoint,
		token:       token,
		excludeBody: !strings.EqualFold(strings.TrimSpace(cfg.Options["exclude_body"]), "false"),
		timeFilter:  !strings.EqualFold(strings.TrimSpace(cfg.Options["time_filter"]), "off"),
		fetchDetail: strings.EqualFold(strings.TrimSpace(cfg.Options["fetch_detail"]), "true"),
		detailMax:   connector.OptionInt(cfg.Options, "detail_max_page", defaultDetailMax),
		limiter:     connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize:    connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
		client:      &http.Client{Timeout: 60 * time.Second, Transport: transport},
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

// Check performs one minimal query. A 401/403 from the appliance maps to an
// authentication or permission error, which the console shows as "token
// invalid" rather than "product not entitled".
func (c *Connector) Check(ctx context.Context) error {
	end := time.Now().UTC()
	_, err := c.Fetch(ctx, connector.Query{Start: end.Add(-1 * time.Hour), End: end, PageSize: 1})
	return err
}

// pageToken is self-contained so a process restart can resume the same window.
type pageToken struct {
	Page         int      `json:"p"`
	Tail         []string `json:"t,omitempty"`
	NoTimeFilter bool     `json:"n,omitempty"`
}

func encodeToken(t pageToken) string {
	raw, _ := json.Marshal(t)
	return string(raw)
}

func decodeToken(s string) (pageToken, error) {
	var t pageToken
	if s == "" {
		return t, nil
	}
	if err := json.Unmarshal([]byte(s), &t); err != nil {
		return t, connector.ConfigError(providerID, "invalid page token")
	}
	return t, nil
}

func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	tok, err := decodeToken(q.Token)
	if err != nil {
		return connector.Page{}, err
	}
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = c.pageSize
	}
	if pageSize > 500 {
		pageSize = 500
	}

	items, total, err := c.query(ctx, q, tok, pageSize)
	if err != nil && c.timeFilter && !tok.NoTimeFilter && isParameterError(err) {
		// Older appliances reject the time filter keys. Retry once without them
		// and keep the decision in the token so later pages do not flip-flop.
		tok.NoTimeFilter = true
		items, total, err = c.query(ctx, q, tok, pageSize)
	}
	if err != nil {
		return connector.Page{}, err
	}

	records := make([]connector.RawAlert, 0, len(items))
	lastSort := []string(nil)
	// Without a server-side time filter the appliance returns newest first, so
	// the first record older than the window means every later page is older
	// too. Stopping there avoids scanning the account's entire history on each
	// sync when the API rejects timestamp filters.
	exhausted := false
	for _, raw := range items {
		if len(raw) == 0 || string(raw) == "null" {
			return connector.Page{}, fmt.Errorf("safeline returned an empty record")
		}
		var item struct {
			Timestamp json.RawMessage `json:"timestamp"`
			Sort      json.RawMessage `json:"sort"`
		}
		_ = json.Unmarshal(raw, &item)
		timestamp := scalarText(item.Timestamp)
		if !inWindow(timestamp, q.Start, q.End) {
			if tok.NoTimeFilter && beforeWindow(timestamp, q.Start) {
				exhausted = true
				break
			}
			continue
		}
		if values := sortValues(item.Sort); len(values) > 0 {
			lastSort = values
		}
		records = append(records, connector.RawAlert{Raw: append(json.RawMessage(nil), raw...)})
	}

	// data.total is optional in the appliance envelope. When it is absent, a
	// full page is the only signal that another page exists.
	more := len(items) > 0
	if total != nil {
		more = more && (tok.Page+1)*pageSize < *total
	} else {
		more = more && len(items) >= pageSize
	}
	next := ""
	if !exhausted && more {
		tok.Page++
		tok.Tail = lastSort
		next = encodeToken(tok)
	}
	if c.fetchDetail && len(records) > 0 {
		records, err = c.withDetails(ctx, records)
		if err != nil {
			return connector.Page{}, err
		}
	}

	pageTotal := len(items)
	if total != nil {
		pageTotal = *total
	}
	return connector.Page{Records: records, NextToken: next, Total: pageTotal}, nil
}

// withDetails replaces list records with the detail payload, which is the only
// scope that returns risk_level, method and the disposition action. The list
// record is kept when the detail call fails or when the per-page budget is
// exhausted, so a detail outage cannot drop events.
func (c *Connector) withDetails(ctx context.Context, records []connector.RawAlert) ([]connector.RawAlert, error) {
	limit := c.detailMax
	if limit <= 0 || limit > len(records) {
		limit = len(records)
	}
	out := make([]connector.RawAlert, 0, len(records))
	var firstErr error
	succeeded := 0
	for i, rec := range records {
		if i >= limit {
			out = append(out, rec)
			continue
		}
		var item struct {
			EventID   json.RawMessage `json:"event_id"`
			Timestamp json.RawMessage `json:"timestamp"`
		}
		_ = json.Unmarshal(rec.Raw, &item)
		eventID := scalarText(item.EventID)
		timestamp := scalarText(item.Timestamp)
		if eventID == "" || timestamp == "" {
			out = append(out, rec)
			continue
		}
		detail, err := c.getDetail(ctx, eventID, timestamp)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			out = append(out, rec)
			continue
		}
		succeeded++
		out = append(out, connector.RawAlert{Raw: detail})
	}
	// Every detail call failed: surface the error instead of silently serving
	// list-only records that look complete.
	if succeeded == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func (c *Connector) getDetail(ctx context.Context, eventID, timestamp string) (json.RawMessage, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	query := url.Values{}
	query.Set("scope", detailScope)
	query.Set("event_id__exact", eventID)
	query.Set("timestamp__exact", timestamp)
	requestURL := c.endpoint + detectPath + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, connector.ConfigError(providerID, "invalid endpoint: "+err.Error())
	}
	req.Header.Set("API-Token", c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GuiLiu/"+mapperVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, connector.WithSourceAPI(providerID, "FilterV2API detail", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, connector.WithSourceAPI(providerID, "FilterV2API detail", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, safelineHTTPError(resp.StatusCode, body)
	}
	var envelope struct {
		Err  *string         `json:"err"`
		Data json.RawMessage `json:"data"`
		Msg  json.RawMessage `json:"msg"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode safeline detail envelope: %w", err)
	}
	if envelope.Err != nil && strings.TrimSpace(*envelope.Err) != "" {
		return nil, safelineAPIError(*envelope.Err, envelope.Data, envelope.Msg)
	}
	// The detail scope returns a bare array.
	var items []json.RawMessage
	if err := json.Unmarshal(envelope.Data, &items); err != nil {
		return nil, fmt.Errorf("decode safeline detail: %w", err)
	}
	if len(items) == 0 || len(items[0]) == 0 || string(items[0]) == "null" {
		return nil, fmt.Errorf("safeline detail is empty for event %s", eventID)
	}
	return append(json.RawMessage(nil), items[0]...), nil
}

func beforeWindow(value string, start time.Time) bool {
	if start.IsZero() {
		return false
	}
	t, ok := parseTimestamp(value)
	return ok && t.Before(start)
}

func (c *Connector) query(ctx context.Context, q connector.Query, tok pageToken, pageSize int) ([]json.RawMessage, *int, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, nil, err
	}
	query := url.Values{}
	query.Set("scope", detectScope)
	if c.excludeBody {
		query.Set("exclude_body", "true")
	}
	query.Set("current_page", strconv.Itoa(tok.Page))
	query.Set("target_page", strconv.Itoa(tok.Page+1))
	query.Set("count", strconv.Itoa(pageSize))
	if c.timeFilter && !tok.NoTimeFilter && !q.Start.IsZero() && !q.End.IsZero() {
		query.Set("timestamp__gte", strconv.FormatInt(q.Start.Unix(), 10))
		query.Set("timestamp__lte", strconv.FormatInt(q.End.Unix(), 10))
	}
	for _, value := range tok.Tail {
		query.Add("tail_sort", value)
	}

	requestURL := c.endpoint + detectPath + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, nil, connector.ConfigError(providerID, "invalid endpoint: "+err.Error())
	}
	req.Header.Set("API-Token", c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GuiLiu/"+mapperVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, connector.WithSourceAPI(providerID, "FilterV2API", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, nil, connector.WithSourceAPI(providerID, "FilterV2API", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, safelineHTTPError(resp.StatusCode, body)
	}

	var envelope struct {
		Err  *string         `json:"err"`
		Data json.RawMessage `json:"data"`
		Msg  json.RawMessage `json:"msg"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, nil, fmt.Errorf("decode safeline envelope: %w", err)
	}
	if envelope.Err != nil && strings.TrimSpace(*envelope.Err) != "" {
		return nil, nil, safelineAPIError(*envelope.Err, envelope.Data, envelope.Msg)
	}
	var data struct {
		Items []json.RawMessage `json:"items"`
		Total *int              `json:"total"`
	}
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		// The detail scope returns an array; the list scope must be paginated.
		return nil, nil, fmt.Errorf("decode safeline page: %w", err)
	}
	return data.Items, data.Total, nil
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalize(raw)
}

// inWindow filters locally because older appliances may not support the time
// filter. An unparsable or missing timestamp stays unknown rather than being
// dropped silently.
func inWindow(value string, start, end time.Time) bool {
	if start.IsZero() || end.IsZero() {
		return true
	}
	t, ok := parseTimestamp(value)
	if !ok {
		return true
	}
	return !t.Before(start) && !t.After(end)
}

func parseTimestamp(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			if t, ok := connector.ParseVendorTime(value); ok {
				return t, true
			}
			return time.Time{}, false
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	switch len(value) {
	case 13:
		return time.UnixMilli(n).UTC(), true
	default:
		return time.Unix(n, 0).UTC(), true
	}
}

func sortValues(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var values []any
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		switch v := value.(type) {
		case string:
			out = append(out, v)
		case float64:
			out = append(out, strconv.FormatFloat(v, 'f', -1, 64))
		case json.Number:
			out = append(out, v.String())
		default:
			out = append(out, fmt.Sprintf("%v", v))
		}
	}
	return out
}

func isParameterError(err error) bool {
	var classified *connector.Error
	if errors.As(err, &classified) {
		return isParameterErrorText(strings.ToLower(classified.Message))
	}
	return isParameterErrorText(strings.ToLower(err.Error()))
}
