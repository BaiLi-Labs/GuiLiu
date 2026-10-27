// Package elasticsearch adapts an existing Elasticsearch deployment as an
// upstream, read-only event source. Elasticsearch is never GuiLiu's database.
package elasticsearch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const mapperVersion = "elasticsearch-event/v1"
const sourceAPI = "Elasticsearch Search API"

var descriptor = connector.Descriptor{
	ID: "elasticsearch", Name: "Elasticsearch", Vendor: "Elastic", Product: "安全日志事件",
	SourceAPI: sourceAPI, APIVersion: "7.12+ Search / PIT REST", MapperVersion: mapperVersion,
	DocsURL:   "https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-search",
	QueryOnly: true, DataTypes: []string{"event"},
	Credential: []connector.CredentialField{
		{Name: "access_key_id", Label: "用户名（仅 Basic 认证）", Help: "使用 API Key 或 Bearer 时留空。"},
		{Name: "access_key_secret", Label: "API Key / 密码 / Bearer Token", Secret: true, Required: true, Help: "API Key 使用 Elasticsearch 返回的 encoded 值，无需添加 ApiKey 前缀。"},
	},
	OptionFields: []connector.OptionField{
		{Name: "endpoint", Label: "Elasticsearch 地址", Required: true, Placeholder: "https://es.example.com:9200", Help: "已有 Elasticsearch 服务地址，凭据单独加密保存。"},
		{Name: "indices", Label: "索引 / 别名范围", Required: true, Placeholder: "logs-web-*,logs-app-*", Help: "多个索引、别名或数据流用逗号分隔，所有查询均限于配置范围。"},
		{Name: "auth_type", Label: "认证方式", Default: "api_key", Choices: []string{"api_key", "basic", "bearer"}, Help: "支持 API Key、用户名密码（Basic）和 Bearer，请使用专用只读凭据。"},
		{Name: "field_mapping", Label: "事件字段映射（JSON）", Multiline: true, Placeholder: `{"event_time":"@timestamp","message":"message"}`, Help: "默认使用 ECS 字段。可覆盖时间、消息、主机、IP、用户等来源路径；空路径禁用可选字段。"},
		{Name: "timestamp_format", Label: "时间戳格式", Placeholder: "date", Help: "date（默认，ISO 日期或 epoch 毫秒）、epoch_millis 或 epoch_seconds，同时用于查询与映射。"},
		{Name: "ca_cert", Label: "自定义 CA 证书（PEM）", Multiline: true, Help: "私有 HTTPS 可填写信任的 CA 证书，始终验证服务端证书。"},
	},
}

var defaultMapping = map[string]string{
	"event_time": "@timestamp", "message": "message", "host_ids": "host.id", "host_names": "host.name",
	"source_ips": "source.ip", "destination_ips": "destination.ip", "users": "user.name",
	"actions": "event.action", "categories": "event.category", "datasets": "event.dataset", "source_severity": "log.level",
}

var indexName = regexp.MustCompile(`^[a-z0-9_.*+][a-z0-9_.*+-]{0,254}$`)
var fieldName = regexp.MustCompile(`^[A-Za-z@][A-Za-z0-9_.@-]{0,255}$`)

type Connector struct {
	cfg     connector.AccountConfig
	base    *url.URL
	indices []string
	mapping map[string]string
	format  string
	auth    string
	client  *http.Client
}

func init() { connector.Register(descriptor, New) }

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	bad := func(message string) (connector.Connector, error) {
		return nil, connector.ConfigError(descriptor.ID, message)
	}
	u, err := url.Parse(strings.TrimSpace(cfg.Options["endpoint"]))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return bad("endpoint must be an HTTP(S) URL without embedded credentials, query or fragment")
	}
	indices := strings.Split(cfg.Options["indices"], ",")
	if len(indices) > 16 {
		return bad("at most 16 index patterns are allowed")
	}
	for i := range indices {
		indices[i] = strings.TrimSpace(indices[i])
		if !indexName.MatchString(indices[i]) || indices[i] == "_all" {
			return bad("indices must contain explicit local index, alias or data stream patterns")
		}
	}
	authType := strings.TrimSpace(cfg.Options["auth_type"])
	if authType == "" {
		authType = "api_key"
	}
	if authType != "api_key" && authType != "basic" && authType != "bearer" {
		return bad("auth_type must be api_key, basic or bearer")
	}
	if cfg.Credential.AccessKeySecret == "" || strings.ContainsAny(cfg.Credential.AccessKeySecret, "\r\n") {
		return bad("a source credential is required")
	}
	if authType == "basic" && (cfg.Credential.AccessKeyID == "" || strings.ContainsAny(cfg.Credential.AccessKeyID, ":\r\n")) {
		return bad("Basic authentication requires a username without a colon")
	}
	mapping := make(map[string]string, len(defaultMapping))
	for key, path := range defaultMapping {
		mapping[key] = path
	}
	if raw := cfg.Options["field_mapping"]; raw != "" {
		var custom map[string]string
		if json.Unmarshal([]byte(raw), &custom) != nil || custom == nil {
			return bad("field_mapping must be a JSON object of normalized field names and source paths")
		}
		for key, path := range custom {
			if _, ok := defaultMapping[key]; !ok {
				return bad("field_mapping contains an unsupported normalized field")
			}
			if path != "" && !fieldName.MatchString(path) {
				return bad("field_mapping contains an invalid source path")
			}
			mapping[key] = path
		}
	}
	if mapping["event_time"] == "" {
		return bad("event_time mapping is required for bounded event queries")
	}
	format := cfg.Options["timestamp_format"]
	if format == "" {
		format = "date"
	}
	if format != "date" && format != "epoch_millis" && format != "epoch_seconds" {
		return bad("timestamp_format must be date, epoch_millis or epoch_seconds")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if pem := cfg.Options["ca_cert"]; pem != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return bad("ca_cert must contain a PEM CA certificate")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &Connector{cfg: cfg, base: u, indices: indices, mapping: mapping, format: format, auth: authType,
		client: &http.Client{Timeout: 12 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor }
func (c *Connector) Close() error               { c.client.CloseIdleConnections(); return nil }
func (c *Connector) Fetch(context.Context, connector.Query) (connector.Page, error) {
	return connector.Page{}, connector.ConfigError(descriptor.ID, "use explicit event queries; this source does not poll Findings")
}
func (c *Connector) Normalize(json.RawMessage) (model.Alert, error) {
	return model.Alert{}, connector.ConfigError(descriptor.ID, "Elasticsearch events are not Findings")
}

func (c *Connector) Check(ctx context.Context) error {
	var response searchResponse
	if err := c.request(ctx, http.MethodPost, c.scopePath("_search"), map[string]any{"size": 0, "query": map[string]any{"match_all": map[string]any{}}, "timeout": "5s", "track_total_hits": false}, &response); err != nil {
		return err
	}
	if response.Hits == nil {
		return c.failure(connector.KindPermanent, "invalid_response", "Elasticsearch omitted search hits", 0)
	}
	if response.TimedOut || response.Shards.Failed > 0 {
		return c.failure(connector.KindTransient, "partial_search", "source connection check returned incomplete results", 0)
	}
	return nil
}

func (c *Connector) scopePath(api string) string { return strings.Join(c.indices, ",") + "/" + api }
func (c *Connector) failure(kind connector.ErrorKind, code, message string, status int) error {
	return &connector.Error{Provider: descriptor.ID, Kind: kind, Code: code, Message: message, HTTPStatus: status, SourceAPI: sourceAPI}
}

var _ connector.EventSource = (*Connector)(nil)
