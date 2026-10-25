// Package cef implements a vendor-neutral Common Event Format connector. It is
// the fallback Pusher for appliances that can only push, and it deliberately
// accepts only the event categories an operator declares as alerts.
//
// CEF itself is a log format, not an alert format: the same device emits
// traffic, DNS, audit and threat records through it. Accepting every CEF line
// would turn GuiLiu into a log collector, which is outside the product scope.
package cef

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/pushwire"
)

const (
	providerID    = "cef"
	mapperVersion = "cef/v3"
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		SourceAPI:     "CEF webhook or syslog",
		ID:            providerID,
		Name:          "Generic CEF",
		Vendor:        "Generic",
		Product:       "Common Event Format",
		ProductUID:    "generic.cef",
		APIVersion:    "cef",
		DocsURL:       "https://github.com/BaiLi-Labs/GuiLiu/blob/main/docs/connector-guide.md",
		MapperVersion: mapperVersion,
		OptionFields: []connector.OptionField{
			{Name: "event_categories", Label: "Alert categories", Placeholder: "ips,attack,threat,malware", Help: "逗号分隔。匹配 CEF 的 cat、name、deviceEventClassId 或 deviceProduct；只有命中这些关键词的事件才会入库。CEF 是日志格式，不配置就无法区分告警与流量日志，因此未配置时不会接收任何记录"},
			{Name: "accept_all_events", Label: "Accept every CEF event", Placeholder: "false", Help: "显式关闭类别过滤。会把流量、审计等日志也当作告警入库，破坏 Finding 语义，仅用于临时排障"},
			{Name: "default_device", Label: "Default device name", Placeholder: "用于 CEF 未声明 device product 时", Help: "只影响缺失字段的展示，不推断告警内容"},
		},
		Products:    []connector.Product{{Code: "CEF", Name: "Common Event Format"}},
		PushFormats: []connector.PushFormat{connector.PushWebhook, connector.PushSyslog},
		PushOnly:    true,
	}
}

// Connector accepts CEF records only; there is no polling API.
type Connector struct {
	defaultDevice string
	categories    []string
	acceptAll     bool
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	c := &Connector{
		defaultDevice: strings.TrimSpace(cfg.Options["default_device"]),
		acceptAll:     strings.EqualFold(strings.TrimSpace(cfg.Options["accept_all_events"]), "true"),
	}
	for _, raw := range strings.Split(cfg.Options["event_categories"], ",") {
		if category := strings.TrimSpace(raw); category != "" {
			c.categories = append(c.categories, category)
		}
	}
	return c, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

// Check reports the configuration gap instead of silently dropping every
// pushed event. A push-only source has no remote call to validate.
func (c *Connector) Check(ctx context.Context) error {
	if c.acceptAll || len(c.categories) > 0 {
		return nil
	}
	return connector.ConfigError(providerID, "event_categories is required: CEF carries logs as well as alerts, so the alert categories must be declared explicitly")
}

func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	return connector.Page{}, connector.ConfigError(providerID, "CEF is a push-only source")
}

func (c *Connector) DecodePush(req connector.PushRequest) ([]connector.RawAlert, error) {
	switch req.Format {
	case connector.PushSyslog:
		var env pushwire.Envelope
		if err := json.Unmarshal(req.Body, &env); err != nil {
			return nil, fmt.Errorf("decode syslog envelope: %w", err)
		}
		if env.CEF == nil {
			return nil, nil // Not every syslog frame is a CEF event.
		}
		if !c.accepts(env.CEF) {
			return nil, nil
		}
		raw, err := json.Marshal(env)
		if err != nil {
			return nil, err
		}
		return []connector.RawAlert{{Raw: raw}}, nil
	case connector.PushWebhook:
		env := pushwire.DecodeWebhook(req.Body)
		if env.CEF == nil {
			if parsed, err := pushwire.ParseCEF(string(req.Body)); err == nil {
				env.CEF = &parsed
			}
		}
		if env.CEF == nil {
			return nil, fmt.Errorf("webhook payload is neither CEF nor a CEF envelope")
		}
		if !c.accepts(env.CEF) {
			return nil, nil
		}
		raw, err := json.Marshal(env)
		if err != nil {
			return nil, err
		}
		return []connector.RawAlert{{Raw: raw}}, nil
	default:
		return nil, fmt.Errorf("unsupported push format %q", req.Format)
	}
}

// accepts matches the declared categories against the CEF header and the
// extension fields vendors use for event class. Substring matching is
// deliberate: device values vary ("ips", "ips:attack", "100015").
func (c *Connector) accepts(record *pushwire.CEF) bool {
	if c.acceptAll {
		return true
	}
	if len(c.categories) == 0 {
		return false
	}
	haystack := strings.ToLower(strings.Join([]string{
		record.Name,
		record.SignatureID,
		record.DeviceProduct,
		record.Extension["cat"],
		record.Extension["deviceEventClassId"],
		record.Extension["cs1"],
		record.Extension["cs1Label"],
	}, " "))
	for _, category := range c.categories {
		if strings.Contains(haystack, strings.ToLower(category)) {
			return true
		}
	}
	return false
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalize(raw, c.defaultDevice)
}
