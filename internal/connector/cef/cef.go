// Package cef implements a vendor-neutral Common Event Format connector. It is
// the reference Pusher: it accepts CEF delivered by webhook or syslog and keeps
// both the transport envelope and the CEF line verbatim.
package cef

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/pushwire"
)

const (
	providerID    = "cef"
	mapperVersion = "cef/v1"
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
		MapperVersion: mapperVersion,
		OptionFields: []connector.OptionField{
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
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	return &Connector{defaultDevice: cfg.Options["default_device"]}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

// Check validates configuration only: a push-only source has no remote call.
func (c *Connector) Check(ctx context.Context) error { return nil }

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
		raw, err := json.Marshal(env)
		if err != nil {
			return nil, err
		}
		return []connector.RawAlert{{Raw: raw}}, nil
	default:
		return nil, fmt.Errorf("unsupported push format %q", req.Format)
	}
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return normalize(raw, c.defaultDevice)
}
