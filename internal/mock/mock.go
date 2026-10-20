// Package mock provides an offline Tencent Cloud connector backed by sanitized
// fixtures. It is registered only when mock mode is enabled, so production
// deployments never advertise it.
package mock

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/tencent"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const ProviderID = "tencent-mock"

//go:embed fixtures/tencent.json
var fixtureData []byte

// Register adds the mock connector to a registry. It is idempotent enough for
// repeated app construction in tests (a duplicate registration is ignored).
func Register(reg *connector.Registry) {
	_ = reg.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		ID:            ProviderID,
		Name:          "Tencent Cloud (Mock)",
		Vendor:        "Tencent Cloud",
		Product:       "Cloud Security Center (CSIP)",
		ProductUID:    "tencent.csip.mock",
		APIVersion:    "mock",
		MapperVersion: "tencent-csip/v1",
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "SecretId", Help: "Mock mode ignores credentials"},
			{Name: "access_key_secret", Label: "SecretKey", Secret: true, Help: "Mock mode ignores credentials"},
		},
		Products: []connector.Product{
			{Code: "CSIP", Name: "Cloud Security Center (mock)"},
			{Code: "CWP", Name: "Host Security (mock)"},
			{Code: "CFW", Name: "Cloud Firewall (mock)"},
			{Code: "WAF", Name: "Web Application Firewall (mock)"},
		},
	}
}

// Connector serves the embedded fixture pages without any network access.
type Connector struct {
	records  []connector.RawAlert
	pageSize int
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	records, err := loadRecords()
	if err != nil {
		return nil, connector.ConfigError(ProviderID, "load fixtures: "+err.Error())
	}
	return &Connector{
		records:  records,
		pageSize: connector.OptionInt(cfg.Options, "page_size", 100),
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

func (c *Connector) Check(context.Context) error { return nil }

func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	if err := ctx.Err(); err != nil {
		return connector.Page{}, err
	}
	offset := 0
	if q.Token != "" {
		v, err := strconv.Atoi(q.Token)
		if err != nil || v < 0 {
			return connector.Page{}, connector.ConfigError(ProviderID, "invalid page token")
		}
		offset = v
	}
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = c.pageSize
	}
	if pageSize > 100 {
		pageSize = 100
	}
	if offset >= len(c.records) {
		return connector.Page{Total: len(c.records)}, nil
	}
	end := offset + pageSize
	if end > len(c.records) {
		end = len(c.records)
	}
	next := ""
	if end < len(c.records) {
		next = strconv.Itoa(end)
	}
	records := append([]connector.RawAlert(nil), c.records[offset:end]...)
	return connector.Page{Records: records, NextToken: next, Total: len(c.records)}, nil
}

// Normalize reuses the production Tencent mapper so mock data exercises the
// exact same field conversion and OCSF path.
func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	return (&tencent.Connector{}).Normalize(raw)
}

var (
	loadOnce sync.Once
	loaded   []connector.RawAlert
	loadErr  error
)

func loadRecords() ([]connector.RawAlert, error) {
	loadOnce.Do(func() {
		var items []json.RawMessage
		if err := json.Unmarshal(fixtureData, &items); err != nil {
			loadErr = err
			return
		}
		now := time.Now().UTC()
		loaded = make([]connector.RawAlert, 0, len(items))
		for i, item := range items {
			var obj map[string]any
			if err := json.Unmarshal(item, &obj); err != nil {
				loadErr = fmt.Errorf("fixture %d: %w", i, err)
				return
			}
			// Fresh, relative timestamps make the mock console useful on any
			// day instead of only around the date the fixture was written.
			updated := now.Add(-time.Duration(20+i*47) * time.Minute)
			created := updated.Add(-time.Duration(10+i*5) * time.Minute)
			obj["CreateTime"] = created.Format(time.RFC3339)
			obj["UpdateTime"] = updated.Format(time.RFC3339)
			obj["Date"] = updated.In(connector.Beijing).Format(time.RFC3339)
			raw, err := json.Marshal(obj)
			if err != nil {
				loadErr = err
				return
			}
			loaded = append(loaded, connector.RawAlert{Raw: raw})
		}
	})
	return loaded, loadErr
}
