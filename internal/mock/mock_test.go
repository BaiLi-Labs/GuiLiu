package mock

import (
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestAllFixturesNormalize(t *testing.T) {
	for _, s := range specs {
		s := s
		t.Run(s.id, func(t *testing.T) {
			records, err := loadRecords(s)
			if err != nil {
				t.Fatalf("load fixtures: %v", err)
			}
			if len(records) < 8 {
				t.Fatalf("fixture has %d records, want at least 8", len(records))
			}
			ids := map[string]bool{}
			for i, record := range records {
				alert, err := s.normalize(record.Raw)
				if err != nil {
					t.Fatalf("record %d normalize: %v", i, err)
				}
				if alert.ExternalID == "" || ids[alert.ExternalID] {
					t.Fatalf("record %d: empty or duplicate external id %q", i, alert.ExternalID)
				}
				ids[alert.ExternalID] = true
				if alert.Title == "" {
					t.Fatalf("record %d: empty title", i)
				}
				if alert.Severity == model.SeverityUnknown {
					t.Fatalf("record %d: unknown severity, raw=%s", i, string(record.Raw)[:120])
				}
				if alert.EventTime.IsZero() || time.Since(alert.EventTime) > 25*time.Hour {
					t.Fatalf("record %d: event time %s is stale or zero", i, alert.EventTime)
				}
				if alert.CloudAccountUID == "" {
					t.Fatalf("record %d: empty cloud account uid", i)
				}
				if alert.Resource.ID == "" {
					t.Fatalf("record %d: empty resource id", i)
				}
				if len(alert.Raw) == 0 {
					t.Fatalf("record %d: empty raw payload", i)
				}
				if len(alert.Evidences) == 0 {
					t.Fatalf("record %d: empty evidences", i)
				}
				if len(alert.Observables) == 0 {
					t.Fatalf("record %d: empty observables", i)
				}
			}
		})
	}
}

func TestRegisterMockProviders(t *testing.T) {
	reg := connector.NewRegistry()
	Register(reg)
	for _, s := range specs {
		if _, ok := reg.Descriptor(s.id); !ok {
			t.Fatalf("provider %s not registered", s.id)
		}
		if !IsMockProvider(s.id) {
			t.Fatalf("IsMockProvider(%s) = false", s.id)
		}
	}
	if IsMockProvider("tencent") {
		t.Fatal("production provider must not be considered a mock provider")
	}
}
