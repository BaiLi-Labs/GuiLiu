package asset

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

// TestSyntheticRefreshForEveryProvider exercises the same service path for
// every registered cloud: provider lookup, host-type defaulting, synthetic
// client, reference enrichment and persistence.
func TestSyntheticRefreshForEveryProvider(t *testing.T) {
	providers := Providers()
	if len(providers) != 6 {
		t.Fatalf("expected six providers, got %d", len(providers))
	}
	for _, p := range providers {
		t.Run(p.ID, func(t *testing.T) {
			if p.SyntheticHostID == "" || p.Synthetic == nil {
				t.Fatal("provider lacks a synthetic fixture")
			}
			st, err := store.Open(filepath.Join(t.TempDir(), p.ID+".db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			a := model.Account{
				ID: "connection-" + p.ID, Name: p.ID, Provider: p.ID,
				AccountUID: "scope-" + p.ID, Region: "region-" + p.ID, Enabled: true,
			}
			switch p.ID {
			case "azure":
				a.Options = map[string]string{"subscription_id": "11111111-1111-1111-1111-111111111111", "tenant_id": "synthetic-tenant"}
			case "huawei":
				a.Options = map[string]string{"project_id": "synthetic-project"}
			}
			if err := st.CreateAccount(context.Background(), &a); err != nil {
				t.Fatal(err)
			}
			s := New(st, nil, true)
			result, err := s.Refresh(context.Background(), a.ID, "", p.SyntheticHostID)
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != "available" || result.Asset == nil {
				t.Fatalf("refresh: %+v", result)
			}
			if result.Asset.Provider != p.ID || result.Asset.ResourceType != p.HostType || !result.Asset.Synthetic {
				t.Fatalf("asset identity: %+v", result.Asset)
			}
			if len(result.Asset.Components) == 0 || result.Asset.ObservedAt.IsZero() {
				t.Fatal("observation incomplete")
			}
			if err := SeedSynthetic(context.Background(), st, a); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProviderRegistryRejectsDuplicate(t *testing.T) {
	p, ok := ProviderFor("tencent")
	if !ok {
		t.Fatal("tencent missing")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate registration accepted")
		}
	}()
	registerProvider(p)
}
