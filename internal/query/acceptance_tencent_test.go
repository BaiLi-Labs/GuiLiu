package query

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/asset"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

// TestRealTencentInvestigationPath is opt-in. It copies a schema-5 local
// database, refreshes one real Tencent host, and exercises the same query
// functions used by REST and MCP: alert context, references and related
// findings. An older database is skipped because the development contract does
// not migrate it.
func TestRealTencentInvestigationPath(t *testing.T) {
	if os.Getenv("GUILIU_REAL_ACCEPTANCE") != "1" {
		t.Skip("set GUILIU_REAL_ACCEPTANCE=1, credentials and GUILIU_ACCEPT_* to run")
	}
	accountID := os.Getenv("GUILIU_ACCEPT_ACCOUNT_ID")
	hostID := os.Getenv("GUILIU_ACCEPT_HOST")
	dbPath := os.Getenv("GUILIU_ACCEPT_DB")
	if dbPath == "" {
		dbPath = filepath.Join("..", "..", "data", "guiliu.db")
	}
	keyFile := os.Getenv("GUILIU_ACCEPT_SECRET_FILE")
	if keyFile == "" {
		keyFile = filepath.Join("..", "..", "data", "secret.key")
	}
	if accountID == "" || hostID == "" {
		t.Fatal("GUILIU_ACCEPT_ACCOUNT_ID and GUILIU_ACCEPT_HOST are required")
	}
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	tmpDB := filepath.Join(t.TempDir(), "acceptance.db")
	if err := os.WriteFile(tmpDB, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(tmpDB)
	if err != nil {
		if strings.Contains(err.Error(), "schema") {
			t.Skipf("acceptance database is not current: %v", err)
		}
		t.Fatal(err)
	}
	defer st.Close()
	cipher, err := secret.Load("", keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	account, err := st.GetAccount(ctx, accountID)
	if err != nil {
		t.Fatal(err)
	}
	if account.Provider != "tencent" || account.AccountUID == "" || account.Region == "" {
		t.Fatalf("account scope incomplete: %+v", account)
	}

	s := asset.New(st, cipher, false)
	result, err := s.Refresh(ctx, account.ID, "", hostID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Asset == nil || result.Status != "available" && result.Status != "partial" {
		t.Fatalf("refresh: %+v %v", result, err)
	}
	if result.Asset.ResourceID != hostID {
		t.Fatalf("asset identity: %+v", result.Asset)
	}
	if len(result.Asset.Components["instance"].Raw) == 0 {
		t.Fatal("instance evidence missing")
	}
	var nicRefs []model.AssetReference
	for _, ref := range result.Asset.References {
		if ref.ResourceType == "nic" {
			nicRefs = append(nicRefs, ref)
		}
	}
	if len(nicRefs) == 0 {
		t.Fatal("host has no NIC reference")
	}
	for _, ref := range result.Asset.References {
		lookup, err := LookupAsset(ctx, st, model.AssetFilter{Provider: ref.Provider, AccountID: account.ID, AccountUID: ref.AccountUID, Region: ref.Region, ResourceType: ref.ResourceType, ResourceID: ref.ResourceID})
		if err != nil {
			t.Fatalf("%s/%s: %v", ref.ResourceType, ref.ResourceID, err)
		}
		if lookup.Status != "available" || lookup.Asset == nil {
			t.Fatalf("%s/%s unavailable: %+v", ref.ResourceType, ref.ResourceID, lookup)
		}
		if len(lookup.Asset.Components["details"].Raw) == 0 && len(lookup.Asset.Components["policies"].Raw) == 0 {
			t.Fatalf("%s/%s has no evidence", ref.ResourceType, ref.ResourceID)
		}
	}

	alerts, _, err := st.ListAlerts(ctx, model.AlertFilter{Provider: "tencent", AccountUID: account.AccountUID, Region: account.Region, Resource: hostID, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) == 0 {
		t.Fatalf("no stored alert references %s; cannot verify the alert path", hostID)
	}
	alert := &alerts[0]
	contextResult, err := ContextForAlert(ctx, st, alert)
	if err != nil {
		t.Fatal(err)
	}
	if contextResult.Status != "available" || contextResult.Asset == nil || contextResult.ResourceID != hostID {
		t.Fatalf("alert context: %+v", contextResult)
	}
	findings, err := AssetFindings(ctx, st, result.Asset.ID, "", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	total, _ := findings["total"].(int)
	if total == 0 {
		t.Fatalf("related findings empty: %+v", findings)
	}
	t.Logf("verified alert=%s host=%s nics=%d refs=%d findings=%d status=%s",
		alert.ExternalID, hostID, len(nicRefs), len(result.Asset.References), total, result.Status)
}
