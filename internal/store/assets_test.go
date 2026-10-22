package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestAssetComponentRawBytesSurviveStorage(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	account := model.Account{ID: "connection", Name: "tencent", Provider: "tencent", AccountUID: "123", Region: "ap-guangzhou", Enabled: true}
	if err := st.CreateAccount(ctx, &account); err != nil {
		t.Fatal(err)
	}
	// Pretty-printed source bytes: encoding/json would compact these if the
	// component were stored as a nested RawMessage.
	original := json.RawMessage("{\n  \"InstanceId\": \"ins-1\",\n  \"FutureVendorField\": 9007199254740993\n}")
	at := time.Now().UTC()
	asset := &model.Asset{
		AccountID: account.ID, Provider: "tencent", AccountUID: account.AccountUID, Region: account.Region,
		ResourceID: "ins-1", ResourceType: "cvm", MapperVersion: "test/v1", ObservedAt: at,
		Components: map[string]model.AssetComponent{"instance": {Status: "available", SourceAPI: "CVM DescribeInstances", APIVersion: "2017-03-12", ObservedAt: &at, Raw: original}},
		Provenance: map[string]model.FieldOrigin{},
	}
	if err := st.SaveAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	loaded, err := st.GetAsset(ctx, asset.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	component := loaded.Components["instance"]
	if string(component.Raw) != string(original) {
		t.Fatalf("raw bytes changed: %q", component.Raw)
	}
	if component.RawHash != fmt.Sprintf("%x", sha256.Sum256(original)) {
		t.Fatalf("raw hash mismatch: %s", component.RawHash)
	}

	// Re-reading the same content advances only last_observed_at and keeps the
	// exact component bytes of revision 1.
	second := *asset
	second.ObservedAt = at.Add(time.Minute)
	if err := st.SaveAsset(ctx, &second); err != nil {
		t.Fatal(err)
	}
	if second.Revision != 1 {
		t.Fatalf("identical content created revision %d", second.Revision)
	}
	historical, err := st.GetAsset(ctx, asset.ID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(historical.Components["instance"].Raw) != string(original) {
		t.Fatal("historical evidence changed")
	}
}
