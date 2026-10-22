package query

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func TestAssetContextDisclosesScopeAndSourceError(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/asset-scope.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	account := model.Account{ID: "tencent-connection", Name: "tencent", Provider: "tencent", AccountUID: "100000000001", Region: "ap-guangzhou", Enabled: true}
	if err := st.CreateAccount(ctx, &account); err != nil {
		t.Fatal(err)
	}
	rec := &model.AlertRecord{Provider: "tencent", AccountID: account.ID, AccountUID: account.AccountUID, Alert: model.Alert{
		ExternalID: "scope-1", Title: "scope", Region: account.Region,
		Resource:  model.Resource{ID: "ins-abc", Type: "host"},
		EventTime: time.Now().UTC(),
		Raw:       json.RawMessage(`{"ID":"scope-1"}`),
	}}
	if _, err := st.UpsertAlert(ctx, rec); err != nil {
		t.Fatal(err)
	}

	// Nothing collected: the response must still say exactly what it asked for.
	got, err := ContextForAlert(ctx, st, rec)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "unavailable" || got.Reason != "not_collected" {
		t.Fatalf("context = %+v", got)
	}
	filter := model.AssetFilter{AccountID: account.ID, Provider: "tencent", AccountUID: account.AccountUID, Region: account.Region, ResourceType: "cvm", ResourceID: "ins-abc"}
	lookupBefore, err := LookupAsset(ctx, st, filter)
	if err != nil || lookupBefore.Status != "not_collected" || lookupBefore.Reason != "no_recorded_refresh" {
		t.Fatalf("unrequested refresh: %+v %v", lookupBefore, err)
	}
	filter.AccountID = ""
	lookupBefore, err = LookupAsset(ctx, st, filter)
	if err != nil || lookupBefore.Reason != "no_saved_observation_refresh_not_checked" {
		t.Fatalf("unspecified connection: %+v %v", lookupBefore, err)
	}
	if got.Scope == nil || got.Scope.Provider != "tencent" || got.Scope.Region != "ap-guangzhou" ||
		got.Scope.ResourceType != "cvm" || got.Scope.ResourceID != "ins-abc" ||
		got.Scope.SourceAPI != "CVM DescribeInstances" || got.Scope.APIVersion == "" {
		t.Fatalf("scope = %+v", got.Scope)
	}

	// A failed refresh keeps its bounded source error, so permission and region
	// mistakes are distinguishable from an empty but authorized read.
	attempt := model.AssetRefresh{
		AccountID: account.ID, Region: account.Region, ResourceID: "ins-abc",
		Status: "permission_denied", AttemptedAt: time.Now().UTC(),
		SourceError: &model.SourceError{Provider: "tencent", Kind: "permission", Code: "UnauthorizedOperation", SourceAPI: "CVM DescribeInstances"},
	}
	if ok, err := st.BeginAssetRefresh(ctx, attempt, 0); err != nil || !ok {
		t.Fatalf("begin refresh = %v %v", ok, err)
	}
	if err := st.FinishAssetRefresh(ctx, attempt); err != nil {
		t.Fatal(err)
	}
	got, err = ContextForAlert(ctx, st, rec)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reason != "permission_denied" || got.Refresh == nil || got.Refresh.SourceError == nil {
		t.Fatalf("context after failed refresh = %+v", got)
	}
	if got.Refresh.SourceError.Code != "UnauthorizedOperation" {
		t.Fatalf("source error = %+v", got.Refresh.SourceError)
	}

	lookup, err := LookupAsset(ctx, st, model.AssetFilter{AccountID: account.ID, Provider: "tencent", AccountUID: account.AccountUID, Region: account.Region, ResourceType: "cvm", ResourceID: "ins-abc"})
	if err != nil {
		t.Fatal(err)
	}
	if lookup.Status != "permission_denied" || lookup.Scope == nil || lookup.Scope.SourceAPI == "" || lookup.Refresh == nil || lookup.Refresh.SourceError == nil {
		t.Fatalf("lookup = %+v", lookup)
	}
}
