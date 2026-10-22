package query

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

// A resource can belong to an account that is not the account that reported the
// alert. Asset context, related Findings and asset grouping must follow the
// owner declared by the source.
func TestResourceOwnerDrivesContextFindingsAndGroups(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/resource-owner.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	reporter := model.Account{ID: "conn-a", Name: "reporter", Provider: "azure", AccountUID: "sub-a", Region: "eastasia", Enabled: true}
	owner := model.Account{ID: "conn-b", Name: "owner", Provider: "azure", AccountUID: "sub-b", Region: "eastasia", Enabled: true}
	for _, account := range []*model.Account{&reporter, &owner} {
		if err := st.CreateAccount(ctx, account); err != nil {
			t.Fatal(err)
		}
	}
	vm := "/subscriptions/sub-b/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-b"
	asset := &model.Asset{
		AccountID: owner.ID, Provider: "azure", AccountUID: "sub-b", Region: owner.Region,
		ResourceID: vm, ResourceType: "vm", Name: "vm-b", MapperVersion: "azure-vm/v1",
		ObservedAt: time.Now().UTC(), Components: map[string]model.AssetComponent{}, Provenance: map[string]model.FieldOrigin{},
	}
	if err := st.SaveAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	rec := &model.AlertRecord{
		Provider: "azure", AccountID: reporter.ID, AccountUID: "sub-a",
		Alert: model.Alert{
			ExternalID: "cross-account", Title: "Cross account", Region: "eastasia",
			Resource:  model.Resource{ID: vm, Type: "Microsoft.Compute/virtualMachines", AccountUID: "sub-b"},
			EventTime: time.Now().UTC(),
			Raw:       json.RawMessage(`{"id":"cross-account"}`),
		},
		Status: model.StatusOpen,
	}
	if _, err := st.UpsertAlert(ctx, rec); err != nil {
		t.Fatal(err)
	}

	got, err := ContextForAlert(ctx, st, rec)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "available" || got.Asset == nil || got.Asset.ID != asset.ID {
		t.Fatalf("context did not resolve the owner asset: %+v", got)
	}
	if got.RefreshAccountID != owner.ID {
		t.Fatalf("refresh must use the owner connection %q, got %q", owner.ID, got.RefreshAccountID)
	}
	if !slices.Contains(got.MatchedOn, "resource_account_uid") {
		t.Fatalf("matched_on must disclose the owner identity: %v", got.MatchedOn)
	}

	findings, err := AssetFindings(ctx, st, asset.ID, "", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if findings["total"] != 1 {
		t.Fatalf("related Findings must follow the resource owner: %+v", findings)
	}

	seq, err := st.SnapshotSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assetSeq, err := st.AssetSnapshotSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	groups, total, err := st.ListAlertGroups(ctx, model.AlertFilter{
		GroupBy: model.GroupByAsset, SnapshotSequence: &seq, AssetSnapshotSequence: &assetSeq, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(groups) != 1 {
		t.Fatalf("cross-account Finding must join its host asset: total=%d groups=%+v", total, groups)
	}
	if groups[0].Key["singleton"] != "" || groups[0].Key["account_uid"] != "sub-b" || groups[0].AssetCount != 1 {
		t.Fatalf("group key must use the resource owner: %+v", groups[0])
	}
}

// When the owner account has no configured connection, the context must say so
// instead of offering a refresh through the reporting account's credentials.
func TestResourceOwnerWithoutConnectionHasNoRefreshTarget(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/owner-missing.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	reporter := model.Account{ID: "conn-a", Name: "reporter", Provider: "azure", AccountUID: "sub-a", Region: "eastasia", Enabled: true}
	if err := st.CreateAccount(ctx, &reporter); err != nil {
		t.Fatal(err)
	}
	vm := "/subscriptions/sub-b/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-b"
	rec := &model.AlertRecord{
		Provider: "azure", AccountID: reporter.ID, AccountUID: "sub-a",
		Alert: model.Alert{
			ExternalID: "owner-missing", Title: "Owner missing", Region: "eastasia",
			Resource:  model.Resource{ID: vm, Type: "Microsoft.Compute/virtualMachines", AccountUID: "sub-b"},
			EventTime: time.Now().UTC(),
			Raw:       json.RawMessage(`{"id":"owner-missing"}`),
		},
		Status: model.StatusOpen,
	}
	if _, err := st.UpsertAlert(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := ContextForAlert(ctx, st, rec)
	if err != nil {
		t.Fatal(err)
	}
	if got.RefreshAccountID != "" || got.RefreshReason != "resource_account_not_connected" {
		t.Fatalf("context = %+v", got)
	}
	if got.Scope == nil || got.Scope.AccountUID != "sub-b" {
		t.Fatalf("scope must name the declared owner: %+v", got.Scope)
	}
}
