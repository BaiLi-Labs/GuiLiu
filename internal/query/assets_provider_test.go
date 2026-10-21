package query

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func TestAssetFindingsUseProviderResourceAliases(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(t.TempDir() + "/aliases.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	account := model.Account{ID: "aws-connection", Name: "aws", Provider: "aws", AccountUID: "123456789012", Region: "ap-southeast-1", Enabled: true}
	if err := st.CreateAccount(ctx, &account); err != nil {
		t.Fatal(err)
	}
	asset := &model.Asset{
		AccountID: account.ID, Provider: "aws", AccountUID: account.AccountUID, Region: account.Region,
		ResourceID: "i-0123456789abcdef0", ResourceType: "ec2", MapperVersion: "aws-ec2/v1",
		ObservedAt: time.Now().UTC(), Components: map[string]model.AssetComponent{}, Provenance: map[string]model.FieldOrigin{},
	}
	if err := st.SaveAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	arn := "arn:aws:ec2:ap-southeast-1:123456789012:instance/i-0123456789abcdef0"
	create := func(id, resource string, kind string) *model.AlertRecord {
		now := time.Now().UTC()
		r := &model.AlertRecord{Provider: "aws", AccountID: account.ID, AccountUID: account.AccountUID, Alert: model.Alert{
			ExternalID: id, Title: id, Region: account.Region,
			Resource: model.Resource{ID: resource, Type: kind}, EventTime: now,
			Raw: json.RawMessage(`{"id":"` + id + `"}`),
		}}
		if _, err := st.UpsertAlert(ctx, r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	arnAlert := create("arn-form", arn, "AwsEc2Instance")
	create("native-form", "i-0123456789abcdef0", "AwsEc2Instance")
	create("other-host", "i-0ffffffffffffffff", "AwsEc2Instance")

	result, err := AssetFindings(ctx, st, asset.ID, "", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result["total"] != 2 {
		t.Fatalf("alias matching failed: %+v", result)
	}
	matched, _ := result["matched_on"].([]string)
	found := false
	for _, value := range matched {
		if value == "vendor_resource_id_alias" {
			found = true
		}
	}
	if !found {
		t.Fatalf("alias not disclosed: %+v", matched)
	}

	contextValue, err := ContextForAlert(ctx, st, arnAlert)
	if err != nil {
		t.Fatal(err)
	}
	if contextValue.Status != "available" || contextValue.Asset == nil || contextValue.ResourceID != "i-0123456789abcdef0" {
		t.Fatalf("ARN context: %+v", contextValue)
	}

	if _, err := LookupAsset(ctx, st, model.AssetFilter{Provider: "unknown", AccountUID: "u", Region: "r", ResourceType: "vm", ResourceID: "x"}); err == nil {
		t.Fatal("unknown provider accepted")
	}
	if _, err := LookupAsset(ctx, st, model.AssetFilter{Provider: "aws", AccountUID: account.AccountUID, Region: account.Region, ResourceType: "cvm", ResourceID: "i-0123456789abcdef0"}); err == nil {
		t.Fatal("foreign resource type accepted")
	}
}
