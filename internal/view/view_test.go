package view

import (
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"testing"
)

func TestResourceAndSourceFactsAreExposed(t *testing.T) {
	rec := &model.AlertRecord{Alert: model.Alert{
		Resource: model.Resource{
			ID: "ins-1", Name: "web-01", Type: "host",
			AccountUID: "1250000000", Source: model.ResourceSourceVendorDeclared,
		},
		SourceLocation: "示例省示例市", SourceCountry: "示例国家", ResponseAction: "BlockAttackIP",
	}}
	list := AlertFromRecord(rec, false)
	if list.Resource.Name != "web-01" || list.Resource.AccountUID != "1250000000" || list.Resource.Source != model.ResourceSourceVendorDeclared {
		t.Fatalf("resource = %+v", list.Resource)
	}
	if list.SourceLocation != "示例省示例市" || list.SourceCountry != "示例国家" || list.ResponseAction != "BlockAttackIP" {
		t.Fatalf("source facts = %+v", list)
	}
}

func TestDetailExposesAllOCSFResources(t *testing.T) {
	rec := &model.AlertRecord{Alert: model.Alert{Resource: model.Resource{ID: "one"}, Resources: []model.Resource{{ID: "one", Name: "first"}, {ID: "two", Name: "second", Type: "host"}}}}
	list := AlertFromRecord(rec, false)
	if len(list.Resources) != 0 {
		t.Fatal("list loaded additional payload")
	}
	detail := AlertFromRecord(rec, true)
	if len(detail.Resources) != 2 || detail.Resources[1].ID != "two" {
		t.Fatalf("detail resources=%+v", detail.Resources)
	}
}
