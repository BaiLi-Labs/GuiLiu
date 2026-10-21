package view

import (
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"testing"
)

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
