package store

import (
	"context"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestTypeAssetGroupsUseExactFieldsAndKeepMissingSources(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Millisecond)
	var originals []*model.AlertRecord
	add := func(id string, change func(*model.AlertRecord)) {
		a := testAlert("different title " + id)
		a.ExternalID, a.Region, a.SourceIP = id, "region-1", ""
		a.EventTime, a.FirstSeenAt, a.LastSeenAt = base, base, base
		a.Status = model.StatusClosed
		if change != nil {
			change(a)
		}
		if _, err := st.UpsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
		originals = append(originals, a)
	}
	add("one", nil)
	add("two", func(a *model.AlertRecord) { a.Severity = model.SeverityCritical })
	add("three", func(a *model.AlertRecord) { a.SourceIP = "203.0.113.50" })
	add("region", func(a *model.AlertRecord) { a.Region = "region-2" })
	add("account", func(a *model.AlertRecord) { a.AccountID = "different-account" })
	add("provider", func(a *model.AlertRecord) { a.Provider = "aliyun" })
	add("product", func(a *model.AlertRecord) { a.Product = "other-product" })
	add("type", func(a *model.AlertRecord) { a.AlertType = "maliciousprocess" }) // Case differs; no fuzzy match.
	add("no-asset-1", func(a *model.AlertRecord) { a.Resource.ID = "" })
	add("no-asset-2", func(a *model.AlertRecord) { a.Resource.ID = "" })
	add("no-type", func(a *model.AlertRecord) { a.AlertType = "" })
	add("no-product", func(a *model.AlertRecord) { a.Product = "" })
	add("outside-window", func(a *model.AlertRecord) { a.EventTime = base.Add(time.Hour) })
	start, end := base.Add(-time.Hour), base
	f := model.AlertFilter{Start: &start, End: &end, Limit: 50}
	groups, total, err := st.ListAlertGroups(ctx, f) // Default is type_asset.
	if err != nil || total != 10 {
		t.Fatalf("total=%d groups=%+v err=%v", total, groups, err)
	}
	count := 0
	var combined model.AlertGroup
	for _, g := range groups {
		count += g.FindingCount
		if g.FindingCount == 3 {
			combined = g
		}
	}
	if count != 12 || combined.GroupBy != model.GroupByTypeAsset || combined.MaxSeverity != model.SeverityCritical {
		t.Fatalf("counts/maximum = %d, %+v", count, combined)
	}
	if _, ok := combined.Key["source_ip"]; ok {
		t.Fatal("type_asset must not require or guess a source IP")
	}
	f.GroupBy, f.GroupKey = model.GroupByTypeAsset, combined.Key
	members, memberTotal, err := st.ListAlerts(ctx, f)
	if err != nil || memberTotal != 3 || len(members) != 3 {
		t.Fatalf("members=%d err=%v", memberTotal, err)
	}
	delete(f.GroupKey, "product")
	_, memberTotal, err = st.ListAlerts(ctx, f)
	if err != nil || memberTotal != 0 {
		t.Fatalf("incomplete group key widened membership: %d err=%v", memberTotal, err)
	}
	for _, original := range originals {
		got, err := st.GetAlert(ctx, original.ID)
		if err != nil || got.Status != original.Status || string(got.Raw) != string(original.Raw) || string(got.OCSF) != string(original.OCSF) {
			t.Fatalf("group query modified a record: %+v err=%v", got, err)
		}
	}
}

func TestGroupPaginationKeepsExactTotals(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	for _, id := range []string{"one", "two", "three"} {
		a := testAlert(id)
		a.ExternalID, a.Resource.ID = id, id
		if _, err := st.UpsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	for _, by := range []model.AlertGroupBy{model.GroupByTypeAsset, model.GroupBySignature, model.GroupByAsset, model.GroupBySource} {
		all, total, err := st.ListAlertGroups(ctx, model.AlertFilter{GroupBy: by})
		if err != nil {
			t.Fatal(err)
		}
		for offset := 0; offset <= total+1; offset++ {
			page, pageTotal, err := st.ListAlertGroups(ctx, model.AlertFilter{GroupBy: by, Limit: 1, Offset: offset})
			if err != nil || pageTotal != total {
				t.Fatalf("by=%s offset=%d total=%d err=%v", by, offset, pageTotal, err)
			}
			if offset < total && (len(page) != 1 || page[0].ID != all[offset].ID) {
				t.Fatalf("unstable page: %s offset=%d", by, offset)
			}
			if offset >= total && len(page) != 0 {
				t.Fatalf("unexpected extra page: %+v", page)
			}
		}
		empty, emptyTotal, err := st.ListAlertGroups(ctx, model.AlertFilter{GroupBy: by, Provider: "nonexistent", Offset: 10})
		if err != nil || len(empty) != 0 || emptyTotal != 0 {
			t.Fatalf("empty query=%+v total=%d err=%v", empty, emptyTotal, err)
		}
	}
}
