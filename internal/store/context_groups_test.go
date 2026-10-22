package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestNetworkGroupsPinObservationsDeduplicateAndRetainEvidence(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	ref := func(kind, id, relation string) model.AssetReference {
		return model.AssetReference{Provider: "tencent", AccountID: "acct", AccountUID: "1234567890", Region: "ap-guangzhou", ResourceType: kind, ResourceID: id, Relation: relation, SourceComponent: "details", SourcePath: "/references/0"}
	}
	host := &model.Asset{Provider: "tencent", AccountID: "acct", AccountUID: "1234567890", Region: "ap-guangzhou", ResourceID: "ins-1", ResourceType: "cvm", Name: "Synthetic host", ObservedAt: now, References: []model.AssetReference{
		ref("security_group", "sg-one", "attached_security_group"), ref("security_group", "sg-one", "attached_security_group"),
		ref("nic", "eni-one", "attached_network_interface"), ref("nic", "eni-two", "attached_network_interface"),
		ref("vpc", "vpc-one", "belongs_to_vpc"), ref("subnet", "subnet-one", "in_subnet"),
	}}
	if err := st.SaveAsset(ctx, host); err != nil {
		t.Fatal(err)
	}
	nic := &model.Asset{Provider: host.Provider, AccountID: host.AccountID, AccountUID: host.AccountUID, Region: host.Region, ResourceID: "eni-one", ResourceType: "nic", ObservedAt: now, References: []model.AssetReference{ref("security_group", "sg-one", "attached_security_group"), ref("security_group", "sg-two", "attached_security_group")}}
	if err := st.SaveAsset(ctx, nic); err != nil {
		t.Fatal(err)
	}
	add := func(id string, edit func(*model.AlertRecord)) *model.AlertRecord {
		a := testAlert("Synthetic scan")
		a.ExternalID = id
		a.Region = host.Region
		a.EventTime = now
		a.Raw = json.RawMessage(`{"source":"synthetic","id":"` + id + `"}`)
		if edit != nil {
			edit(a)
		}
		if _, err := st.UpsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := add("one", nil)
	b := add("two", func(a *model.AlertRecord) { a.Title = "Synthetic command" })
	add("foreign-account", func(a *model.AlertRecord) { a.AccountUID = "other-account" })
	add("foreign-region", func(a *model.AlertRecord) { a.Region = "ap-shanghai" })
	add("wrong-kind", func(a *model.AlertRecord) { a.Resource.Type = "network" })
	add("only-same-ip", func(a *model.AlertRecord) { a.Resource.ID = "ins-other" })
	add("missing-account", func(a *model.AlertRecord) { a.AccountUID = "" })
	seq, _ := st.SnapshotSequence(ctx)
	assetSeq, _ := st.AssetSnapshotSequence(ctx)
	f := model.AlertFilter{GroupBy: model.GroupBySecurityGroup, SnapshotSequence: &seq, AssetSnapshotSequence: &assetSeq, Limit: 100}
	groups, total, err := st.ListAlertGroups(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if total != 7 {
		t.Fatalf("groups=%d want 2 known + 5 independent unknown", total)
	}
	var sg model.AlertGroup
	for _, g := range groups {
		if g.Key["resource_id"] == "sg-one" {
			sg = g
		}
		if g.Key["singleton"] != "" && g.FindingCount != 1 {
			t.Fatal("merged missing network identity")
		}
	}
	if sg.FindingCount != 2 || sg.AssetCount != 1 || len(sg.Assets) != 1 || sg.Assets[0].Revision != 1 || len(sg.TopTitles) != 2 {
		t.Fatalf("summary=%+v", sg)
	}
	if len(sg.RelationEvidence) != 2 {
		t.Fatalf("missing exact direct and NIC edge evidence: %+v", sg.RelationEvidence)
	}
	sawNIC := false
	for _, edge := range sg.RelationEvidence {
		if edge.SourceRevision != 1 || edge.HostRevision != 1 || edge.HostAssetID != host.ID {
			t.Fatal("wrong evidence revision", edge)
		}
		if edge.SourceAssetID == nic.ID {
			sawNIC = true
		}
	}
	if !sawNIC {
		t.Fatal("NIC-derived edge cannot be replayed from an exact revision")
	}
	summary, err := st.GroupingSummary(ctx, f)
	if err != nil || summary.FindingCount != 7 || summary.AssetContextFindingCount != 2 || summary.UngroupedFindingCount != 5 || summary.MembershipCount != 9 {
		t.Fatalf("summary=%+v err=%v", summary, err)
	}
	f.GroupKey = sg.Key
	statistics, err := st.AlertStats(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	members, n, err := st.ListAlerts(ctx, f)
	if err != nil || n != 2 || len(members) != 2 {
		t.Fatalf("members=%d err=%v", n, err)
	}
	// A new host observation moves its direct SG, and a NIC observation moves its
	// second SG. A later Finding and revisions must not affect the old two-watermark view.
	host.References = []model.AssetReference{ref("security_group", "sg-new", "attached_security_group")}
	host.ObservedAt = now.Add(time.Minute)
	if err := st.SaveAsset(ctx, host); err != nil {
		t.Fatal(err)
	}
	nic.References = nil
	nic.ObservedAt = now.Add(time.Minute)
	if err := st.SaveAsset(ctx, nic); err != nil {
		t.Fatal(err)
	}
	add("late", nil)
	b.Title = "Changed title"
	if _, err := st.UpsertAlert(ctx, b); err != nil {
		t.Fatal(err)
	}
	afterStats, err := st.AlertStats(ctx, f)
	if err != nil || !reflect.DeepEqual(statistics, afterStats) {
		t.Fatalf("statistics did not share the group snapshots: %v", err)
	}
	again, n, err := st.ListAlerts(ctx, f)
	if err != nil || n != 2 || !reflect.DeepEqual(members, again) {
		t.Fatalf("membership changed under asset refresh: n=%d err=%v", n, err)
	}
	f.GroupKey = nil
	frozen, _, err := st.ListAlertGroups(ctx, f)
	if err != nil || !reflect.DeepEqual(groups, frozen) {
		t.Fatalf("frozen groups changed: %v", err)
	}
	// All grouping reads leave original source bytes untouched.
	stored, _ := st.GetAlertRevision(ctx, a.ID, 1)
	if string(stored.Raw) != string(a.Raw) {
		t.Fatal("grouping rewrote evidence")
	}
	latestFinding, _ := st.SnapshotSequence(ctx)
	latestAsset, _ := st.AssetSnapshotSequence(ctx)
	f.SnapshotSequence = &latestFinding
	f.AssetSnapshotSequence = &latestAsset
	current, _, err := st.ListAlertGroups(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range current {
		if g.Key["resource_id"] == "sg-one" || g.Key["resource_id"] == "sg-two" {
			t.Fatal("old network membership leaked into current view")
		}
	}
	for _, by := range []model.AlertGroupBy{model.GroupByVPC, model.GroupBySubnet, model.GroupByNIC} {
		f.GroupBy = by
		f.SnapshotSequence = &seq
		f.AssetSnapshotSequence = &assetSeq
		page, _, err := st.ListAlertGroups(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		known := 0
		for _, g := range page {
			if g.Key["singleton"] == "" {
				known++
				if g.FindingCount != 2 {
					t.Fatal(g)
				}
			}
		}
		want := 1
		if by == model.GroupByNIC {
			want = 2
		}
		if known != want {
			t.Fatalf("%s groups=%d want=%d", by, known, want)
		}
	}
}

func TestAssetGroupsScopeTitleAndPagination(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	for i, id := range []string{"a", "b", "c", "d", "e"} {
		a := testAlert("Source exact title")
		a.ExternalID = id
		a.Region = "region-one"
		if i == 2 {
			a.Resource.Type = "database"
		}
		if i == 3 {
			a.AccountUID = "other-uid"
		}
		if i == 4 {
			a.Title = "source exact title"
		}
		if _, err := st.UpsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	seq, _ := st.SnapshotSequence(ctx)
	zero := int64(0)
	for _, by := range []model.AlertGroupBy{model.GroupByAsset, model.GroupByNameAsset} {
		f := model.AlertFilter{GroupBy: by, SnapshotSequence: &seq, AssetSnapshotSequence: &zero, Limit: 100}
		all, total, err := st.ListAlertGroups(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		want := 3
		if by == model.GroupByNameAsset {
			want = 4
		}
		if total != want {
			t.Fatalf("%s total=%d", by, total)
		}
		for i := 0; i <= total+1; i++ {
			f.Offset = i
			f.Limit = 1
			page, count, err := st.ListAlertGroups(ctx, f)
			if err != nil || count != total {
				t.Fatalf("page %d total=%d err=%v", i, count, err)
			}
			if i < total && (len(page) != 1 || page[0].ID != all[i].ID) {
				t.Fatal("unstable page")
			}
		}
		f.Offset = 0
		f.Limit = 100
		f.GroupKey = all[0].Key
		members, n, err := st.ListAlerts(ctx, f)
		if err != nil || n != all[0].FindingCount || len(members) != n {
			t.Fatalf("member counts %d %v", n, err)
		}
		delete(f.GroupKey, "account_uid")
		_, n, err = st.ListAlerts(ctx, f)
		if err != nil || n != 0 {
			t.Fatal("incomplete key broadened members")
		}
	}
}

func TestAssetWatermarkPersistsAndIdenticalRefreshDoesNotMoveMembership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watermark.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a := &model.Asset{Provider: "tencent", AccountID: "acct", AccountUID: "synthetic", Region: "region", ResourceID: "ins-one", ResourceType: "cvm", ObservedAt: time.Now().UTC()}
	if err = st.SaveAsset(ctx, a); err != nil {
		t.Fatal(err)
	}
	seq, _ := st.AssetSnapshotSequence(ctx)
	a.ObservedAt = a.LastObservedAt.Add(time.Minute)
	if err = st.SaveAsset(ctx, a); err != nil {
		t.Fatal(err)
	}
	same, _ := st.AssetSnapshotSequence(ctx)
	if same != seq {
		t.Fatal("identical content moved membership watermark")
	}
	st.Close()
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, _ := st.AssetSnapshotSequence(ctx)
	if got != seq {
		t.Fatal("watermark changed after reopen")
	}
	a.Name = "new name"
	a.ObservedAt = a.LastObservedAt.Add(time.Minute)
	if err = st.SaveAsset(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, _ = st.AssetSnapshotSequence(ctx)
	if got <= seq {
		t.Fatal("non-monotonic watermark")
	}
}

func TestNetworkGroupSummariesStayBoundedWithoutLosingMembers(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 7; i++ {
		id := fmt.Sprintf("ins-synthetic%d", i)
		a := &model.Asset{Provider: "tencent", AccountID: "acct", AccountUID: "1234567890", Region: "ap-guangzhou", ResourceType: "cvm", ResourceID: id, ObservedAt: now, Synthetic: true, References: []model.AssetReference{{Provider: "tencent", AccountUID: "1234567890", Region: "ap-guangzhou", ResourceType: "security_group", ResourceID: "sg-synthetic", Relation: "attached_security_group", SourceComponent: "instance", SourcePath: "/SecurityGroupIds/0"}}, Components: map[string]model.AssetComponent{"instance": {Status: "available", ObservedAt: &now, Raw: json.RawMessage(`{"source_canary":"NOT_FOR_SUMMARIES"}`)}}}
		if err := st.SaveAsset(ctx, a); err != nil {
			t.Fatal(err)
		}
		r := testAlert(fmt.Sprintf("Source title %d", i))
		r.Resource.ID = id
		r.Region = a.Region
		r.ExternalID = id
		if _, err := st.UpsertAlert(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	f := model.AlertFilter{GroupBy: model.GroupBySecurityGroup}
	groups, total, err := st.ListAlertGroups(ctx, f)
	if err != nil || total != 1 {
		t.Fatalf("groups=%d err=%v", total, err)
	}
	g := groups[0]
	if g.FindingCount != 7 || g.AssetCount != 7 || len(g.Assets) != 5 || len(g.TopTitles) != 5 || len(g.RelationEvidence) != 5 {
		t.Fatalf("unbounded or incorrect summary: %+v", g)
	}
	encoded, _ := json.Marshal(g)
	if bytes.Contains(encoded, []byte("NOT_FOR_SUMMARIES")) {
		t.Fatal("summary included raw source payload")
	}
	f.GroupKey = g.Key
	f.Limit = 100
	_, n, err := st.ListAlerts(ctx, f)
	if err != nil || n != 7 {
		t.Fatal("samples truncated member access", n, err)
	}
}
