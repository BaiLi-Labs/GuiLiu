package store

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestChangeFeedIsDurableAndIgnoresRepeatedContent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "facts.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first := testAlert("first")
	first.EventTime = first.EventTime.Add(-30 * 24 * time.Hour)
	first.Raw = json.RawMessage("{\n  \"ID\": \"one\", \"large\":9007199254740993\n}")
	if _, err = st.UpsertAlert(ctx, first); err != nil {
		t.Fatal(err)
	}
	same := testAlert("first")
	same.EventTime = first.EventTime
	same.Raw = json.RawMessage("{ \"large\":9007199254740993,\"ID\":\"one\" }")
	if _, err = st.UpsertAlert(ctx, same); err != nil {
		t.Fatal(err)
	}
	initial, err := st.ListAlertChanges(ctx, "", 1, "", "")
	if err != nil || len(initial.Changes) != 1 || initial.HasMore {
		t.Fatalf("initial=%+v err=%v", initial, err)
	}
	if same.Changed {
		t.Fatal("JSON formatting manufactured a revision")
	}
	changed := testAlert("first")
	changed.EventTime = first.EventTime
	changed.Raw = json.RawMessage(`{"ID":"one","large":9007199254740994}`)
	if _, err = st.UpsertAlert(ctx, changed); err != nil {
		t.Fatal(err)
	}
	page, err := st.ListAlertChanges(ctx, initial.NextCursor, 1, "tencent", first.AccountID)
	if err != nil || len(page.Changes) != 1 || page.Changes[0].ChangeType != "updated" || page.Changes[0].Revision != 2 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	before := page.NextCursor
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	reread, err := st.ListAlertChanges(ctx, initial.NextCursor, 1, "tencent", first.AccountID)
	if err != nil || reread.NextCursor != before {
		t.Fatalf("cursor changed after restart: %+v %v", reread, err)
	}
	baseline, err := st.GetAlertRevision(ctx, first.ID, 1)
	if err != nil || string(baseline.Raw) != string(first.Raw) || baseline.Title != "first" {
		t.Fatalf("immutable revision changed: %+v %v", baseline, err)
	}
	for _, bad := range []string{"-1", "offset:10", "1.5"} {
		if _, err = st.ListAlertChanges(ctx, bad, 10, "", ""); err == nil {
			t.Fatalf("invalid cursor %q accepted", bad)
		}
	}
}

func TestLocalAnnotationsStayIndependentOfSourceSnapshots(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	a := testAlert("source fact")
	if _, err := st.UpsertAlert(ctx, a); err != nil {
		t.Fatal(err)
	}
	seq := a.Sequence
	before, _ := st.GetAlert(ctx, a.ID)
	if err := st.UpdateAlertStatus(ctx, a.ID, model.StatusAcknowledged); err != nil {
		t.Fatal(err)
	}
	items, total, err := st.ListAlerts(ctx, model.AlertFilter{SnapshotSequence: &seq, Statuses: []model.AlertStatus{model.StatusAcknowledged}})
	if err != nil || total != 1 || items[0].Status != model.StatusAcknowledged {
		t.Fatalf("annotation lost in snapshot: %+v %d %v", items, total, err)
	}
	for _, read := range []func() (*model.AlertRecord, error){
		func() (*model.AlertRecord, error) { return st.GetAlert(ctx, a.ID) },
		func() (*model.AlertRecord, error) { return st.GetAlertAtSnapshot(ctx, a.ID, seq) },
		func() (*model.AlertRecord, error) { return st.GetAlertRevision(ctx, a.ID, 1) },
	} {
		record, err := read()
		if err != nil || record.Status != model.StatusAcknowledged || record.Revision != 1 || !record.UpdatedAt.Equal(before.UpdatedAt) {
			t.Fatalf("annotation altered source version: %+v %v", record, err)
		}
	}
	feed, err := st.ListAlertChanges(ctx, strconv.FormatInt(seq, 10), 10, "", "")
	if err != nil || len(feed.Changes) != 0 {
		t.Fatalf("local annotation emitted source change: %+v %v", feed, err)
	}
}

func TestTypedObservableAndIngestionTimeQueries(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i, typ := range []int{0, 8} {
		a := testAlert("unknown event time")
		a.ExternalID = strconv.Itoa(i)
		a.EventTime = time.Time{}
		a.IngestedAt = now
		a.Observables = []model.Observable{{TypeID: typ, Value: "same-value"}}
		if _, err := st.UpsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	unknown := 0
	_, total, err := st.ListAlerts(ctx, model.AlertFilter{ObservableType: &unknown, ObservableValue: "same-value"})
	if err != nil || total != 1 {
		t.Fatalf("type zero became wildcard: %d %v", total, err)
	}
	_, total, err = st.ListAlerts(ctx, model.AlertFilter{ObservableValue: "same-value"})
	if err != nil || total != 2 {
		t.Fatalf("untyped value omitted members: %d %v", total, err)
	}
	start, end := now.Add(-time.Hour), now.Add(time.Hour)
	for field, want := range map[string]int{"event_time": 0, "source_updated_at": 0, "ingested_at": 2} {
		_, total, err := st.ListAlerts(ctx, model.AlertFilter{Start: &start, End: &end, TimeField: field})
		if err != nil || total != want {
			t.Fatalf("time field %s count=%d want=%d err=%v", field, total, want, err)
		}
	}
}

func TestSnapshotRetainsFieldsAndObservablesDuringUpdates(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	first := testAlert("before")
	first.Observables = []model.Observable{{TypeID: 8, Name: "file.hash.sha256", Value: "old-hash"}}
	first.RuleID = "rule-1"
	if _, err := st.UpsertAlert(ctx, first); err != nil {
		t.Fatal(err)
	}
	seq, err := st.SnapshotSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	updated := testAlert("after")
	updated.Observables = []model.Observable{{TypeID: 8, Name: "file.hash.sha256", Value: "new-hash"}}
	updated.RuleID = "rule-2"
	if _, err = st.UpsertAlert(ctx, updated); err != nil {
		t.Fatal(err)
	}
	late := testAlert("late")
	late.ExternalID = "late"
	late.EventTime = first.EventTime
	if _, err = st.UpsertAlert(ctx, late); err != nil {
		t.Fatal(err)
	}
	items, total, err := st.ListAlerts(ctx, model.AlertFilter{SnapshotSequence: &seq, ObservableValue: "old-hash", Limit: 10})
	if err != nil || total != 1 || len(items) != 1 || items[0].Title != "before" {
		t.Fatalf("snapshot changed: %+v %d %v", items, total, err)
	}
	_, total, err = st.ListAlerts(ctx, model.AlertFilter{ObservableValue: "old-hash"})
	if err != nil || total != 0 {
		t.Fatalf("current index contains obsolete value: %d %v", total, err)
	}
	groups, total, err := st.ListAlertGroups(ctx, model.AlertFilter{SnapshotSequence: &seq, GroupBy: model.GroupByTypeAsset})
	if err != nil || total != 1 || groups[0].FindingCount != 1 {
		t.Fatalf("snapshot grouping changed: %+v %v", groups, err)
	}
	stats, err := st.AlertStats(ctx, model.AlertFilter{SnapshotSequence: &seq})
	if err != nil || stats.Total != 1 {
		t.Fatalf("snapshot stats=%+v %v", stats, err)
	}
	detail, err := st.GetAlertAtSnapshot(ctx, first.ID, seq)
	if err != nil || detail.Title != "before" || detail.RuleID != "rule-1" {
		t.Fatalf("snapshot detail=%+v %v", detail, err)
	}
}

func TestEveryRevisionCanBePagedAndFailedWritesAreAtomic(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	var id string
	for i := 0; i < 205; i++ {
		a := testAlert(strconv.Itoa(i))
		if _, err := st.UpsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
		id = a.ID
	}
	all, before := 0, 0
	for {
		items, err := st.AlertRevisionPage(ctx, id, before, 50)
		if err != nil {
			t.Fatal(err)
		}
		if len(items) == 0 {
			break
		}
		all += len(items)
		before = items[len(items)-1].Revision
	}
	if all != 205 {
		t.Fatalf("only %d revisions accessible", all)
	}
	seq, _ := st.SnapshotSequence(ctx)
	// Fail after the revision was inserted, while building the query index.
	if _, err := st.db.Exec(`CREATE TRIGGER fail_index BEFORE INSERT ON alert_versions BEGIN SELECT RAISE(ABORT,'index failure'); END`); err != nil {
		t.Fatal(err)
	}
	broken := testAlert("must roll back")
	if _, err := st.UpsertAlert(ctx, broken); err == nil {
		t.Fatal("injected failure accepted")
	}
	after, _ := st.SnapshotSequence(ctx)
	if after != seq {
		t.Fatalf("failed transaction leaked a feed entry: %d -> %d", seq, after)
	}
	latest, err := st.GetAlert(ctx, id)
	if err != nil || latest.Title != "204" {
		t.Fatalf("failed transaction changed current record: %+v %v", latest, err)
	}
	page, err := st.ListAlertChanges(ctx, "0", 1000, "", "")
	if err != nil || len(page.Changes) != 205 {
		t.Fatalf("changes=%d err=%v", len(page.Changes), err)
	}
	for i, c := range page.Changes {
		if c.Sequence != int64(i+1) {
			t.Fatal(fmt.Sprintf("unexpected order: %+v", c))
		}
	}
}
