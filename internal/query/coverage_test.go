package query

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func TestCoverageChecksTheRequestedHistoryNotOnlyFreshness(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "coverage.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	a := &model.Account{Name: "prod", Provider: "huawei", Enabled: true, Options: map[string]string{"project_id": "project", "workspace_id": "space"}}
	if err = st.CreateAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	watermark := now.Add(-2 * time.Minute)
	state := &model.SyncState{AccountID: a.ID, CoverageStart: now.Add(-24 * time.Hour), CursorEnd: watermark, LastSuccessAt: &now}
	if err = st.SaveSyncState(ctx, state); err != nil {
		t.Fatal(err)
	}
	start, end := now.Add(-time.Hour), now.Add(-3*time.Minute)
	registry := connector.NewRegistry()
	c, err := Coverage(ctx, st, registry, model.AlertFilter{Start: &start, End: &end}, 15*time.Minute)
	if err != nil || !c.Complete {
		t.Fatalf("bounded collected range=%+v %v", c, err)
	}
	start = now.Add(-7 * 24 * time.Hour)
	c, err = Coverage(ctx, st, registry, model.AlertFilter{Start: &start, End: &end}, 15*time.Minute)
	if err != nil || c.Complete || c.Accounts[0].Status != "healthy" {
		t.Fatalf("recent success falsely covered older history: %+v %v", c, err)
	}
	if c.Accounts[0].Scope["workspace_id"] != "space" {
		t.Fatal("source scope missing")
	}
	start = now.Add(-time.Hour)
	if err = st.SaveIngestFailure(ctx, &model.IngestFailure{AccountID: a.ID, Raw: json.RawMessage(`{"bad":true}`), IngestedAt: now, Error: "mapping failed"}); err != nil {
		t.Fatal(err)
	}
	c, err = Coverage(ctx, st, registry, model.AlertFilter{Start: &start, End: &end}, 15*time.Minute)
	if err != nil || c.Complete || c.Accounts[0].FailedRecords != 1 {
		t.Fatalf("mapping hole falsely complete: %+v %v", c, err)
	}
}

func TestCoverageSeparatesCollectionBoundsFromObservedEvents(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "facts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	a := &model.Account{Name: "synthetic", Provider: "tencent", Enabled: true}
	if err := st.CreateAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	collectionStart, watermark := now.Add(-24*time.Hour), now.Add(-time.Hour)
	pendingEnd := now.Add(-time.Minute)
	state := &model.SyncState{AccountID: a.ID, CoverageStart: collectionStart, CursorEnd: watermark, LastSuccessAt: &now, PendingStart: watermark, PendingEnd: pendingEnd, PendingToken: "private-resume-token"}
	if err := st.SaveSyncState(ctx, state); err != nil {
		t.Fatal(err)
	}
	event := now.Add(-48 * time.Hour)
	rec := &model.AlertRecord{AccountID: a.ID, Provider: "tencent", Alert: model.Alert{ExternalID: "old-event", Title: "synthetic", EventTime: event, Raw: json.RawMessage(`{"synthetic":true}`)}}
	if _, err := st.UpsertAlert(ctx, rec); err != nil {
		t.Fatal(err)
	}
	start, end := now.Add(-72*time.Hour), now
	c, err := Coverage(ctx, st, connector.NewRegistry(), model.AlertFilter{Start: &start, End: &end}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v := c.Accounts[0]
	if c.Complete || v.Status != "pending" || !v.CoverageStart.Equal(collectionStart) || !v.ObservedEvents.Start.Equal(event) || v.ObservedEvents.FindingCount != 1 || v.PendingWindow == nil || len(v.OutsideCompletedWindows) != 2 {
		t.Fatalf("facts: %+v", v)
	}
	if v.OutsideCompletedWindows[0].DurationSeconds != 48*3600 || v.OutsideCompletedWindows[1].DurationSeconds != 3600 {
		t.Fatalf("bounds comparison=%+v", v.OutsideCompletedWindows)
	}
	raw, _ := json.Marshal(c)
	if strings.Contains(string(raw), "private-resume-token") {
		t.Fatal("source pagination token leaked")
	}
	// An empty result does not extend a collection envelope or prove any
	// additional gap; all observation times remain explicitly null.
	c, err = Coverage(ctx, st, connector.NewRegistry(), model.AlertFilter{Start: &start, End: &end, VendorTitle: "absent"}, time.Hour)
	if err != nil || c.Accounts[0].ObservedEvents.FindingCount != 0 || c.Accounts[0].ObservedEvents.Start != nil || len(c.Accounts[0].OutsideCompletedWindows) != 2 {
		t.Fatalf("empty facts: %+v %v", c, err)
	}
}

func TestOutsideCollectionClipsBounds(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                 string
		start, end, from, to int
		want                 int
		seconds              float64
	}{
		{"before", 0, 1, 2, 3, 1, 3600}, {"after", 4, 5, 2, 3, 1, 3600}, {"within", 2, 3, 1, 4, 0, 0}, {"both", 0, 5, 1, 4, 2, 7200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := func(n int) time.Time { return base.Add(time.Duration(n) * time.Hour) }
			a, b := at(tc.start), at(tc.end)
			v := outsideCollection(&a, &b, at(tc.from), at(tc.to))
			var total float64
			for _, x := range v {
				total += x.DurationSeconds
			}
			if len(v) != tc.want || total != tc.seconds {
				t.Fatalf("%+v", v)
			}
		})
	}
	end := base.Add(time.Hour)
	if v := outsideCollection(&base, &end, time.Time{}, time.Time{}); len(v) != 1 || v[0].Reason != "no_completed_collection_window" {
		t.Fatalf("never collected: %+v", v)
	}
	if v := outsideCollection(nil, &end, base, end); len(v) != 0 {
		t.Fatalf("unbounded: %+v", v)
	}
}
