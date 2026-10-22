package store

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestDistributionsCountFindingsAndKeepSnapshot(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	var first *model.AlertRecord
	for i, title := range []string{"A", "A", "B", "B", "C", ""} {
		a := testAlert(title)
		a.ExternalID = fmt.Sprint(i)
		a.SourceCountry = "Source value"
		if i == 5 {
			a.SourceIP = ""
			a.SourceCountry = ""
		}
		if _, err := st.UpsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = a
		}
	}
	seq, err := st.SnapshotSequence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f := model.AlertFilter{SnapshotSequence: &seq, StatsOptions: model.StatsOptions{TopBy: []string{"title", "source_ip", "source_country", "severity_day"}, TopN: 1}}
	s, err := st.AlertStats(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	d := s.Distributions["title"]
	if s.Total != 6 || d.DistinctCount != 3 || d.MissingCount != 1 || d.OtherCount != 3 || !d.HasMore || len(d.Top) != 1 || d.Top[0].Key != "A" || d.Top[0].Count != 2 {
		t.Fatalf("title counts=%+v", s)
	}
	for _, key := range []string{"source_ip", "source_country"} {
		d = s.Distributions[key]
		if d.DistinctCount != 1 || d.MissingCount != 1 || d.HasMore || d.OtherCount != 0 || d.Top[0].Count != 5 {
			t.Fatalf("%s: %+v", key, d)
		}
	}
	d = s.Distributions["severity_day"]
	if s.DayTimezone != "UTC" || d.Top[0].Key != "2026-10-20" || d.Top[0].Severity != "high" || d.Top[0].Count != 6 {
		t.Fatalf("day: %+v", d)
	}
	// Re-observation is not another Finding. A changed source creates a
	// revision, while the pinned distribution must still show the old value.
	if _, err := st.UpsertAlert(ctx, first); err != nil {
		t.Fatal(err)
	}
	first.Title = "Z"
	first.SourceCountry = "Changed"
	first.Raw = json.RawMessage(`{"changed":true}`)
	if _, err := st.UpsertAlert(ctx, first); err != nil {
		t.Fatal(err)
	}
	pinned, err := st.AlertStats(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.Distributions["title"].Top[0].Key != "A" {
		t.Fatal("snapshot distribution moved")
	}
	f.SnapshotSequence = nil
	f.VendorTitle = "Z"
	s, err = st.AlertStats(ctx, f)
	if err != nil || s.Total != 1 || s.Distributions["title"].Top[0].Key != "Z" {
		t.Fatalf("filter not applied: %+v %v", s, err)
	}
	f.VendorTitle = "absent"
	s, err = st.AlertStats(ctx, f)
	if err != nil || s.Total != 0 || len(s.Distributions["title"].Top) != 0 || s.Distributions["title"].MissingCount != 0 {
		t.Fatalf("empty=%+v %v", s, err)
	}
}

func TestObservedEventRangesRespectFilterAndSnapshot(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	a := testAlert("old")
	if _, err := st.UpsertAlert(ctx, a); err != nil {
		t.Fatal(err)
	}
	seq, _ := st.SnapshotSequence(ctx)
	old := a.EventTime
	a.EventTime = old.Add(time.Hour)
	a.Raw = json.RawMessage(`{"new":true}`)
	if _, err := st.UpsertAlert(ctx, a); err != nil {
		t.Fatal(err)
	}
	ranges, err := st.ObservedEventRanges(ctx, model.AlertFilter{SnapshotSequence: &seq})
	if err != nil || ranges[a.AccountID].FindingCount != 1 || !ranges[a.AccountID].Start.Equal(old) {
		t.Fatalf("snapshot bounds: %+v %v", ranges, err)
	}
	ranges, err = st.ObservedEventRanges(ctx, model.AlertFilter{VendorTitle: "absent"})
	if err != nil || len(ranges) != 0 {
		t.Fatalf("filter bounds=%+v %v", ranges, err)
	}
}
