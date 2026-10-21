package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestOlderSourceVersionIsRetainedWithoutReplacingCurrentProjection(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	makeRecord := func(label string, modified, ingested time.Time) *model.AlertRecord {
		a := testAlert(label)
		a.SourceUpdatedAt, a.IngestedAt = modified, ingested
		a.VendorStatus = label
		a.Raw = json.RawMessage(fmt.Sprintf(`{"id":"one","status":%q}`, label))
		a.Observables = []model.Observable{{Name: "file.hash.sha256", TypeID: 8, Value: label}}
		return a
	}
	current := makeRecord("newer", at.Add(time.Hour), at.Add(time.Hour))
	if _, err := st.UpsertAlert(ctx, current); err != nil {
		t.Fatal(err)
	}
	baseline, err := st.GetAlert(ctx, current.ID)
	if err != nil {
		t.Fatal(err)
	}
	old := makeRecord("older", at, at.Add(2*time.Hour))
	if _, err := st.UpsertAlert(ctx, old); err != nil {
		t.Fatal(err)
	}
	if !old.Changed || old.ProjectionUpdated || old.Revision != 2 {
		t.Fatalf("stale observation not retained independently: %+v", old)
	}
	for _, sequence := range []int64{current.Sequence, old.Sequence} {
		items, total, err := st.ListAlerts(ctx, model.AlertFilter{SnapshotSequence: &sequence, ObservableValue: "newer"})
		if err != nil || total != 1 || items[0].Revision != 1 || items[0].VendorStatus != "newer" {
			t.Fatalf("snapshot changed current facts: %+v %d %v", items, total, err)
		}
		detail, err := st.GetAlertAtSnapshot(ctx, current.ID, sequence)
		if err != nil || detail.VendorStatus != "newer" || string(detail.Raw) != string(current.Raw) {
			t.Fatalf("snapshot detail returned older observation: %+v %v", detail, err)
		}
		groups, _, err := st.ListAlertGroups(ctx, model.AlertFilter{SnapshotSequence: &sequence})
		wantChanges := 0
		if sequence == old.Sequence {
			wantChanges = 1
		}
		if err != nil || len(groups) != 1 || groups[0].RevisionCount != wantChanges {
			t.Fatalf("history count at %d: %+v %v", sequence, groups, err)
		}
	}
	got, err := st.GetAlert(ctx, current.ID)
	if err != nil || got.Revision != 1 || got.Sequence != current.Sequence || got.VendorStatus != "newer" || !got.UpdatedAt.Equal(baseline.UpdatedAt) || !got.LastIngestedAt.Equal(baseline.LastIngestedAt) {
		t.Fatalf("current projection regressed: %+v %v", got, err)
	}
	_, total, err := st.ListAlerts(ctx, model.AlertFilter{ObservableValue: "older"})
	if err != nil || total != 0 {
		t.Fatalf("stale observable leaked into current index: %d %v", total, err)
	}
	revision, err := st.GetAlertRevision(ctx, current.ID, 2)
	if err != nil || revision.ProjectionUpdated || string(revision.Raw) != string(old.Raw) {
		t.Fatalf("stale raw is inaccessible: %+v %v", revision, err)
	}
	feed, err := st.ListAlertChanges(ctx, strconv.FormatInt(current.Sequence, 10), 20, "", "")
	if err != nil || len(feed.Changes) != 1 || feed.Changes[0].ProjectionUpdated || feed.Changes[0].Revision != 2 {
		t.Fatalf("feed misrepresented projection update: %+v %v", feed, err)
	}
	duplicate := makeRecord("older", at, at.Add(3*time.Hour))
	if _, err := st.UpsertAlert(ctx, duplicate); err != nil || duplicate.Changed {
		t.Fatalf("duplicate stale observation created another revision: %+v %v", duplicate, err)
	}
	high, _ := st.SnapshotSequence(ctx)
	if high != old.Sequence {
		t.Fatal("repeated stale payload emitted a feed entry")
	}
	// Explicit vendor modification time wins even if collection was delayed.
	future := makeRecord("newest", at.Add(4*time.Hour), at.Add(-time.Hour))
	if _, err := st.UpsertAlert(ctx, future); err != nil || !future.ProjectionUpdated || future.Revision != 3 {
		t.Fatalf("newer vendor version was not promoted: %+v %v", future, err)
	}
	got, err = st.GetAlert(ctx, current.ID)
	if err != nil || got.VendorStatus != "newest" || got.Revision != 3 {
		t.Fatalf("future version missing: %+v %v", got, err)
	}
}

func TestProjectionOrderingOnlyUsesKnownSourceModificationOrCollectionTime(t *testing.T) {
	at := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name                                                   string
		oldSource, incomingSource, oldCapture, incomingCapture time.Time
		promote                                                bool
	}{
		{"known older", at, at.Add(-time.Nanosecond), at, at.Add(time.Hour), false},
		{"known newer", at, at.Add(time.Nanosecond), at, at.Add(-time.Hour), true},
		{"equal source delayed retry", at, at, at, at.Add(-time.Hour), false},
		{"unknown source delayed retry", time.Time{}, time.Time{}, at, at.Add(-time.Hour), false},
		{"unknown source later observation", time.Time{}, time.Time{}, at, at.Add(time.Hour), true},
		{"one missing timestamp", at, time.Time{}, at, at.Add(time.Hour), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newTestStore(t)
			first := testAlert("current")
			first.SourceUpdatedAt, first.IngestedAt = tc.oldSource, tc.oldCapture
			if _, err := st.UpsertAlert(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			incoming := testAlert("incoming")
			incoming.SourceUpdatedAt, incoming.IngestedAt = tc.incomingSource, tc.incomingCapture
			incoming.EventTime = at.Add(365 * 24 * time.Hour) // occurrence time must not determine revision ordering
			if _, err := st.UpsertAlert(context.Background(), incoming); err != nil {
				t.Fatal(err)
			}
			if incoming.ProjectionUpdated != tc.promote {
				t.Fatalf("projection_updated=%v want=%v", incoming.ProjectionUpdated, tc.promote)
			}
			got, err := st.GetAlert(context.Background(), first.ID)
			want := "current"
			if tc.promote {
				want = "incoming"
			}
			if err != nil || got.Title != want {
				t.Fatalf("selected=%+v want=%s err=%v", got, want, err)
			}
		})
	}
}

func TestRepeatedPayloadCannotMoveLastIngestedTimeBackwards(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)
	for _, captured := range []time.Time{at, at.Add(time.Hour), at.Add(-time.Hour)} {
		a := testAlert("same")
		a.IngestedAt = captured
		if _, err := st.UpsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	items, _, err := st.ListAlerts(ctx, model.AlertFilter{})
	if err != nil || len(items) != 1 || !items[0].LastIngestedAt.Equal(at.Add(time.Hour)) {
		t.Fatalf("last ingestion regressed: %+v %v", items, err)
	}
}

func TestDelayedRetryIsComparedWithLastObservationOfCurrentContent(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)
	var id string
	for _, captured := range []time.Time{at, at.Add(10 * time.Hour)} {
		a := testAlert("current observed again")
		a.IngestedAt = captured
		if _, err := st.UpsertAlert(ctx, a); err != nil {
			t.Fatal(err)
		}
		id = a.ID
	}
	old := testAlert("old failure")
	old.IngestedAt = at.Add(5 * time.Hour)
	if _, err := st.UpsertAlert(ctx, old); err != nil || old.ProjectionUpdated {
		t.Fatalf("retry compared with first capture instead of last observation: %+v %v", old, err)
	}
	got, err := st.GetAlert(ctx, id)
	if err != nil || got.Title != "current observed again" {
		t.Fatalf("current content regressed: %+v %v", got, err)
	}
}
