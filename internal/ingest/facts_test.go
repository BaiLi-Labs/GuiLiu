package ingest

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestMissingSourceTimeDoesNotMoveOrManufactureRevisions(t *testing.T) {
	st, cipher, reg, acct, fake := fixture(t)
	e := New(st, reg, cipher, Options{}, slog.Default())
	ctx := context.Background()
	at := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	a := model.Alert{ExternalID: "unchanged", FindingKind: model.FindingDetection, Title: "unchanged", Raw: json.RawMessage(`{"id":"unchanged"}`)}
	var id string
	for i := 0; i < 2; i++ {
		e.now = func() time.Time { return at.Add(time.Duration(i) * 5 * time.Minute) }
		r, err := e.buildRecord(*acct, fake.Info(), a, e.now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = st.UpsertAlert(ctx, r); err != nil {
			t.Fatal(err)
		}
		id = r.ID
	}
	rec, err := st.GetAlert(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !rec.EventTime.IsZero() || !rec.FirstSeenAt.IsZero() || !rec.LastSeenAt.IsZero() || rec.Revision != 1 || len(rec.OCSF) > 0 {
		t.Fatalf("unknown facts were fabricated: %+v", rec)
	}
	if !rec.LastIngestedAt.After(rec.IngestedAt) {
		t.Fatal("ingestion observations not tracked separately")
	}
	changes, err := st.ListAlertChanges(ctx, "", 100, "", "")
	if err != nil || len(changes.Changes) != 1 {
		t.Fatalf("unchanged record emitted changes: %+v %v", changes, err)
	}
}

func TestRenamingConnectionDoesNotCreateSourceRevision(t *testing.T) {
	st, cipher, reg, acct, fake := fixture(t)
	e := New(st, reg, cipher, Options{}, slog.Default())
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)
	a := model.Alert{ExternalID: "native", FindingKind: model.FindingDetection, Title: "source title", EventTime: at, CloudAccountUID: "vendor-account", Raw: json.RawMessage(`{"id":"native","title":"source title"}`)}
	first, err := e.buildRecord(*acct, fake.Info(), a, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAlert(ctx, first); err != nil {
		t.Fatal(err)
	}
	baseline, err := st.GetAlert(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	acct.Name = "new connection label"
	if err := st.UpdateAccount(ctx, acct, nil); err != nil {
		t.Fatal(err)
	}
	repeated, err := e.buildRecord(*acct, fake.Info(), a, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAlert(ctx, repeated); err != nil {
		t.Fatal(err)
	}
	if repeated.Changed || repeated.Revision != 1 {
		t.Fatalf("rename manufactured source revision: %+v", repeated)
	}
	if string(repeated.OCSF) != string(first.OCSF) {
		t.Fatal("local connection name leaked into OCSF")
	}
	feed, err := st.ListAlertChanges(ctx, "0", 20, "", "")
	if err != nil || len(feed.Changes) != 1 {
		t.Fatalf("rename emitted a source change: %+v %v", feed, err)
	}
	for _, read := range []func() (*model.AlertRecord, error){
		func() (*model.AlertRecord, error) { return st.GetAlert(ctx, first.ID) },
		func() (*model.AlertRecord, error) { return st.GetAlertAtSnapshot(ctx, first.ID, first.Sequence) },
		func() (*model.AlertRecord, error) { return st.GetAlertRevision(ctx, first.ID, 1) },
	} {
		got, err := read()
		if err != nil || got.AccountName != acct.Name || !got.UpdatedAt.Equal(baseline.UpdatedAt) || got.RawHash != baseline.RawHash {
			t.Fatalf("rename changed source facts or lost display name: %+v %v", got, err)
		}
	}
	sequence := first.Sequence
	items, _, err := st.ListAlerts(ctx, model.AlertFilter{SnapshotSequence: &sequence})
	if err != nil || len(items) != 1 || items[0].AccountName != acct.Name {
		t.Fatalf("snapshot retained outdated local label: %+v %v", items, err)
	}
}

func TestMappingFailureRetryRetainsOldContentWithoutRegressingCurrent(t *testing.T) {
	for _, knownSourceTime := range []bool{false, true} {
		t.Run(map[bool]string{false: "collection time", true: "vendor modification time"}[knownSourceTime], func(t *testing.T) {
			st, cipher, reg, acct, fake := fixture(t)
			e := New(st, reg, cipher, Options{}, slog.Default())
			ctx := context.Background()
			at := time.Now().UTC().Truncate(time.Millisecond)
			fake.normalizeFn = func(raw json.RawMessage) (model.Alert, error) {
				var a model.Alert
				err := json.Unmarshal(raw, &a)
				return a, err
			}
			old := model.Alert{ExternalID: "native", FindingKind: model.FindingDetection, Title: "older", EventTime: at}
			newer := old
			newer.Title = "newer"
			if knownSourceTime {
				old.SourceUpdatedAt, newer.SourceUpdatedAt = at, at.Add(time.Hour)
			}
			oldRaw, _ := json.Marshal(old)
			newRaw, _ := json.Marshal(newer)
			if err := st.SaveIngestFailure(ctx, &model.IngestFailure{AccountID: acct.ID, Raw: oldRaw, IngestedAt: at, MapperVersion: "old/v1", Error: "previous mapping failure"}); err != nil {
				t.Fatal(err)
			}
			if _, _, err := e.processRecord(ctx, *acct, fake, newRaw, at.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if _, _, failed, err := e.retryFailures(ctx, *acct, fake); err != nil || failed != 0 {
				t.Fatalf("retry failed=%d err=%v", failed, err)
			}
			items, _, err := st.ListAlerts(ctx, model.AlertFilter{})
			if err != nil || len(items) != 1 || items[0].Title != "newer" || items[0].Revision != 1 {
				t.Fatalf("retry regressed current projection: %+v %v", items, err)
			}
			_, remaining, err := st.ListIngestFailures(ctx, acct.ID, 100)
			if err != nil || remaining != 0 {
				t.Fatalf("successful retry remains pending: %d %v", remaining, err)
			}
			feed, err := st.ListAlertChanges(ctx, "0", 20, "", "")
			if err != nil || len(feed.Changes) != 2 || !feed.Changes[0].ProjectionUpdated || feed.Changes[1].ProjectionUpdated {
				t.Fatalf("retry feed=%+v %v", feed, err)
			}
			history, err := st.GetAlertRevision(ctx, items[0].ID, 2)
			if err != nil || history.Title != "older" || string(history.Raw) != string(oldRaw) {
				t.Fatalf("retry lost original evidence: %+v %v", history, err)
			}
		})
	}
}
