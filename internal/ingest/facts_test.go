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
