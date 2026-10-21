package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestReplayCorrectsTimesAcrossPagesAndPreservesState(t *testing.T) {
	st, cipher, reg, acct, fake := fixture(t)
	eng := New(st, reg, cipher, Options{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	fake.fetchFn = func(context.Context, connector.Query) (connector.Page, error) {
		t.Fatal("replay must not fetch cloud data")
		return connector.Page{}, nil
	}
	ctx := context.Background()
	correct := time.Now().UTC().Truncate(time.Millisecond)
	var firstID string
	for i := 0; i < 205; i++ {
		raw := rawAlert(t, fmt.Sprint(i), "historical", 3, correct)
		a, err := fake.Normalize(raw)
		if err != nil {
			t.Fatal(err)
		}
		a.EventTime = correct.Add(8 * time.Hour)
		rec, err := eng.buildRecord(*acct, fake.Info(), a, correct)
		if err != nil {
			t.Fatal(err)
		}
		rec.ID = fmt.Sprintf("%05d", i)
		rec.Status = model.StatusClosed
		if _, err := st.UpsertAlert(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstID = rec.ID
		}
	}
	before, _ := st.GetAlert(ctx, firstID)
	preview, err := eng.Replay(ctx, *acct, model.AlertFilter{}, "", false)
	if err != nil || preview.Scanned != 205 || preview.Changed != 205 {
		t.Fatalf("preview=%+v err=%v", preview, err)
	}
	after, _ := st.GetAlert(ctx, firstID)
	if !after.EventTime.Equal(before.EventTime) {
		t.Fatal("dry run changed stored data")
	}
	result, err := eng.Replay(ctx, *acct, model.AlertFilter{}, "", true)
	if err != nil || result.Scanned != 205 || result.Changed != 205 {
		t.Fatalf("apply=%+v err=%v", result, err)
	}
	after, _ = st.GetAlert(ctx, firstID)
	if !after.EventTime.Equal(correct) || after.Status != model.StatusClosed || string(after.Raw) != string(before.Raw) || after.ID != before.ID || !after.CreatedAt.Equal(before.CreatedAt) {
		t.Fatalf("unexpected replay result: %+v", after)
	}
	result, err = eng.Replay(ctx, *acct, model.AlertFilter{}, "", true)
	if err != nil || result.Changed != 0 {
		t.Fatalf("replay not idempotent: %+v err=%v", result, err)
	}
}

func TestExpiredPageTokenRestartsOnlyTheSameWindow(t *testing.T) {
	st, cipher, reg, acct, fake := fixture(t)
	eng := New(st, reg, cipher, Options{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	end := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	start := end.Add(-time.Hour)
	if err := st.SaveSyncState(context.Background(), &model.SyncState{AccountID: acct.ID, PendingStart: start, PendingEnd: end, PendingToken: "expired"}); err != nil {
		t.Fatal(err)
	}
	var tokens []string
	fake.fetchFn = func(_ context.Context, q connector.Query) (connector.Page, error) {
		if !q.Start.Equal(start) || !q.End.Equal(end) {
			t.Fatal("recovery changed the time window")
		}
		tokens = append(tokens, q.Token)
		if q.Token != "" {
			return connector.Page{}, errors.New("InvalidNextToken: token expired")
		}
		return connector.Page{}, nil
	}
	run, err := eng.SyncAccount(context.Background(), *acct, "test")
	if err != nil || run.Status != "success" || len(tokens) != 2 || tokens[0] != "expired" || tokens[1] != "" {
		t.Fatalf("run=%+v tokens=%v err=%v", run, tokens, err)
	}
	state, _ := st.GetSyncState(context.Background(), acct.ID)
	if !state.CursorEnd.Equal(end) || state.PendingToken != "" {
		t.Fatalf("state=%+v", state)
	}
}
