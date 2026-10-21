package query

import (
	"context"
	"encoding/json"
	"path/filepath"
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
