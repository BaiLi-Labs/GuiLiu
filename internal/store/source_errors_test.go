package store

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestSourceDiagnosticsSurviveReopenAndClearOnNewAttempt(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "source-errors.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSyncState(ctx, &model.SyncState{AccountID: "legacy", LastError: "existing safe failure"}); err != nil {
		st.Close()
		t.Fatal(err)
	}
	// Emulate an existing schema-5 development database before the additive
	// diagnostics columns. Existing data must remain queryable after reopen.
	for _, table := range []string{"sync_states", "sync_runs", "asset_refreshes"} {
		if _, err := st.db.Exec("ALTER TABLE " + table + " DROP COLUMN source_error"); err != nil {
			st.Close()
			t.Fatal(err)
		}
	}
	st.Close()
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := st.GetSyncState(ctx, "legacy")
	if err != nil || legacy.LastError != "existing safe failure" || legacy.LastSourceError != nil {
		t.Fatal("existing operational data changed", legacy, err)
	}
	detail := &model.SourceError{Provider: "tencent", Kind: "permission", Code: "UnauthorizedOperation", SourceAPI: "VPC DescribeVpcs"}
	attempt := model.AssetRefresh{AccountID: "synthetic", Region: "ap-guangzhou", ResourceID: "vpc-synthetic", Status: "permission_denied", AttemptedAt: time.Now().UTC(), SourceError: detail}
	if ok, err := st.BeginAssetRefresh(ctx, attempt, time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if err := st.FinishAssetRefresh(ctx, attempt); err != nil {
		t.Fatal(err)
	}
	state := &model.SyncState{AccountID: attempt.AccountID, LastError: "safe summary", LastSourceError: detail}
	if err := st.SaveSyncState(ctx, state); err != nil {
		t.Fatal(err)
	}
	run := &model.SyncRun{AccountID: attempt.AccountID, Status: "running"}
	if err := st.StartSyncRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	run.Status, run.SourceError = "failed", detail
	if err := st.FinishSyncRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	st.Close()
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.GetAssetRefresh(ctx, attempt.AccountID, attempt.Region, attempt.ResourceID)
	if err != nil || !reflect.DeepEqual(got.SourceError, detail) {
		t.Fatal(got, err)
	}
	state, err = st.GetSyncState(ctx, attempt.AccountID)
	if err != nil || !reflect.DeepEqual(state.LastSourceError, detail) {
		t.Fatal(state, err)
	}
	runs, err := st.ListSyncRuns(ctx, attempt.AccountID, 1)
	if err != nil || len(runs) != 1 || !reflect.DeepEqual(runs[0].SourceError, detail) {
		t.Fatal(runs, err)
	}
	attempt.AttemptedAt = attempt.AttemptedAt.Add(2 * time.Minute)
	if ok, err := st.BeginAssetRefresh(ctx, attempt, time.Minute); err != nil || !ok {
		t.Fatal(ok, err)
	}
	got, err = st.GetAssetRefresh(ctx, attempt.AccountID, attempt.Region, attempt.ResourceID)
	if err != nil || got.Status != "refreshing" || got.SourceError != nil {
		t.Fatal("new request retained previous error", got, err)
	}
}
