package ingest

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
)

func TestSourceDenialIsDurableDoesNotAdvanceAndClearsAfterRecovery(t *testing.T) {
	ctx := context.Background()
	st, cipher, reg, account, fake := fixture(t)
	engine := New(st, reg, cipher, Options{Enabled: true, InitialLookback: time.Hour, MaxWindow: time.Hour, PageSize: 10, MaxPages: 2, Workers: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	calls := 0
	fake.fetchFn = func(context.Context, connector.Query) (connector.Page, error) {
		calls++
		return connector.Page{}, connector.WithSourceAPI("tencent", "CSIP DescribeAlertList", tcerrors.NewTencentCloudSDKError("UnauthorizedOperation", "DO_NOT_LEAK", ""))
	}
	run, err := engine.SyncAccount(ctx, *account, "manual")
	if err == nil || run.Status != "failed" || calls != 1 || run.SourceError == nil || run.SourceError.Code != "UnauthorizedOperation" {
		t.Fatal(run, err, calls)
	}
	state, err := st.GetSyncState(ctx, account.ID)
	if err != nil || state.LastSourceError == nil || state.LastSourceError.Kind != "permission" || !state.CursorEnd.IsZero() || state.LastSuccessAt != nil || state.Health(time.Now(), time.Hour) == "healthy" || strings.Contains(state.LastError, "DO_NOT_LEAK") {
		t.Fatal(state, err)
	}
	runs, err := st.ListSyncRuns(ctx, account.ID, 1)
	if err != nil || len(runs) != 1 || runs[0].SourceError == nil || runs[0].SourceError.SourceAPI != "CSIP DescribeAlertList" {
		t.Fatal(runs, err)
	}
	fake.fetchFn = func(context.Context, connector.Query) (connector.Page, error) { return connector.Page{}, nil }
	if _, err := engine.SyncAccount(ctx, *account, "manual"); err != nil {
		t.Fatal(err)
	}
	state, err = st.GetSyncState(ctx, account.ID)
	if err != nil || state.LastSourceError != nil || state.LastError != "" || state.CursorEnd.IsZero() {
		t.Fatal("failure did not clear on recovery", state, err)
	}
}
