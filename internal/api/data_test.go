package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

func TestDataAccessFeedSnapshotAndHistoricalRaw(t *testing.T) {
	ts, st, _ := setup(t, true)
	client := newClient(t, ts)
	ctx := context.Background()
	id := createAccount(t, ts, client, "")
	a := seedAlert(t, st, id)
	response, body := do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts?sort=id&limit=1", "", "")
	var first struct {
		Snapshot int64        `json:"snapshot_sequence"`
		Alerts   []view.Alert `json:"alerts"`
	}
	if response.StatusCode != 200 || json.Unmarshal(body, &first) != nil || len(first.Alerts) != 1 {
		t.Fatalf("snapshot=%s", body)
	}
	a.Title = "source changed"
	a.Raw = json.RawMessage("{\n \"native_id\": \"source\", \"future\":9007199254740993\n}")
	if _, err := st.UpsertAlert(ctx, a); err != nil {
		t.Fatal(err)
	}
	response, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts/changes?cursor="+strconv.FormatInt(first.Snapshot, 10), "", "")
	var feed model.ChangePage
	if response.StatusCode != 200 || json.Unmarshal(body, &feed) != nil || len(feed.Changes) != 1 || feed.Changes[0].Revision != 2 {
		t.Fatalf("changes=%s", body)
	}
	response, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts/"+a.ID+"?snapshot_sequence="+strconv.FormatInt(first.Snapshot, 10), "", "")
	var previous view.Alert
	if response.StatusCode != 200 || json.Unmarshal(body, &previous) != nil || previous.Title == "source changed" {
		t.Fatalf("snapshot detail moved=%s", body)
	}
	response, body = do(t, client, http.MethodGet, ts.URL+fmt.Sprintf("/api/v1/alerts/%s/revisions/2", a.ID), "", "")
	var detail view.Alert
	if response.StatusCode != 200 || json.Unmarshal(body, &detail) != nil || detail.RawURL == "" {
		t.Fatalf("revision detail=%s", body)
	}
	response, body = do(t, client, http.MethodGet, ts.URL+detail.RawURL, "", "")
	if response.StatusCode != 200 || string(body) != string(a.Raw) || detail.RawHash != fmt.Sprintf("%x", sha256.Sum256(body)) {
		t.Fatalf("historical raw/hash mismatch: %s", body)
	}
	for _, cursor := range []string{"-1", "garbage", "999999"} {
		response, _ = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts/changes?cursor="+cursor, "", "")
		if response.StatusCode != 400 {
			t.Fatalf("invalid cursor accepted: %s", cursor)
		}
	}
	response, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/coverage?since=7d", "", "")
	var coverage model.Coverage
	if response.StatusCode != 200 || json.Unmarshal(body, &coverage) != nil || coverage.Complete || len(coverage.Accounts) != 1 {
		t.Fatalf("unsynchronized coverage=%s", body)
	}
	now := time.Now().UTC()
	if err := st.SaveSyncState(ctx, &model.SyncState{AccountID: id, CoverageStart: now.Add(-24 * time.Hour), CursorEnd: now, LastSuccessAt: &now}); err != nil {
		t.Fatal(err)
	}
	response, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/coverage?since=7d", "", "")
	if response.StatusCode != 200 || json.Unmarshal(body, &coverage) != nil || coverage.Complete {
		t.Fatalf("recent success falsely covered 7d: %s", body)
	}
}
