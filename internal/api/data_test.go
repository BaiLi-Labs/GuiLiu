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

func TestLateRevisionFeedAndSnapshotExposeSeparateVersions(t *testing.T) {
	ts, st, _ := setup(t, true)
	client := newClient(t, ts)
	id := createAccount(t, ts, client, "")
	a := seedAlert(t, st, id)
	at := time.Now().UTC()
	a.Title, a.SourceUpdatedAt, a.Raw = "newest source state", at, json.RawMessage(`{"id":"native","state":"newest"}`)
	if _, err := st.UpsertAlert(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	latestSequence, latestRevision := a.Sequence, a.Revision
	old := *a
	old.Title, old.SourceUpdatedAt, old.Raw = "older source state", at.Add(-time.Hour), json.RawMessage(`{"id":"native","state":"older"}`)
	if _, err := st.UpsertAlert(context.Background(), &old); err != nil {
		t.Fatal(err)
	}
	response, body := do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts/changes?cursor="+strconv.FormatInt(latestSequence, 10), "", "")
	var feed model.ChangePage
	if response.StatusCode != 200 || json.Unmarshal(body, &feed) != nil || len(feed.Changes) != 1 || feed.Changes[0].ProjectionUpdated || feed.Changes[0].Revision != latestRevision+1 {
		t.Fatalf("feed=%s", body)
	}
	for _, suffix := range []string{"", "?snapshot_sequence=" + strconv.FormatInt(old.Sequence, 10)} {
		response, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts/"+a.ID+suffix, "", "")
		var detail view.Alert
		if response.StatusCode != 200 || json.Unmarshal(body, &detail) != nil || detail.Title != a.Title || detail.Revision != latestRevision {
			t.Fatalf("current/snapshot regressed=%s", body)
		}
	}
	response, body = do(t, client, http.MethodGet, ts.URL+fmt.Sprintf("/api/v1/alerts/%s/revisions/%d", a.ID, old.Revision), "", "")
	var historical view.Alert
	if response.StatusCode != 200 || json.Unmarshal(body, &historical) != nil || historical.ProjectionUpdated || historical.Title != old.Title || historical.RawHash != old.RawHash {
		t.Fatalf("historical observation=%s", body)
	}
}

func TestFindingSelectionAndEvidenceMatchAcrossRESTAndMCP(t *testing.T) {
	ts, st, _ := setup(t, true)
	client := newClient(t, ts)
	id := createAccount(t, ts, client, "")
	rec := seedAlert(t, st, id)
	original, err := st.GetAlert(context.Background(), rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec.Title = "changed"
	rec.Raw = json.RawMessage(`{"id":"updated","integer":9007199254740993}`)
	if _, err := st.UpsertAlert(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"get_alert", "get_alert_evidence"} {
		request := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":{"alert_id":%q,"revision":1}}}`, name, rec.ID)
		response, body := do(t, client, "POST", ts.URL+"/mcp", "", request)
		var rpc struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if response.StatusCode != 200 || json.Unmarshal(body, &rpc) != nil || rpc.Result.IsError || len(rpc.Result.Content) != 1 {
			t.Fatalf("MCP %s", body)
		}
		var payload map[string]json.RawMessage
		_ = json.Unmarshal([]byte(rpc.Result.Content[0].Text), &payload)
		if name == "get_alert" {
			var d view.Alert
			_ = json.Unmarshal(payload["alert"], &d)
			if d.Revision != 1 || d.RawHash != original.RawHash {
				t.Fatal("MCP did not pin revision")
			}
		} else {
			var revision int
			var hash string
			_ = json.Unmarshal(payload["revision"], &revision)
			_ = json.Unmarshal(payload["raw_hash"], &hash)
			if revision != 1 || hash != original.RawHash || len(payload["raw_url"]) == 0 {
				t.Fatal("evidence did not pin revision")
			}
		}
	}
	response, body := do(t, client, "GET", ts.URL+"/api/v1/alerts/"+rec.ID+"?revision=1", "", "")
	var d view.Alert
	if response.StatusCode != 200 || json.Unmarshal(body, &d) != nil || d.RawHash != original.RawHash {
		t.Fatal("REST did not pin revision")
	}
	response, body = do(t, client, "GET", ts.URL+"/api/v1/alerts/"+rec.ID+"/raw?revision=1", "", "")
	if response.StatusCode != 200 || string(body) != string(original.Raw) {
		t.Fatal("REST raw did not pin revision")
	}
	response, _ = do(t, client, "GET", ts.URL+"/api/v1/alerts/"+rec.ID+"?revision=1&snapshot_sequence=0", "", "")
	if response.StatusCode != 400 {
		t.Fatal("ambiguous selection accepted")
	}
	for _, selection := range []string{`"revision":0`, `"revision":1.5`, `"revision":1,"snapshot_sequence":0`, `"snapshot_sequence":999999`} {
		request := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_alert","arguments":{"alert_id":%q,%s}}}`, rec.ID, selection)
		_, body := do(t, client, "POST", ts.URL+"/mcp", "", request)
		var rpc struct {
			Result struct {
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &rpc) != nil || !rpc.Result.IsError {
			t.Fatalf("invalid selector accepted: %s", body)
		}
	}
}
