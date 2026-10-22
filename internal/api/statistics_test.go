package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/cli"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestStatisticsFactsAreIdenticalAcrossRESTMCPAndCLI(t *testing.T) {
	ts, st, _ := setup(t, true)
	client := newClient(t, ts)
	live := httptest.NewServer(ts.handler)
	defer live.Close()
	id := createAccount(t, ts, client, "")
	a := seedAlert(t, st, id)
	a.SourceCountry = "Source-declared value"
	a.Raw = json.RawMessage(`{"synthetic":true}`)
	if _, err := st.UpsertAlert(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	seq, _ := st.SnapshotSequence(context.Background())
	start, end := a.EventTime.Add(-time.Hour).Format(time.RFC3339Nano), a.EventTime.Add(time.Hour).Format(time.RFC3339Nano)
	q := url.Values{"start": {start}, "end": {end}, "snapshot_sequence": {strconv.FormatInt(seq, 10)}, "top_by": {"title,source_ip,source_country,severity_day"}, "top_n": {"1"}}
	response, body := do(t, client, "GET", ts.URL+"/api/v1/stats?"+q.Encode(), "", "")
	var rest map[string]any
	if response.StatusCode != 200 || json.Unmarshal(body, &rest) != nil {
		t.Fatalf("REST: %s", body)
	}
	rows, err := st.ListAuditEvents(context.Background(), model.AuditFilter{RequestID: response.Header.Get("X-Request-ID"), Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].EffectiveQuery["top_by"] != q.Get("top_by") || rows[0].EffectiveQuery["top_n"] != float64(1) {
		t.Fatalf("stats audit omitted dimensions: %+v %v", rows, err)
	}
	// Updating the latest projection after pinning must not move any of the
	// counts or observed event bounds returned through the other surfaces.
	a.Title = "different current title"
	a.EventTime = a.EventTime.Add(24 * time.Hour)
	a.Raw = json.RawMessage(`{"changed":true}`)
	if _, err := st.UpsertAlert(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"start": start, "end": end, "snapshot_sequence": seq, "top_by": q.Get("top_by"), "top_n": 1}
	request, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "get_alert_statistics", "arguments": args}})
	_, rpcBody := do(t, client, "POST", ts.URL+"/mcp", "", string(request))
	var rpc struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if json.Unmarshal(rpcBody, &rpc) != nil || rpc.Result.IsError || len(rpc.Result.Content) != 1 {
		t.Fatalf("MCP: %s", rpcBody)
	}
	var mcp map[string]any
	if json.Unmarshal([]byte(rpc.Result.Content[0].Text), &mcp) != nil || !reflect.DeepEqual(rest, mcp) {
		t.Fatalf("different facts: %s\n%s", body, rpcBody)
	}
	var stdout, stderr bytes.Buffer
	t.Setenv("GUILIU_API_KEY", "")
	t.Setenv("GUILIU_API_KEY_FILE", "")
	code := cli.Run([]string{"--url", live.URL, "stats", "--start", start, "--end", end, "--snapshot-sequence", strconv.FormatInt(seq, 10), "--top-by", q.Get("top_by"), "--top-n", "1", "--json"}, &stdout, &stderr)
	var result map[string]any
	if code != 0 || json.Unmarshal(stdout.Bytes(), &result) != nil || !reflect.DeepEqual(rest, result) {
		t.Fatalf("CLI: %d %s %s", code, stdout.String(), stderr.String())
	}
	statistics := rest["statistics"].(map[string]any)
	if statistics["day_timezone"] != "UTC" || statistics["total"] != float64(1) {
		t.Fatal(statistics)
	}
	for _, bad := range []string{"top_n=0", "top_n=101", "top_n=1.5", "top_by=unknown", "top_by=title,,source_ip"} {
		response, body = do(t, client, "GET", ts.URL+"/api/v1/stats?"+bad, "", "")
		if response.StatusCode != 400 {
			t.Fatalf("accepted %s: %s", bad, body)
		}
	}
	response, body = do(t, client, "GET", ts.URL+"/api/v1/coverage?snapshot_sequence=999999", "", "")
	if response.StatusCode != 400 {
		t.Fatalf("future coverage snapshot accepted: %s", body)
	}
	// Coverage is collection metadata plus matching local facts, not a score.
	var coverage model.Coverage
	encoded, _ := json.Marshal(rest["coverage"])
	if json.Unmarshal(encoded, &coverage) != nil || coverage.SnapshotSequence == nil || *coverage.SnapshotSequence != seq || coverage.Accounts[0].ObservedEvents.FindingCount != 1 {
		t.Fatalf("coverage: %s", encoded)
	}
}
