package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

func newTestServer(t *testing.T) (*Server, *model.AlertRecord) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	now := time.Now().UTC().Add(-time.Hour)
	rec := &model.AlertRecord{
		Provider:    "tencent",
		AccountID:   "acct-1",
		AccountName: "prod",
		AccountUID:  "123456",
		Alert: model.Alert{
			ExternalID:  "a-1",
			Title:       "Reverse shell",
			Severity:    model.SeverityCritical,
			EventTime:   now,
			FirstSeenAt: now,
			LastSeenAt:  now,
			SourceIP:    "203.0.113.9",
			Resource:    model.Resource{ID: "ins-1", Name: "web-01", Type: "host"},
			Observables: []model.Observable{{Name: "src_endpoint.ip", TypeID: 2, Value: "203.0.113.9"}},
			Evidences:   []model.Evidence{{Type: "tencent.csip", Data: map[string]any{"path": "/tmp/x"}}},
			Raw:         json.RawMessage(`{"ID":"a-1"}`),
			OCSF:        json.RawMessage(`{"class_uid":2004}`),
		},
		Status: model.StatusOpen,
	}
	if _, err := st.UpsertAlert(context.Background(), rec); err != nil {
		t.Fatal(err)
	}

	reg := connector.NewRegistry()
	_ = reg.Register(connector.Descriptor{ID: "tencent", Name: "Tencent Cloud", Product: "CSIP"}, func(connector.AccountConfig) (connector.Connector, error) {
		return nil, nil
	})
	return New(st, reg, slog.New(slog.NewTextHandler(io.Discard, nil))), rec
}

func call(t *testing.T, srv *Server, method string, params any) *Response {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handle(context.Background(), &Request{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  method,
		Params:  raw,
	})
}

func TestInitializeAndTools(t *testing.T) {
	srv, rec := newTestServer(t)

	resp := call(t, srv, "initialize", map[string]any{"protocolVersion": "2025-06-18"})
	if resp == nil || resp.Error != nil {
		t.Fatalf("initialize resp = %+v", resp)
	}
	result := resp.Result.(map[string]any)
	if result["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocol = %v", result["protocolVersion"])
	}

	resp = call(t, srv, "tools/list", map[string]any{})
	tools := resp.Result.(map[string]any)["tools"].([]map[string]any)
	if len(tools) != 20 {
		t.Fatalf("tools = %d", len(tools))
	}

	resp = call(t, srv, "tools/call", map[string]any{
		"name":      "list_alert_groups",
		"arguments": map[string]any{"group_by": "signature"},
	})
	groupPayload := resp.Result.(map[string]any)
	if groupPayload["isError"] != false {
		t.Fatalf("group tool error: %+v", groupPayload)
	}
	groupText := groupPayload["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(groupText, `"total": 1`) || !strings.Contains(groupText, `"group_by": "signature"`) {
		t.Fatalf("group result = %s", groupText)
	}
	resp = call(t, srv, "tools/call", map[string]any{
		"name": "get_alert_group",
		"arguments": map[string]any{
			"group_by":  "signature",
			"group_key": map[string]any{"singleton": rec.ID},
		},
	})
	groupMembers := resp.Result.(map[string]any)
	if groupMembers["isError"] != false {
		t.Fatalf("group members error: %+v", groupMembers)
	}
	groupMembersText := groupMembers["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(groupMembersText, `"total": 1`) {
		t.Fatalf("group members = %s", groupMembersText)
	}

	resp = call(t, srv, "tools/call", map[string]any{
		"name":      "list_alerts",
		"arguments": map[string]any{"severity": "critical"},
	})
	payload := resp.Result.(map[string]any)
	if payload["isError"] != false {
		t.Fatalf("tool error: %+v", payload)
	}
	text := payload["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(text, "Reverse shell") {
		t.Fatalf("result = %s", text)
	}

	resp = call(t, srv, "tools/call", map[string]any{
		"name":      "get_alert_evidence",
		"arguments": map[string]any{"alert_id": rec.ID},
	})
	text = resp.Result.(map[string]any)["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(text, "203.0.113.9") || !strings.Contains(text, "class_uid") {
		t.Fatalf("evidence = %s", text)
	}

	resp = call(t, srv, "tools/call", map[string]any{
		"name":      "search_alerts_by_ip",
		"arguments": map[string]any{"ip": "203.0.113.9"},
	})
	text = resp.Result.(map[string]any)["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(text, "Reverse shell") {
		t.Fatalf("ip search = %s", text)
	}

	resp = call(t, srv, "tools/call", map[string]any{
		"name":      "get_alert_statistics",
		"arguments": map[string]any{},
	})
	text = resp.Result.(map[string]any)["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(text, "by_severity") {
		t.Fatalf("stats = %s", text)
	}
}

func TestDefaultGroupsAndMemberTimeWindow(t *testing.T) {
	srv, rec := newTestServer(t)
	start := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second).Add(250 * time.Millisecond)
	end := start.Add(time.Hour)
	rec.Product, rec.AlertType, rec.Region, rec.SourceIP = "CWP", "MaliciousProcess", "region-1", ""
	for i, at := range []time.Time{start.Add(-time.Millisecond), start, end, end.Add(time.Millisecond)} {
		rec.ID = ""
		rec.ExternalID = []string{"a-1", "at-start", "at-end", "after-end"}[i]
		rec.EventTime, rec.FirstSeenAt, rec.LastSeenAt = at, at, at
		if _, err := srv.store.UpsertAlert(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
	}
	args := map[string]any{"start": start.Format(time.RFC3339Nano), "end": end.Format(time.RFC3339Nano)}
	result, err := srv.toolListAlertGroups(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	payload := result.(map[string]any)
	groups := payload["groups"].([]model.AlertGroup)
	window := payload["window"].(view.QueryWindow)
	if payload["total"] != 1 || payload["group_by"] != model.GroupByAsset || len(groups) != 1 || groups[0].FindingCount != 2 || window.Start != args["start"] || window.End != args["end"] {
		t.Fatalf("default groups=%+v", payload)
	}
	key := make(map[string]any, len(groups[0].Key))
	for k, v := range groups[0].Key {
		key[k] = v
	}
	args["asset_snapshot_sequence"] = *payload["asset_snapshot_sequence"].(*int64)
	args["group_by"], args["group_key"] = string(groups[0].GroupBy), key
	args["start"], args["end"] = window.Start, window.End
	result, err = srv.toolGetAlertGroup(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	members := result.(map[string]any)
	if members["total"] != 2 || members["window"] != window {
		t.Fatalf("expanded members=%+v", members)
	}
}

func TestStdioTransport(t *testing.T) {
	srv, _ := newTestServer(t)
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	}, "\n")
	var out bytes.Buffer
	if err := srv.ServeStdio(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("responses = %d: %s", len(lines), out.String())
	}
	var resp Response
	if err := json.Unmarshal([]byte(lines[1]), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error != nil {
		t.Fatalf("error = %+v", resp.Error)
	}
}

func TestQueryWindowsAndCoverage(t *testing.T) {
	for _, args := range []map[string]any{{}, {"end": "2026-10-21"}, {"since": "7d"}} {
		start, end, err := parseRange(args, 0)
		if err != nil || start == nil || end == nil || end.Sub(*start) != 7*24*time.Hour {
			t.Fatalf("args=%v start=%v end=%v err=%v", args, start, end, err)
		}
	}
	if _, _, err := parseRange(map[string]any{"since": "91d"}, 0); err == nil {
		t.Fatal("unbounded MCP query accepted")
	}
	srv, _ := newTestServer(t)
	acct := &model.Account{Name: "new-account", Provider: "tencent", Enabled: true}
	if err := srv.store.CreateAccount(context.Background(), acct); err != nil {
		t.Fatal(err)
	}
	health, err := srv.toolHealth(context.Background(), map[string]any{})
	if err != nil || health.(map[string]any)["status"] != "degraded" {
		t.Fatalf("health=%+v err=%v", health, err)
	}
	result, err := srv.toolListAlerts(context.Background(), map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	coverage := result.(map[string]any)["coverage"].(*model.Coverage)
	if coverage.Complete != false {
		t.Fatalf("coverage=%+v", coverage)
	}
}

func TestLargeSnapshotSequenceKeepsIntegerPrecision(t *testing.T) {
	for _, value := range []any{float64(1000000), "1000000", json.Number("1000000")} {
		got, err := parseInteger(value)
		if err != nil || got != 1000000 {
			t.Fatalf("sequence %v parsed as %d: %v", value, got, err)
		}
	}
	if _, err := parseInteger(float64(1.5)); err == nil {
		t.Fatal("fractional sequence accepted")
	}
}

func TestMCPRevisionHistoryMarksNonProjectedObservations(t *testing.T) {
	srv, a := newTestServer(t)
	ctx := context.Background()
	a.SourceUpdatedAt = time.Now().UTC()
	if _, err := srv.store.UpsertAlert(ctx, a); err != nil {
		t.Fatal(err)
	}
	old := *a
	old.Title, old.SourceUpdatedAt = "late older observation", a.SourceUpdatedAt.Add(-time.Hour)
	if _, err := srv.store.UpsertAlert(ctx, &old); err != nil {
		t.Fatal(err)
	}
	result, err := srv.tools["get_alert_revisions"].Handler(ctx, map[string]any{"alert_id": a.ID})
	if err != nil {
		t.Fatal(err)
	}
	items := result.(map[string]any)["revisions"].([]view.Revision)
	if len(items) < 2 || items[0].ProjectionUpdated || items[0].Record.ProjectionUpdated || items[0].Record.Title != old.Title {
		t.Fatalf("MCP history hid projection status: %+v", items)
	}
}
