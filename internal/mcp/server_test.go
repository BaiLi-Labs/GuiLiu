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
)

func newTestServer(t *testing.T) (*Server, *model.AlertRecord) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "mcp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	now := time.Date(2026, 10, 20, 6, 0, 0, 0, time.UTC)
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
	if len(tools) != 8 {
		t.Fatalf("tools = %d", len(tools))
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
