package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func TestStdioAuditIncludesProtocolFailuresWithoutSourceBodies(t *testing.T) {
	srv, rec := newTestServer(t)
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_alert","arguments":{"alert_id":"` + rec.ID + `"}}}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"unknown","arguments":{"password":"PRIVATE_PASSWORD"}}}` + "\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + `malformed PRIVATE_PAYLOAD` + "\n"
	var out bytes.Buffer
	if err := srv.ServeStdio(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	rows, err := srv.store.ListAuditEvents(context.Background(), model.AuditFilter{Surface: "mcp_stdio", Limit: 10})
	if err != nil || len(rows) != 4 {
		t.Fatal(rows, err)
	}
	if rows[0].ErrorCode != "parse_error" || rows[1].Operation != "notifications/initialized" || rows[2].Outcome != "error" || rows[3].Tool != "get_alert" {
		t.Fatal("stdio audit omitted operations", rows)
	}
	for _, r := range rows {
		if r.AuthType != "local_process" || r.UserID != "" || r.FinishedAt == nil {
			t.Fatal("stdio claimed a remote authenticated identity", r)
		}
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "PRIVATE_PASSWORD") || strings.Contains(string(raw), "PRIVATE_PAYLOAD") || strings.Contains(string(raw), "class_uid") {
		t.Fatal("source/request body entered audit", string(raw))
	}
}

type deniedAuditStore struct{ store.Store }

func (s deniedAuditStore) StartAuditEvent(context.Context, *model.AuditEvent) error {
	return errors.New("PRIVATE_ERROR")
}
func TestToolDoesNotRunWithoutDurableAuditAndPanicIsRecorded(t *testing.T) {
	srv, _ := newTestServer(t)
	original := srv.store
	called := false
	srv.register(Tool{Name: "test_operation", Handler: func(context.Context, map[string]any) (any, error) { called = true; panic("PRIVATE_PANIC_VALUE") }})
	srv.store = deniedAuditStore{original}
	resp := call(t, srv, "tools/call", map[string]any{"name": "test_operation"})
	if called || resp.Error == nil || resp.Error.Code != codeInternalError {
		t.Fatal("unaudited operation ran", resp)
	}
	srv.store = original
	resp = call(t, srv, "tools/call", map[string]any{"name": "test_operation"})
	if !called || resp.Error == nil || strings.Contains(resp.Error.Message, "PRIVATE_PANIC_VALUE") {
		t.Fatal(resp)
	}
	rows, err := original.ListAuditEvents(context.Background(), model.AuditFilter{Tool: "test_operation", Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].Outcome != "error" || rows[0].ErrorCode != "panic" {
		t.Fatal("panic lost its audit", rows, err)
	}
}
