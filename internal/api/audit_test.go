package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/api"
	"github.com/BaiLi-Labs/GuiLiu/internal/config"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func TestAuditRESTAndMCPAttributeKeysAndKeepQueryEvidenceReferences(t *testing.T) {
	ts, st, svc := setup(t, false)
	client := newClient(t, ts)
	ctx := context.Background()
	user, err := svc.CreateUser(ctx, "audit-admin", "synthetic-audit-password", "admin")
	if err != nil {
		t.Fatal(err)
	}
	key, meta, err := svc.CreateAPIKey(ctx, user.ID, "agent-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	finding := &model.AlertRecord{Provider: "tencent", AccountID: "cloud", Alert: model.Alert{ExternalID: "a", Title: "source title", SourceIP: "203.0.113.9", EventTime: time.Now(), Raw: json.RawMessage(`{"private":"SOURCE_EVIDENCE_SECRET"}`)}}
	if _, err := st.UpsertAlert(ctx, finding); err != nil {
		t.Fatal(err)
	}
	response, body := do(t, client, "GET", ts.URL+"/api/v1/alerts?provider=tencent&ip=203.0.113.9&limit=1", key, "")
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, string(body))
	}
	rows, err := st.ListAuditEvents(ctx, model.AuditFilter{RequestID: response.Header.Get("X-Request-ID"), Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	e := rows[0]
	if e.APIKeyID != meta.ID || e.APIKeyName != "agent-a" || e.UserID != user.ID || e.AuthType != "api_key" || e.Outcome != "success" || e.ResponseBytes == 0 || e.Operation != "GET /alerts" {
		t.Fatal("identity/result missing", e)
	}
	if e.EffectiveQuery["end"] == nil || e.EffectiveQuery["snapshot_sequence"] != float64(finding.Sequence) {
		t.Fatal("resolved query omitted", e.EffectiveQuery)
	}
	refs := e.Summary["alerts"].(map[string]any)["references"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["id"] != finding.ID || refs[0].(map[string]any)["revision"] != float64(1) {
		t.Fatal("returned evidence reference missing", refs)
	}
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_alert","arguments":{"alert_id":"` + finding.ID + `"}}}`
	response, body = do(t, client, "POST", ts.URL+"/mcp", key, request)
	if response.StatusCode != 200 || !strings.Contains(string(body), "SOURCE_EVIDENCE_SECRET") {
		t.Fatal("evidence unavailable", string(body))
	}
	rows, err = st.ListAuditEvents(ctx, model.AuditFilter{RequestID: response.Header.Get("X-Request-ID"), Limit: 10})
	if err != nil || len(rows) != 2 {
		t.Fatal("MCP/HTTP trace not linked", rows, err)
	}
	var tool, transport model.AuditEvent
	for _, r := range rows {
		if r.Tool != "" {
			tool = r
		} else {
			transport = r
		}
	}
	if tool.ParentSequence != transport.Sequence || tool.APIKeyID != meta.ID || tool.Outcome != "success" || tool.Tool != "get_alert" || tool.Summary["alert"].(map[string]any)["id"] != finding.ID {
		t.Fatal("MCP trace incomplete", rows)
	}
	raw, _ := json.Marshal(rows)
	for _, secret := range []string{key, "SOURCE_EVIDENCE_SECRET", "synthetic-audit-password"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("secret entered audit")
		}
	}
	response, body = do(t, client, "POST", ts.URL+"/mcp", key, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_alert","arguments":{"alert_id":"missing"}}}`)
	if response.StatusCode != 200 || !strings.Contains(string(body), `"isError":true`) {
		t.Fatal(string(body))
	}
	rows, _ = st.ListAuditEvents(ctx, model.AuditFilter{RequestID: response.Header.Get("X-Request-ID"), Tool: "get_alert", Limit: 10})
	if len(rows) != 1 || rows[0].Outcome != "error" || rows[0].ErrorCode != "tool_error" {
		t.Fatal("HTTP 200 hid tool failure", rows)
	}
}

func TestAuditAccessControlLoginAndMutationBodyRedaction(t *testing.T) {
	ts, st, svc := setup(t, false)
	client := newClient(t, ts)
	ctx := context.Background()
	user, err := svc.CreateUser(ctx, "audit-viewer", "synthetic-audit-password", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := svc.CreateAPIKey(ctx, user.ID, "agent-viewer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", key} {
		response, _ := do(t, client, "GET", ts.URL+"/api/v1/audit-events", token, "")
		if response.StatusCode != 401 && response.StatusCode != 403 {
			t.Fatal("audit read exposed", response.StatusCode)
		}
	}
	response, _ := do(t, client, "POST", ts.URL+"/api/v1/auth/login", "", `{"username":"audit-viewer","password":"WRONG_PRIVATE_PASSWORD"}`)
	rows, _ := st.ListAuditEvents(ctx, model.AuditFilter{RequestID: response.Header.Get("X-Request-ID"), Limit: 10})
	if len(rows) != 1 || rows[0].Outcome != "denied" || rows[0].Parameters["username"] != "audit-viewer" || rows[0].AuthType != "anonymous" {
		t.Fatal("login attempt missing", rows)
	}
	admin, err := svc.CreateUser(ctx, "audit-owner", "synthetic-audit-password", "admin")
	if err != nil {
		t.Fatal(err)
	}
	adminKey, _, err := svc.CreateAPIKey(ctx, admin.ID, "admin-agent", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	response, body := do(t, client, "POST", ts.URL+"/api/v1/auth/keys", adminKey, `{"name":"new-agent","expires_in_days":1}`)
	if response.StatusCode != 201 {
		t.Fatal(string(body))
	}
	var created struct {
		Key    string       `json:"key"`
		APIKey model.APIKey `json:"api_key"`
	}
	if json.Unmarshal(body, &created) != nil {
		t.Fatal(string(body))
	}
	rows, _ = st.ListAuditEvents(ctx, model.AuditFilter{RequestID: response.Header.Get("X-Request-ID"), Limit: 10})
	raw, _ := json.Marshal(rows)
	if len(rows) != 1 || strings.Contains(string(raw), created.Key) || rows[0].Summary["api_key"].(map[string]any)["id"] != created.APIKey.ID {
		t.Fatal("key issuance not safely traceable", string(raw))
	}
	do(t, client, "GET", ts.URL+"/api/v1/auth/me", adminKey, "")
	response, body = do(t, client, "GET", ts.URL+"/api/v1/audit-events?limit=1&username=audit-owner", adminKey, "")
	if response.StatusCode != 200 || !strings.Contains(string(body), `"has_more":true`) {
		t.Fatal("audit page/filter", string(body))
	}
	for _, suffix := range []string{"?limit=0", "?before_sequence=-1", "?start=bad", "?outcome=x&outcome=y", "?password=anything"} {
		response, _ = do(t, client, "GET", ts.URL+"/api/v1/audit-events"+suffix, adminKey, "")
		if response.StatusCode != 400 {
			t.Fatal("invalid audit query", suffix, response.StatusCode)
		}
	}
}

type noAuditStore struct{ store.Store }

func (s noAuditStore) StartAuditEvent(context.Context, *model.AuditEvent) error {
	return errors.New("PRIVATE_STORAGE_ERROR")
}

type noAuditIdentityStore struct{ store.Store }

func (s noAuditIdentityStore) IdentifyAuditEvent(context.Context, *model.AuditEvent) error {
	return errors.New("PRIVATE_STORAGE_ERROR")
}
func TestAuditUnavailableRejectsRequestBeforeHandler(t *testing.T) {
	_, st, svc := setup(t, true)
	for _, storage := range []store.Store{noAuditStore{st}, noAuditIdentityStore{st}} {
		server := api.New(&config.Config{}, storage, nil, nil, nil, nil, svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/v1/alerts", nil)
		server.Handler().ServeHTTP(w, r)
		if w.Code != 503 || !strings.Contains(w.Body.String(), "audit_unavailable") || strings.Contains(w.Body.String(), "PRIVATE_STORAGE_ERROR") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func TestAuditUsesServerRequestIDAndDirectPeerOnly(t *testing.T) {
	ts, st, _ := setup(t, true)
	r := httptest.NewRequest("GET", "/api/v1/meta?token=PRIVATE_TOKEN&q=PRIVATE_KEYWORD", nil)
	r.RemoteAddr = "198.51.100.8:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	r.Header.Set("X-Request-ID", "forged-request-id")
	r.Header.Set("Authorization", "Bearer PRIVATE_AUTH_HEADER")
	w := httptest.NewRecorder()
	ts.handler.ServeHTTP(w, r)
	rows, err := st.ListAuditEvents(context.Background(), model.AuditFilter{RequestID: w.Header().Get("X-Request-ID"), Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].RequestID == "forged-request-id" || rows[0].PeerIP != "198.51.100.8" {
		t.Fatal("caller forged trace identity", rows, err)
	}
	raw, _ := json.Marshal(rows)
	for _, secret := range []string{"PRIVATE_TOKEN", "PRIVATE_KEYWORD", "PRIVATE_AUTH_HEADER", "203.0.113.9"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("untrusted headers or free text retained", string(raw))
		}
	}
}
