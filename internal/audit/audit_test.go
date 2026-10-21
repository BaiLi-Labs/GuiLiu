package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/auth"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func TestAuditValuesExcludeCredentialsEvidenceAndBoundResults(t *testing.T) {
	params := Parameters(map[string]any{"provider": "tencent", "ip": "203.0.113.9", "keyword": "SECRET_SEARCH_TEXT", "q": "password=SECRET_PASSWORD", "resource_id": "glk_SYNTHETIC_PRIVATE_TOKEN", "access_key_secret": "CLOUD_SECRET", "password": "PASSWORD_SECRET", "group_key": map[string]string{"title": "PRIVATE_TITLE"}, "limit": 200})
	raw, _ := json.Marshal(params)
	for _, secret := range []string{"SECRET_SEARCH_TEXT", "SECRET_PASSWORD", "SYNTHETIC_PRIVATE_TOKEN", "CLOUD_SECRET", "PASSWORD_SECRET", "PRIVATE_TITLE"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("parameter leaked", secret)
		}
	}
	if params["ip"] != "203.0.113.9" || params["keyword"].(map[string]any)["redacted"] != true {
		t.Fatal(params)
	}
	items := []map[string]any{}
	for i := 0; i < 201; i++ {
		items = append(items, map[string]any{"id": "finding", "revision": 2, "raw_hash": strings.Repeat("a", 64), "raw": "PRIVATE_SOURCE_EVIDENCE", "token": "RAW_TOKEN"})
	}
	summary := Summary(map[string]any{"alerts": items, "total": 201, "token": "SESSION_SECRET", "api_key": map[string]any{"id": "key-id", "key_hash": "KEY_HASH_SECRET", "prefix": "glk_SECRET"}})
	refs := summary["alerts"].(map[string]any)
	if refs["returned_count"] != 201 || refs["truncated"] != true || len(refs["references"].([]map[string]any)) != 200 {
		t.Fatal("result cap", summary)
	}
	raw, _ = json.Marshal(summary)
	for _, secret := range []string{"PRIVATE_SOURCE_EVIDENCE", "RAW_TOKEN", "SESSION_SECRET", "KEY_HASH_SECRET", "glk_SECRET"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("summary leaked", secret)
		}
	}
	if summary["api_key"].(map[string]any)["id"] != "key-id" {
		t.Fatal("new key target missing")
	}
}

type failingAudit struct {
	store.Store
	start, finish bool
}

func (s failingAudit) StartAuditEvent(ctx context.Context, e *model.AuditEvent) error {
	if s.start {
		return errors.New("PRIVATE_STORAGE_ERROR")
	}
	return s.Store.StartAuditEvent(ctx, e)
}
func (s failingAudit) FinishAuditEvent(ctx context.Context, e *model.AuditEvent) error {
	if s.finish {
		return errors.New("PRIVATE_STORAGE_ERROR")
	}
	return s.Store.FinishAuditEvent(ctx, e)
}

func TestAuditDurableStartSurvivesFailedCompletionAndCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&log, nil))
	ctx, cancel := context.WithCancel(context.Background())
	p := &auth.Principal{User: model.User{ID: "u", Username: "operator", Role: "admin"}, Kind: "api_key", TokenHash: "PRIVATE_TOKEN_HASH", APIKeyID: "k", APIKeyName: "agent-a"}
	ctx = auth.WithPrincipal(ctx, p)
	_, span, err := Begin(ctx, failingAudit{Store: st, finish: true}, logger, model.AuditEvent{Surface: "rest", Operation: "GET /alerts"})
	if err != nil {
		t.Fatal(err)
	}
	FindingQuery(context.WithValue(ctx, spanKey{}, span), model.AlertFilter{Provider: "tencent", Limit: 20})
	cancel()
	span.Finish(ctx, "cancelled", "request_cancelled")
	if strings.Contains(log.String(), "PRIVATE_STORAGE_ERROR") || strings.Contains(log.String(), "PRIVATE_TOKEN_HASH") {
		t.Fatal("runtime audit leaked credentials or raw error")
	}
	st.Close()
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rows, err := st.ListAuditEvents(context.Background(), model.AuditFilter{Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].Outcome != "in_progress" || rows[0].FinishedAt != nil || rows[0].APIKeyID != "k" {
		t.Fatal("lost initial attempt", rows, err)
	}
	if _, span, err := Begin(context.Background(), failingAudit{Store: st, start: true}, logger, model.AuditEvent{Surface: "rest", Operation: "GET /alerts"}); err == nil || span != nil {
		t.Fatal("audit start failure ignored")
	}
}

func TestAuditOrderingFiltersAndRetention(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		e := model.AuditEvent{RequestID: "request", StartedAt: time.Now().Add(-time.Duration(i) * 24 * time.Hour), Surface: "rest", Operation: "GET /alerts", Username: "operator", Outcome: "in_progress", Parameters: map[string]any{}, Summary: map[string]any{}}
		if err := st.StartAuditEvent(ctx, &e); err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		e.FinishedAt = &now
		e.Outcome = "success"
		if err := st.FinishAuditEvent(ctx, &e); err != nil {
			t.Fatal(err)
		}
		if err := st.FinishAuditEvent(ctx, &e); !errors.Is(err, store.ErrConflict) {
			t.Fatal("completed audit was rewritten")
		}
	}
	first, err := st.ListAuditEvents(ctx, model.AuditFilter{Limit: 2, Username: "operator"})
	if err != nil || len(first) != 2 || first[0].Sequence <= first[1].Sequence {
		t.Fatal(first, err)
	}
	next, err := st.ListAuditEvents(ctx, model.AuditFilter{Limit: 2, BeforeSequence: first[1].Sequence})
	if err != nil || len(next) != 2 || next[0].Sequence >= first[1].Sequence {
		t.Fatal(next, err)
	}
	wrong, err := st.ListAuditEvents(ctx, model.AuditFilter{Username: "' OR 1=1 --", Limit: 10})
	if err != nil || len(wrong) != 0 {
		t.Fatal("filter escaped", wrong, err)
	}
	n, err := st.PruneAuditEvents(ctx, time.Now().Add(-47*time.Hour))
	if err != nil || n != 3 {
		t.Fatal("retention", n, err)
	}
	seq, err := st.SnapshotSequence(ctx)
	if err != nil || seq != 0 {
		t.Fatal("audit changed Finding feed", seq, err)
	}
}
