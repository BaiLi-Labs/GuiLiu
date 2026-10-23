package intake

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/ingest"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

type fakePusher struct{}

func (fakePusher) Info() connector.Descriptor {
	return connector.Descriptor{
		ID: "fake-push", Name: "Fake Push", Vendor: "Fake", Product: "Fake Sensor",
		ProductUID: "fake.sensor", APIVersion: "v1", MapperVersion: "fake/v1",
		PushFormats: []connector.PushFormat{connector.PushWebhook, connector.PushSyslog},
		PushOnly:    true,
	}
}

func (fakePusher) Check(context.Context) error { return nil }

func (fakePusher) Fetch(context.Context, connector.Query) (connector.Page, error) {
	return connector.Page{}, connector.ConfigError("fake-push", "push only")
}

func (fakePusher) DecodePush(req connector.PushRequest) ([]connector.RawAlert, error) {
	return []connector.RawAlert{{Raw: req.Body}}, nil
}

func (fakePusher) Normalize(raw json.RawMessage) (model.Alert, error) {
	var v struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return model.Alert{}, err
	}
	return model.Alert{ExternalID: v.ID, Title: v.Title, Severity: model.SeverityHigh}, nil
}

func newTestServer(t *testing.T) (*Server, store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "intake.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cipher, err := secret.Load(key, "")
	if err != nil {
		t.Fatal(err)
	}
	reg := connector.NewRegistry()
	if err := reg.Register(fakePusher{}.Info(), func(connector.AccountConfig) (connector.Connector, error) {
		return fakePusher{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	engine := ingest.New(st, reg, cipher, ingest.Options{Enabled: false}, logger)
	return New(st, engine, reg, cipher, Options{}, logger), st
}

func createAccount(t *testing.T, st store.Store, name, token string) *model.Account {
	t.Helper()
	account := &model.Account{
		Name:     name,
		Provider: "fake-push",
		Enabled:  true,
		Options:  map[string]string{},
	}
	if token != "" {
		account.Options["push_token_sha256"] = HashToken(token)
	}
	if err := st.CreateAccount(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	return account
}

func post(t *testing.T, s *Server, account, token, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ingest/"+account, strings.NewReader(body))
	req.SetPathValue("account", account)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Webhook(rec, req)
	var decoded map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
	return rec, decoded
}

func TestWebhookRequiresAccountToken(t *testing.T) {
	s, st := newTestServer(t)
	createAccount(t, st, "sensor", "s3cret")

	if rec, _ := post(t, s, "sensor", "", `{"id":"a"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d", rec.Code)
	}
	if rec, _ := post(t, s, "sensor", "wrong", `{"id":"a"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d", rec.Code)
	}
	if rec, _ := post(t, s, "missing", "s3cret", `{"id":"a"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown account status = %d", rec.Code)
	}
	if rec, _ := post(t, s, "sensor", "s3cret", `{"id":"a","title":"first"}`); rec.Code != http.StatusOK {
		t.Fatalf("valid token status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWebhookAccountWithoutTokenIsRejected(t *testing.T) {
	s, st := newTestServer(t)
	createAccount(t, st, "unconfigured", "")
	if rec, _ := post(t, s, "unconfigured", "anything", `{"id":"a"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestWebhookIsIdempotentAndTracksChanges(t *testing.T) {
	s, st := newTestServer(t)
	createAccount(t, st, "sensor", "s3cret")

	_, first := post(t, s, "sensor", "s3cret", `{"id":"evt-1","title":"first"}`)
	if first["created"] != float64(1) || first["updated"] != float64(0) {
		t.Fatalf("first delivery = %v", first)
	}

	// A retried delivery must not create a second row.
	rec, second := post(t, s, "sensor", "s3cret", `{"id":"evt-1","title":"first"}`)
	if rec.Code != http.StatusOK || second["created"] != float64(0) || second["updated"] != float64(0) {
		t.Fatalf("duplicate delivery = %d %v", rec.Code, second)
	}

	// A real change updates the existing alert instead of duplicating it.
	_, third := post(t, s, "sensor", "s3cret", `{"id":"evt-1","title":"changed"}`)
	if third["created"] != float64(0) || third["updated"] != float64(1) {
		t.Fatalf("changed delivery = %v", third)
	}

	alerts, total, err := st.ListAlerts(context.Background(), model.AlertFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(alerts) != 1 {
		t.Fatalf("stored alerts = %d", total)
	}
	if alerts[0].Title != "changed" {
		t.Fatalf("title = %q", alerts[0].Title)
	}
	// One create plus one real change: the retried delivery added no revision.
	if alerts[0].Revision != 2 {
		t.Fatalf("revision = %d", alerts[0].Revision)
	}
}

func TestWebhookRejectsOversizedPayload(t *testing.T) {
	s, st := newTestServer(t)
	s.opts.MaxBodyBytes = 16
	createAccount(t, st, "sensor", "s3cret")
	rec, _ := post(t, s, "sensor", "s3cret", `{"id":"a","title":"`+strings.Repeat("x", 64)+`"}`)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestWebhookMarksPushHealth(t *testing.T) {
	s, st := newTestServer(t)
	acct := createAccount(t, st, "sensor", "s3cret")
	if _, err := st.GetSyncState(context.Background(), acct.ID); err != nil {
		t.Fatal(err)
	}
	post(t, s, "sensor", "s3cret", `{"id":"evt-1","title":"first"}`)
	state, err := st.GetSyncState(context.Background(), acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastSuccessAt == nil {
		t.Fatal("push ingest must record freshness")
	}
	if !state.CursorEnd.IsZero() {
		t.Fatal("push ingest must not invent a polling cursor")
	}
	if got := state.Health(time.Now().UTC(), time.Hour); got != "healthy" {
		t.Fatalf("health = %s", got)
	}
}
