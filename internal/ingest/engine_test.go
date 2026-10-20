package ingest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

type fakeConnector struct {
	desc        connector.Descriptor
	fetchFn     func(context.Context, connector.Query) (connector.Page, error)
	normalizeFn func(json.RawMessage) (model.Alert, error)
}

func (f *fakeConnector) Info() connector.Descriptor  { return f.desc }
func (f *fakeConnector) Check(context.Context) error { return nil }
func (f *fakeConnector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	return f.fetchFn(ctx, q)
}

func (f *fakeConnector) Normalize(raw json.RawMessage) (model.Alert, error) {
	if f.normalizeFn != nil {
		return f.normalizeFn(raw)
	}
	var p struct {
		ID       string `json:"id"`
		Title    string `json:"title"`
		Severity int    `json:"severity"`
		Time     int64  `json:"time"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return model.Alert{}, err
	}
	a := model.Alert{
		ExternalID: p.ID,
		Title:      p.Title,
		Severity:   model.Severity(p.Severity),
		Raw:        append(json.RawMessage(nil), raw...),
	}
	if p.Time > 0 {
		a.EventTime = time.UnixMilli(p.Time).UTC()
	}
	return a, nil
}

func rawAlert(t *testing.T, id, title string, severity int, ts time.Time) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"id": id, "title": title, "severity": severity, "time": ts.UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixture(t *testing.T) (*store.SQLite, *secret.Cipher, *connector.Registry, *model.Account, *fakeConnector) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "engine.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cipher, err := secret.Load(key, "")
	if err != nil {
		t.Fatal(err)
	}

	desc := connector.Descriptor{
		ID:            "fake",
		Name:          "Fake Cloud",
		Vendor:        "Fake Cloud",
		Product:       "Fake SIEM",
		ProductUID:    "fake.siem",
		MapperVersion: "fake/v1",
	}
	fake := &fakeConnector{desc: desc}
	reg := connector.NewRegistry()
	if err := reg.Register(desc, func(connector.AccountConfig) (connector.Connector, error) {
		return fake, nil
	}); err != nil {
		t.Fatal(err)
	}

	credRaw, _ := json.Marshal(connector.Credential{AccessKeyID: "ak", AccessKeySecret: "sk"})
	enc, err := cipher.Encrypt(string(credRaw))
	if err != nil {
		t.Fatal(err)
	}
	acct := &model.Account{Name: "fake-prod", Provider: "fake", Enabled: true, CredentialEncrypted: enc, CredentialSet: true}
	if err := st.CreateAccount(context.Background(), acct); err != nil {
		t.Fatal(err)
	}
	return st, cipher, reg, acct, fake
}

func TestSyncAccountDedupesAndAdvancesCursor(t *testing.T) {
	st, cipher, reg, acct, fake := fixture(t)
	eng := New(st, reg, cipher, Options{
		Enabled: true, Interval: time.Hour, InitialLookback: 24 * time.Hour,
		Overlap: 10 * time.Minute, MaxWindow: 24 * time.Hour, MaxPages: 10, PageSize: 100, Workers: 1,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	fixed := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	eng.now = func() time.Time { return fixed }

	eventTime := fixed.Add(-2 * time.Hour)
	raws := []json.RawMessage{
		rawAlert(t, "a-1", "Reverse shell", 5, eventTime),
		rawAlert(t, "a-2", "Port scan", 3, eventTime.Add(-time.Minute)),
		rawAlert(t, "a-3", "Brute force", 4, eventTime.Add(-2*time.Minute)),
	}
	fake.fetchFn = func(_ context.Context, q connector.Query) (connector.Page, error) {
		if q.Token == "" {
			return connector.Page{Records: []connector.RawAlert{{Raw: raws[0]}, {Raw: raws[1]}}, NextToken: "2", Total: 3}, nil
		}
		return connector.Page{Records: []connector.RawAlert{{Raw: raws[2]}}, Total: 3}, nil
	}

	run, err := eng.SyncAccount(context.Background(), *acct, "test")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if run.Status != "success" || run.Fetched != 3 || run.Created != 3 || run.Updated != 0 || run.Pages != 2 {
		t.Fatalf("run = %+v", run)
	}

	state, err := st.GetSyncState(context.Background(), acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !state.CursorEnd.Equal(fixed) {
		t.Fatalf("cursor = %s, want %s", state.CursorEnd, fixed)
	}
	if state.LastSuccessAt == nil || state.ConsecutiveFailures != 0 {
		t.Fatalf("state = %+v", state)
	}

	_, total, err := st.ListAlerts(context.Background(), model.AlertFilter{Limit: 10})
	if err != nil || total != 3 {
		t.Fatalf("alerts total = %d, %v", total, err)
	}

	// A second run inside the overlap window must update, not duplicate.
	eng.now = func() time.Time { return fixed.Add(5 * time.Minute) }
	run2, err := eng.SyncAccount(context.Background(), *acct, "test")
	if err != nil {
		t.Fatal(err)
	}
	if run2.Created != 0 || run2.Updated != 3 || run2.Fetched != 3 {
		t.Fatalf("second run = %+v", run2)
	}
	_, total, _ = st.ListAlerts(context.Background(), model.AlertFilter{Limit: 10})
	if total != 3 {
		t.Fatalf("dedupe failed, total = %d", total)
	}

	// Failures must not advance the cursor.
	fake.fetchFn = func(context.Context, connector.Query) (connector.Page, error) {
		return connector.Page{}, &connector.Error{Provider: "fake", Kind: connector.KindPermanent, Message: "boom"}
	}
	eng.now = func() time.Time { return fixed.Add(10 * time.Minute) }
	run3, err := eng.SyncAccount(context.Background(), *acct, "test")
	if err == nil {
		t.Fatal("expected failure")
	}
	if run3 == nil || run3.Status != "failed" {
		t.Fatalf("failed run = %+v", run3)
	}
	state, _ = st.GetSyncState(context.Background(), acct.ID)
	if !state.CursorEnd.Equal(fixed.Add(5 * time.Minute)) {
		t.Fatalf("cursor moved on failure: %s", state.CursorEnd)
	}
	if state.ConsecutiveFailures != 1 || state.LastError == "" {
		t.Fatalf("state after failure = %+v", state)
	}
}

func TestRecordFailurePersistsRawAndResumes(t *testing.T) {
	st, cipher, reg, acct, fake := fixture(t)
	eng := New(st, reg, cipher, Options{
		Enabled: true, Interval: time.Hour, InitialLookback: time.Hour,
		Overlap: time.Minute, MaxWindow: time.Hour, MaxPages: 10, PageSize: 100, Workers: 1,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	fixed := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	eng.now = func() time.Time { return fixed }

	good := rawAlert(t, "good-1", "good", 3, fixed.Add(-time.Minute))
	bad := rawAlert(t, "bad-1", "bad", 4, fixed.Add(-2*time.Minute))
	var tokens []string
	fake.fetchFn = func(_ context.Context, q connector.Query) (connector.Page, error) {
		tokens = append(tokens, q.Token)
		if q.Token == "" {
			return connector.Page{
				Records:   []connector.RawAlert{{Raw: good}, {Raw: bad}},
				NextToken: "2",
				Total:     2,
			}, nil
		}
		return connector.Page{Total: 2}, nil
	}
	fake.normalizeFn = func(raw json.RawMessage) (model.Alert, error) {
		var p struct {
			ID       string `json:"id"`
			Title    string `json:"title"`
			Severity int    `json:"severity"`
			Time     int64  `json:"time"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return model.Alert{}, err
		}
		if p.ID == "bad-1" {
			return model.Alert{}, errors.New("bad record")
		}
		return model.Alert{
			ExternalID: p.ID,
			Title:      p.Title,
			Severity:   model.Severity(p.Severity),
			EventTime:  time.UnixMilli(p.Time).UTC(),
			Raw:        append(json.RawMessage(nil), raw...),
		}, nil
	}

	run, err := eng.SyncAccount(context.Background(), *acct, "test")
	if err == nil || run == nil || run.Status != "failed" || run.Failed != 1 {
		t.Fatalf("expected record failure, run=%+v err=%v", run, err)
	}
	state, err := st.GetSyncState(context.Background(), acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !state.CursorEnd.IsZero() {
		t.Fatalf("cursor advanced over failed record: %s", state.CursorEnd)
	}
	if state.PendingToken != "2" || len(state.PendingRecords) != 1 || string(state.PendingRecords[0]) != string(bad) {
		t.Fatalf("pending state = %+v", state)
	}
	_, total, _ := st.ListAlerts(context.Background(), model.AlertFilter{Limit: 10})
	if total != 1 {
		t.Fatalf("successful record not stored, total=%d", total)
	}

	fake.normalizeFn = nil
	eng.now = func() time.Time { return fixed.Add(5 * time.Minute) }
	run2, err := eng.SyncAccount(context.Background(), *acct, "test")
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if run2.Status != "success" || run2.Created != 1 {
		t.Fatalf("resume run = %+v", run2)
	}
	state, _ = st.GetSyncState(context.Background(), acct.ID)
	if len(state.PendingRecords) != 0 || state.PendingToken != "" || !state.CursorEnd.Equal(fixed) {
		t.Fatalf("state after retry = %+v", state)
	}
	if len(tokens) != 2 || tokens[0] != "" || tokens[1] != "2" {
		t.Fatalf("unexpected fetch sequence: %v", tokens)
	}
	_, total, _ = st.ListAlerts(context.Background(), model.AlertFilter{Limit: 10})
	if total != 2 {
		t.Fatalf("total after retry = %d", total)
	}
}

func TestRecordFailureOnLastPageResumesWithoutRefetch(t *testing.T) {
	st, cipher, reg, acct, fake := fixture(t)
	eng := New(st, reg, cipher, Options{
		Enabled: true, Interval: time.Hour, InitialLookback: time.Hour,
		Overlap: time.Minute, MaxWindow: time.Hour, MaxPages: 10, PageSize: 100, Workers: 1,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	fixed := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	eng.now = func() time.Time { return fixed }

	fake.fetchFn = func(context.Context, connector.Query) (connector.Page, error) {
		return connector.Page{Records: []connector.RawAlert{{Raw: rawAlert(t, "bad-last", "bad", 3, fixed.Add(-time.Minute))}}, Total: 1}, nil
	}
	fake.normalizeFn = func(json.RawMessage) (model.Alert, error) { return model.Alert{}, errors.New("bad record") }
	if _, err := eng.SyncAccount(context.Background(), *acct, "test"); err == nil {
		t.Fatal("expected failure")
	}
	state, _ := st.GetSyncState(context.Background(), acct.ID)
	if state.PendingToken != "" || len(state.PendingRecords) != 1 {
		t.Fatalf("pending state = %+v", state)
	}

	fake.normalizeFn = nil
	fetches := 0
	fake.fetchFn = func(context.Context, connector.Query) (connector.Page, error) {
		fetches++
		return connector.Page{}, errors.New("must not refetch a completed last page")
	}
	run, err := eng.SyncAccount(context.Background(), *acct, "test")
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if run.Status != "success" || fetches != 0 {
		t.Fatalf("run=%+v fetches=%d", run, fetches)
	}
	state, _ = st.GetSyncState(context.Background(), acct.ID)
	if !state.CursorEnd.Equal(fixed) || len(state.PendingRecords) != 0 {
		t.Fatalf("state after retry = %+v", state)
	}
}

func TestSyncResumesFromPendingToken(t *testing.T) {
	st, cipher, reg, acct, fake := fixture(t)
	eng := New(st, reg, cipher, Options{
		Enabled: true, Interval: time.Hour, InitialLookback: time.Hour,
		Overlap: time.Minute, MaxWindow: time.Hour, MaxPages: 10, PageSize: 100, Workers: 1,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	fixed := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	eng.now = func() time.Time { return fixed }

	failSecondPage := true
	var tokens []string
	fake.fetchFn = func(_ context.Context, q connector.Query) (connector.Page, error) {
		tokens = append(tokens, q.Token)
		switch q.Token {
		case "":
			return connector.Page{
				Records:   []connector.RawAlert{{Raw: rawAlert(t, "p-1", "page one", 3, fixed.Add(-time.Minute))}},
				NextToken: "2",
				Total:     2,
			}, nil
		case "2":
			if failSecondPage {
				return connector.Page{}, &connector.Error{Provider: "fake", Kind: connector.KindPermanent, Message: "throttled after page 1"}
			}
			return connector.Page{
				Records: []connector.RawAlert{{Raw: rawAlert(t, "p-2", "page two", 4, fixed.Add(-2*time.Minute))}},
				Total:   2,
			}, nil
		default:
			return connector.Page{}, errors.New("unexpected token " + q.Token)
		}
	}

	run, err := eng.SyncAccount(context.Background(), *acct, "test")
	if err == nil || run.Status != "failed" {
		t.Fatalf("expected failure, run=%+v err=%v", run, err)
	}
	state, err := st.GetSyncState(context.Background(), acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.PendingToken != "2" || !state.CursorEnd.IsZero() {
		t.Fatalf("pending state not saved: %+v", state)
	}
	_, total, _ := st.ListAlerts(context.Background(), model.AlertFilter{Limit: 10})
	if total != 1 {
		t.Fatalf("first page not stored, total=%d", total)
	}

	failSecondPage = false
	eng.now = func() time.Time { return fixed.Add(time.Minute) }
	run2, err := eng.SyncAccount(context.Background(), *acct, "test")
	if err != nil {
		t.Fatalf("resume failed: %v", err)
	}
	if run2.Created != 1 || run2.Pages != 1 {
		t.Fatalf("resume run = %+v", run2)
	}
	if len(tokens) != 3 || tokens[0] != "" || tokens[1] != "2" || tokens[2] != "2" {
		t.Fatalf("unexpected fetch sequence: %v", tokens)
	}
	state, _ = st.GetSyncState(context.Background(), acct.ID)
	if state.PendingToken != "" || !state.CursorEnd.Equal(fixed) {
		t.Fatalf("state after resume = %+v", state)
	}
	_, total, _ = st.ListAlerts(context.Background(), model.AlertFilter{Limit: 10})
	if total != 2 {
		t.Fatalf("total after resume = %d", total)
	}
}

func TestSyncAccountPageLimit(t *testing.T) {
	st, cipher, reg, acct, fake := fixture(t)
	eng := New(st, reg, cipher, Options{
		Enabled: true, Interval: time.Hour, InitialLookback: time.Hour,
		Overlap: time.Minute, MaxWindow: time.Hour, MaxPages: 1, PageSize: 100, Workers: 1,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	eng.now = func() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) }

	fake.fetchFn = func(context.Context, connector.Query) (connector.Page, error) {
		return connector.Page{
			Records:   []connector.RawAlert{{Raw: rawAlert(t, "a-1", "x", 1, time.Now())}},
			NextToken: "next",
			Total:     100,
		}, nil
	}
	run, err := eng.SyncAccount(context.Background(), *acct, "test")
	if err != nil {
		t.Fatalf("page budget should pause, not fail: %v", err)
	}
	if run == nil || run.Status != "partial" {
		t.Fatalf("run = %+v", run)
	}
	state, _ := st.GetSyncState(context.Background(), acct.ID)
	if !state.CursorEnd.IsZero() {
		t.Fatalf("cursor advanced: %s", state.CursorEnd)
	}
	if state.PendingToken != "next" {
		t.Fatalf("pending token = %q", state.PendingToken)
	}
}
