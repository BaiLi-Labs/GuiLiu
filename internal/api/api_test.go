package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/api"
	"github.com/BaiLi-Labs/GuiLiu/internal/auth"
	"github.com/BaiLi-Labs/GuiLiu/internal/config"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/ingest"
	"github.com/BaiLi-Labs/GuiLiu/internal/mcp"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

// Handler-level HTTP tests need no listening socket and still exercise cookies,
// authentication, routing and JSON serialization through http.Client.
type testServer struct {
	URL     string
	handler http.Handler
}
type handlerTransport struct{ handler http.Handler }

func (tr handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	tr.handler.ServeHTTP(w, r)
	if r.Body != nil {
		_ = r.Body.Close()
	}
	resp := w.Result()
	resp.Request = r
	return resp, nil
}

func setup(t *testing.T, devMode bool) (*testServer, store.Store, *auth.Service) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
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
	fakeFactory := func(connector.AccountConfig) (connector.Connector, error) { return nil, nil }
	desc := connector.Descriptor{
		ID: "fake", Name: "Fake Cloud", Vendor: "Fake Cloud", Product: "Fake SIEM",
		ProductUID: "fake.siem", MapperVersion: "fake/v1",
		Credential: []connector.CredentialField{{Name: "access_key_id", Label: "AK", Required: true}},
	}
	if err := reg.Register(desc, fakeFactory); err != nil {
		t.Fatal(err)
	}
	descGCP := connector.Descriptor{
		ID: "fake-gcp", Name: "Fake GCP", Vendor: "Fake", Product: "Fake SCC",
		ProductUID: "fake.scc", MapperVersion: "fake/v1",
		Credential:   []connector.CredentialField{{Name: "service_account_json", Label: "SA JSON", Required: true, Multiline: true}},
		OptionFields: []connector.OptionField{{Name: "parent", Label: "Parent", Required: true}},
	}
	if err := reg.Register(descGCP, fakeFactory); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{Listen: ":0", Auth: config.AuthConfig{DevMode: devMode}}
	eng := ingest.New(st, reg, cipher, ingest.Options{Enabled: false}, logger)
	authSvc := auth.New(st, auth.Config{DevMode: devMode, SessionTTL: time.Hour, AdminUser: "admin"}, logger)
	mcpServer := mcp.New(st, reg, logger)
	server := api.New(cfg, st, eng, reg, cipher, mcpServer, authSvc, logger)
	ts := &testServer{URL: "http://guiliu.test", handler: server.Handler()}
	return ts, st, authSvc
}

func do(t *testing.T, client *http.Client, method, url, token, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

func newClient(t *testing.T, ts *testServer) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, Timeout: 5 * time.Second, Transport: handlerTransport{ts.handler}}
}

func createAccount(t *testing.T, ts *testServer, client *http.Client, token string) string {
	t.Helper()
	resp, body := do(t, client, http.MethodPost, ts.URL+"/api/v1/accounts", token,
		`{"name":"prod","provider":"fake","account_uid":"123456","access_key_id":"TEST_ONLY_ACCESS_KEY","access_key_secret":"test-only-secret"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create account = %d: %s", resp.StatusCode, body)
	}
	var acct struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &acct); err != nil {
		t.Fatal(err)
	}
	return acct.ID
}

func seedAlert(t *testing.T, st store.Store, accountID string) *model.AlertRecord {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rec := &model.AlertRecord{
		Provider:    "fake",
		AccountID:   accountID,
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
			Evidences:   []model.Evidence{{Type: "fake", Data: map[string]any{"path": "/tmp/mock"}}},
			Raw:         json.RawMessage(`{"ID":"a-1"}`),
			OCSF:        json.RawMessage(`{"class_uid":2004,"severity_id":5}`),
		},
		Status: model.StatusOpen,
	}
	if _, err := st.UpsertAlert(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestDevModeAndAlerts(t *testing.T) {
	ts, st, _ := setup(t, true)
	client := newClient(t, ts)
	acctID := createAccount(t, ts, client, "")
	rec := seedAlert(t, st, acctID)

	resp, body := do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts?severity=critical&ip=203.0.113.9", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list = %d: %s", resp.StatusCode, body)
	}
	var list struct {
		Total  int `json:"total"`
		Alerts []struct {
			ID       string `json:"id"`
			Title    string `json:"title"`
			Severity string `json:"severity"`
			OCSF     any    `json:"ocsf"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 || len(list.Alerts) != 1 || list.Alerts[0].Title != "Reverse shell" {
		t.Fatalf("list = %+v", list)
	}
	if list.Alerts[0].OCSF != nil {
		t.Fatal("list responses must omit OCSF")
	}

	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts/"+rec.ID, "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "class_uid") || !strings.Contains(string(body), `"raw":{"ID":"a-1"}`) {
		t.Fatalf("detail = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, client, http.MethodPatch, ts.URL+"/api/v1/alerts/"+rec.ID, "", `{"status":"acknowledged"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "acknowledged") {
		t.Fatalf("patch = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts/groups?group_by=signature", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("groups = %d: %s", resp.StatusCode, body)
	}
	var groups struct {
		Total  int `json:"total"`
		Groups []struct {
			ID    string            `json:"id"`
			Count int               `json:"finding_count"`
			Key   map[string]string `json:"key"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(body, &groups); err != nil {
		t.Fatal(err)
	}
	if groups.Total != 1 || len(groups.Groups) != 1 || groups.Groups[0].Count != 1 {
		t.Fatalf("groups = %+v", groups)
	}
	keyJSON, _ := json.Marshal(groups.Groups[0].Key)
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts?group_by=signature&group_key="+url.QueryEscape(string(keyJSON)), "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"total":1`) {
		t.Fatalf("group members = %d: %s", resp.StatusCode, body)
	}

	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts/"+rec.ID+"/revisions", "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"revision":1`) {
		t.Fatalf("revisions = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/stats", "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"total":1`) {
		t.Fatalf("stats = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/providers", "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "fake") {
		t.Fatalf("providers = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/auth/me", "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"auth_type":"dev"`) {
		t.Fatalf("dev me = %d: %s", resp.StatusCode, body)
	}
}

func TestDefaultGroupsAndMemberTimeWindow(t *testing.T) {
	ts, st, _ := setup(t, true)
	client := newClient(t, ts)
	rec := seedAlert(t, st, createAccount(t, ts, client, ""))
	start := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second).Add(250 * time.Millisecond)
	end := start.Add(time.Hour)
	rec.Product, rec.AlertType, rec.Region, rec.SourceIP = "CWP", "MaliciousProcess", "region-1", ""
	for i, at := range []time.Time{start.Add(-time.Millisecond), start, end, end.Add(time.Millisecond)} {
		rec.ID = ""
		rec.ExternalID = []string{"a-1", "at-start", "at-end", "after-end"}[i]
		rec.EventTime, rec.FirstSeenAt, rec.LastSeenAt = at, at, at
		if _, err := st.UpsertAlert(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
	}
	q := url.Values{"start": {start.Format(time.RFC3339Nano)}, "end": {end.Format(time.RFC3339Nano)}}
	resp, body := do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts/groups?"+q.Encode(), "", "")
	var result struct {
		Total   int                `json:"total"`
		GroupBy model.AlertGroupBy `json:"group_by"`
		Groups  []model.AlertGroup `json:"groups"`
		Window  view.QueryWindow   `json:"window"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &result) != nil || result.Total != 1 || len(result.Groups) != 1 || result.Groups[0].FindingCount != 2 || result.GroupBy != model.GroupByTypeAsset {
		t.Fatalf("default groups=%d %s", resp.StatusCode, body)
	}
	if result.Window.Start != q.Get("start") || result.Window.End != q.Get("end") {
		t.Fatalf("subsecond window changed: %+v", result.Window)
	}
	key, _ := json.Marshal(result.Groups[0].Key)
	q.Set("group_by", string(result.GroupBy))
	q.Set("group_key", string(key))
	q.Set("start", result.Window.Start)
	q.Set("end", result.Window.End)
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts?"+q.Encode(), "", "")
	var members struct {
		Total  int              `json:"total"`
		Window view.QueryWindow `json:"window"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &members) != nil || members.Total != 2 || members.Window != result.Window {
		t.Fatalf("expanded members=%d %s", resp.StatusCode, body)
	}
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts/groups?since=24h", "", "")
	if resp.StatusCode != 200 || json.Unmarshal(body, &result) != nil || result.Window.Start == "" || result.Window.End == "" {
		t.Fatalf("relative window missing=%d %s", resp.StatusCode, body)
	}
}

func TestHealthAndFailedPayloadInspection(t *testing.T) {
	ts, st, _ := setup(t, true)
	client := newClient(t, ts)
	id := createAccount(t, ts, client, "")
	resp, body := do(t, client, http.MethodGet, ts.URL+"/api/v1/health", "", "")
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte(`"status":"degraded"`)) || !bytes.Contains(body, []byte(`"status":"never_synced"`)) {
		t.Fatalf("health=%s", body)
	}
	if err := st.SaveIngestFailure(context.Background(), &model.IngestFailure{AccountID: id, Raw: json.RawMessage(`invalid json`), Error: "decode error", MapperVersion: "v1", IngestedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/accounts/"+id+"/failures", "", "")
	if resp.StatusCode != 200 || !json.Valid(body) || !bytes.Contains(body, []byte(`"raw":"invalid json"`)) {
		t.Fatalf("failed payload=%s", body)
	}
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/accounts/missing/failures", "", "")
	if resp.StatusCode != 404 {
		t.Fatalf("missing account=%d body=%s", resp.StatusCode, body)
	}
}

func TestAuthenticationSessionsAndAPIKeys(t *testing.T) {
	ts, st, authSvc := setup(t, false)
	client := newClient(t, ts)
	ctx := context.Background()
	if _, err := authSvc.EnsureAdmin(ctx, "admin", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	if resp, _ := do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous alerts = %d", resp.StatusCode)
	}
	if resp, _ := do(t, client, http.MethodGet, ts.URL+"/healthz", "", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz = %d", resp.StatusCode)
	}
	if resp, _ := do(t, client, http.MethodGet, ts.URL+"/mcp", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous mcp = %d", resp.StatusCode)
	}

	// Cross-origin login is rejected before credentials are checked.
	crossReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login",
		strings.NewReader(`{"username":"admin","password":"correct-horse-battery"}`))
	crossReq.Header.Set("Content-Type", "application/json")
	crossReq.Header.Set("Origin", "http://evil.example")
	crossResp, err := client.Do(crossReq)
	if err != nil {
		t.Fatal(err)
	}
	crossResp.Body.Close()
	if crossResp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin login = %d", crossResp.StatusCode)
	}

	resp, _ := do(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login", "",
		`{"username":"admin","password":"wrong-password-123"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong login = %d", resp.StatusCode)
	}
	resp, body := do(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login", "",
		`{"username":"admin","password":"correct-horse-battery"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get("Set-Cookie"), auth.CookieName) {
		t.Fatalf("missing session cookie: %v", resp.Header)
	}
	var login struct {
		Token string `json:"token"`
		User  struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &login); err != nil {
		t.Fatal(err)
	}
	if login.Token == "" || login.User.Username != "admin" || login.User.Role != "admin" {
		t.Fatalf("login = %+v", login)
	}

	// Cookie from the cookiejar is enough for the browser path.
	if resp, body := do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts", "", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("cookie alerts = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/auth/me", "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"auth_type":"session"`) {
		t.Fatalf("me = %d: %s", resp.StatusCode, body)
	}

	// Account creation is authenticated.
	resp, body = do(t, client, http.MethodPost, ts.URL+"/api/v1/accounts", "",
		`{"name":"prod","provider":"fake","account_uid":"123456","access_key_id":"TEST_ONLY_ACCESS_KEY","access_key_secret":"test-only-secret"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create account = %d: %s", resp.StatusCode, body)
	}
	var acct struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &acct); err != nil {
		t.Fatal(err)
	}
	rec := seedAlert(t, st, acct.ID)

	// Bearer session token works for API clients.
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts", login.Token, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Reverse shell") {
		t.Fatalf("bearer alerts = %d: %s", resp.StatusCode, body)
	}

	// Cookie-authenticated mutations reject a cross-site Origin.
	csrfReq, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/alerts/"+rec.ID,
		strings.NewReader(`{"status":"closed"}`))
	csrfReq.Header.Set("Content-Type", "application/json")
	csrfReq.Header.Set("Origin", "http://evil.example")
	csrfResp, err := client.Do(csrfReq)
	if err != nil {
		t.Fatal(err)
	}
	csrfResp.Body.Close()
	if csrfResp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin mutation = %d", csrfResp.StatusCode)
	}

	// Viewers can read but cannot mutate accounts or alert state.
	if _, err := authSvc.CreateUser(ctx, "viewer", "viewer-password-123", "viewer"); err != nil {
		t.Fatal(err)
	}
	resp, body = do(t, client, http.MethodPost, ts.URL+"/api/v1/auth/login", "",
		`{"username":"viewer","password":"viewer-password-123"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer login = %d: %s", resp.StatusCode, body)
	}
	var viewerLogin struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &viewerLogin); err != nil {
		t.Fatal(err)
	}
	if resp, _ := do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts", viewerLogin.Token, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer read = %d", resp.StatusCode)
	}
	if resp, _ := do(t, client, http.MethodPost, ts.URL+"/api/v1/accounts", viewerLogin.Token,
		`{"name":"nope","provider":"fake","access_key_id":"x","access_key_secret":"y"}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer create account = %d", resp.StatusCode)
	}
	if resp, _ := do(t, client, http.MethodPatch, ts.URL+"/api/v1/alerts/"+rec.ID, viewerLogin.Token, `{"status":"closed"}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer patch alert = %d", resp.StatusCode)
	}

	// API keys are created once, usable as Bearer tokens, and revocable.
	resp, body = do(t, client, http.MethodPost, ts.URL+"/api/v1/auth/keys", login.Token, `{"name":"mcp"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create key = %d: %s", resp.StatusCode, body)
	}
	var keyResp struct {
		Key string `json:"key"`
		API struct {
			ID string `json:"id"`
		} `json:"api_key"`
	}
	if err := json.Unmarshal(body, &keyResp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(keyResp.Key, auth.APIKeyPrefix) || keyResp.API.ID == "" {
		t.Fatalf("key response = %+v", keyResp)
	}
	resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts", keyResp.Key, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("api key alerts = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, client, http.MethodPost, ts.URL+"/mcp", keyResp.Key,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "2025-06-18") {
		t.Fatalf("mcp with api key = %d: %s", resp.StatusCode, body)
	}
	resp, _ = do(t, client, http.MethodDelete, ts.URL+"/api/v1/auth/keys/"+keyResp.API.ID, login.Token, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke key = %d", resp.StatusCode)
	}
	if resp, _ := do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts", keyResp.Key, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked key = %d", resp.StatusCode)
	}

	// Logout revokes the session.
	resp, _ = do(t, client, http.MethodPost, ts.URL+"/api/v1/auth/logout", login.Token, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d", resp.StatusCode)
	}
	if resp, _ := do(t, client, http.MethodGet, ts.URL+"/api/v1/alerts", login.Token, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout = %d", resp.StatusCode)
	}
}

func TestCredentialAndOptionValidation(t *testing.T) {
	ts, _, _ := setup(t, true)
	client := newClient(t, ts)

	if resp, body := do(t, client, http.MethodPost, ts.URL+"/api/v1/accounts", "",
		`{"name":"gcp","provider":"fake-gcp","options":{"parent":"organizations/1"}}`); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(string(body), "service_account_json") {
		t.Fatalf("missing credential = %d: %s", resp.StatusCode, body)
	}
	if resp, body := do(t, client, http.MethodPost, ts.URL+"/api/v1/accounts", "",
		`{"name":"gcp","provider":"fake-gcp","service_account_json":"{\"client_email\":\"mock@example.iam.gserviceaccount.com\"}"}`); resp.StatusCode != http.StatusBadRequest ||
		!strings.Contains(string(body), "parent") {
		t.Fatalf("missing option = %d: %s", resp.StatusCode, body)
	}
	resp, body := do(t, client, http.MethodPost, ts.URL+"/api/v1/accounts", "",
		`{"name":"gcp","provider":"fake-gcp","service_account_json":"{\"client_email\":\"mock@example.iam.gserviceaccount.com\"}","options":{"parent":"organizations/1"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d: %s", resp.StatusCode, body)
	}
	var acct struct {
		ID            string            `json:"id"`
		Options       map[string]string `json:"options"`
		AccessKeyHint string            `json:"access_key_hint"`
	}
	if err := json.Unmarshal(body, &acct); err != nil {
		t.Fatal(err)
	}
	if acct.Options["parent"] != "organizations/1" || !strings.Contains(acct.AccessKeyHint, "ount.com") {
		t.Fatalf("account = %+v", acct)
	}

	resp, body = do(t, client, http.MethodPatch, ts.URL+"/api/v1/accounts/"+acct.ID, "",
		`{"service_account_json":"{\"client_email\":\"rotated@example.iam.gserviceaccount.com\"}"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"parent":"organizations/1"`) {
		t.Fatalf("patch = %d: %s", resp.StatusCode, body)
	}
}

func TestMCPHTTP(t *testing.T) {
	ts, _, _ := setup(t, true)
	client := newClient(t, ts)

	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	resp, body := do(t, client, http.MethodPost, ts.URL+"/mcp", "", initBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize = %d: %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Mcp-Session-Id") == "" {
		t.Fatal("missing Mcp-Session-Id")
	}
	if !strings.Contains(string(body), "2025-06-18") {
		t.Fatalf("initialize body = %s", body)
	}
	resp, body = do(t, client, http.MethodPost, ts.URL+"/mcp", "",
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "list_alerts") {
		t.Fatalf("tools/list = %d: %s", resp.StatusCode, body)
	}
}
