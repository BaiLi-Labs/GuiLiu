package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/cli"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/elasticsearch"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

func TestRemoteEventsRESTMCPCLIShareSourceContract(t *testing.T) {
	var queries atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries.Add(1)
		if r.Header.Get("Authorization") != "ApiKey synthetic-source-key" {
			t.Error("source credential was not used")
		}
		switch r.URL.Path {
		case "/logs-prod/_pit":
			fmt.Fprint(w, `{"id":"synthetic-pit"}`)
		case "/_pit":
			fmt.Fprint(w, `{"succeeded":true}`)
		case "/logs-prod/_field_caps":
			fmt.Fprint(w, `{"fields":{"message":{"text":{"searchable":true,"aggregatable":false}}}}`)
		case "/_search", "/logs-prod/_search":
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid search request")
			}
			if body["size"] == float64(0) {
				fmt.Fprint(w, `{"hits":{"hits":[]}}`)
				return
			}
			count := 1
			if body["size"] == float64(2) && r.URL.Path == "/_search" {
				count = 2
			}
			if _, after := body["search_after"]; after {
				count = 0
			}
			if r.URL.Path == "/logs-prod/_search" {
				query, _ := json.Marshal(body["query"])
				if strings.Contains(string(query), "outside-index") {
					count = 0
				}
			}
			hits := []string{}
			for i := 0; i < count; i++ {
				hits = append(hits, fmt.Sprintf(`{"_index":"logs-web-000001","_id":"doc-%d","_source":{"@timestamp":"2026-10-01T00:00:00Z","message":"synthetic private source text","host":{"name":"test-web"},"request_id":9007199254740993},"sort":["2026-10-01T00:00:00Z",%d]}`, i+1, i+1))
			}
			fmt.Fprintf(w, `{"hits":{"total":{"value":2,"relation":"eq"},"hits":[%s]}}`, strings.Join(hits, ","))
		default:
			t.Errorf("escaped source scope: %s", r.URL)
			w.WriteHeader(500)
		}
	}))
	defer upstream.Close()
	register := func(reg *connector.Registry) {
		d, ok := connector.Default().Descriptor("elasticsearch")
		if !ok {
			t.Fatal("Elasticsearch was not registered")
		}
		if err := reg.Register(d, elasticsearch.New); err != nil {
			t.Fatal(err)
		}
	}
	ts, st, svc := setup(t, false, register)
	ctx := context.Background()
	admin, err := svc.CreateUser(ctx, "test-es-admin", "synthetic-admin-password", "admin")
	if err != nil {
		t.Fatal(err)
	}
	adminKey, _, err := svc.CreateAPIKey(ctx, admin.ID, "setup", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	user, err := svc.CreateUser(ctx, "test-es-reader", "synthetic-reader-password", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	readerKey, _, err := svc.CreateAPIKey(ctx, user.ID, "agent", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client := newClient(t, ts)
	input, _ := json.Marshal(map[string]any{"name": "test-es", "provider": "elasticsearch", "access_key_secret": "synthetic-source-key", "options": map[string]string{"endpoint": upstream.URL, "indices": "logs-prod"}})
	resp, body := do(t, client, "POST", ts.URL+"/api/v1/accounts", adminKey, string(input))
	var account view.Account
	if resp.StatusCode != 201 || json.Unmarshal(body, &account) != nil || !account.QueryOnly || !account.CredentialSet || account.SyncState != nil {
		t.Fatalf("account: %d %s", resp.StatusCode, body)
	}
	stored, _ := st.AccountCredential(ctx, account.ID)
	if strings.Contains(stored, "synthetic-source-key") || strings.Contains(string(body), "synthetic-source-key") {
		t.Fatal("source credential was not encrypted/redacted")
	}
	request, _ := json.Marshal(model.EventSearch{AccountID: account.ID, Start: "2026-10-01", End: "2026-10-02", Keyword: "private query phrase", Limit: 1})
	before := queries.Load()
	resp, _ = do(t, client, "POST", ts.URL+"/api/v1/events/search", "", string(request))
	if resp.StatusCode != 401 || queries.Load() != before {
		t.Fatal("unauthenticated request reached the source")
	}
	resp, body = do(t, client, "POST", ts.URL+"/api/v1/events/search", readerKey, string(request))
	var page model.EventPage
	if resp.StatusCode != 200 || json.Unmarshal(body, &page) != nil || len(page.Events) != 1 || page.NextCursor == "" || !page.HasMore {
		t.Fatalf("event search: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(page.NextCursor, "synthetic-pit") || strings.Contains(string(body), "synthetic-source-key") {
		t.Fatal("unsealed cursor or source credential exposed")
	}
	for _, invalid := range []model.EventSearch{
		{AccountID: account.ID, Cursor: page.NextCursor, Keyword: "changed filter"},
		{AccountID: account.ID, Cursor: page.NextCursor + "invalid"},
		{AccountID: "wrong-source", Cursor: page.NextCursor},
	} {
		raw, _ := json.Marshal(invalid)
		before := queries.Load()
		resp, _ := do(t, client, "POST", ts.URL+"/api/v1/events/search", readerKey, string(raw))
		if resp.StatusCode != 400 || queries.Load() != before {
			t.Fatal("invalid cursor reached the upstream")
		}
	}
	ref, _ := json.Marshal(page.Events[0].Evidence)
	resp, body = do(t, client, "POST", ts.URL+"/api/v1/events/evidence", readerKey, string(ref))
	if resp.StatusCode != 200 || !strings.Contains(string(body), "9007199254740993") || !strings.Contains(string(body), `"changed":false`) {
		t.Fatalf("evidence: %d %s", resp.StatusCode, body)
	}
	outOfScope, _ := json.Marshal(model.EventReference{AccountID: account.ID, Index: "outside-index", ID: "doc-1"})
	resp, body = do(t, client, "POST", ts.URL+"/api/v1/events/evidence", readerKey, string(outOfScope))
	if resp.StatusCode != 404 {
		t.Fatalf("out of scope evidence: %d %s", resp.StatusCode, body)
	}
	mcpQuery, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "search_events", "arguments": map[string]any{"account_id": account.ID, "start": "2026-10-01", "end": "2026-10-02", "limit": 1}}})
	resp, body = do(t, client, "POST", ts.URL+"/mcp", readerKey, string(mcpQuery))
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"isError":false`) || !strings.Contains(string(body), `ese_`) {
		t.Fatalf("MCP events: %d %s", resp.StatusCode, body)
	}
	cliServer := httptest.NewServer(ts.handler)
	defer cliServer.Close()
	t.Setenv("GUILIU_API_KEY", readerKey)
	var output, diagnostics bytes.Buffer
	exit := cli.Run([]string{"--url", cliServer.URL, "events", "--account", account.ID, "--start", "2026-10-01", "--end", "2026-10-02", "--limit", "1", "--json"}, &output, &diagnostics)
	var cliPage model.EventPage
	if exit != 0 || json.Unmarshal(output.Bytes(), &cliPage) != nil || cliPage.Events[0].ID != page.Events[0].ID {
		t.Fatalf("CLI events: exit=%d %s %s", exit, output.String(), diagnostics.String())
	}
	resp, body = do(t, client, "POST", ts.URL+"/api/v1/accounts/"+account.ID+"/sync", adminKey, "")
	if resp.StatusCode != 422 || !strings.Contains(string(body), "query_only") {
		t.Fatalf("query source was polled: %d %s", resp.StatusCode, body)
	}
	resp, body = do(t, client, "GET", ts.URL+"/api/v1/health", readerKey, "")
	if resp.StatusCode != 200 || strings.Contains(string(body), "degraded") {
		t.Fatalf("query source caused fake sync failure: %s", body)
	}
	resp, body = do(t, client, "GET", ts.URL+"/api/v1/coverage?since=24h", readerKey, "")
	if resp.StatusCode != 200 || strings.Contains(string(body), account.ID) {
		t.Fatalf("remote events mixed into Finding coverage: %d %s", resp.StatusCode, body)
	}
	resp, body = do(t, client, "GET", ts.URL+"/api/v1/audit-events", adminKey, "")
	for _, secret := range []string{"synthetic-source-key", "synthetic private source text", "private query phrase", "synthetic-pit"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("audit leaked %q", secret)
		}
	}
	if !strings.Contains(string(body), "logs-web-000001") || !strings.Contains(string(body), "effective_query") {
		t.Fatalf("missing event audit references: %s", body)
	}
	// Changing source configuration invalidates old cursors before any ES query.
	resp, body = do(t, client, "PATCH", ts.URL+"/api/v1/accounts/"+account.ID, adminKey, `{"options":{"endpoint":"`+upstream.URL+`","indices":"logs-other"}}`)
	if resp.StatusCode != 200 {
		t.Fatalf("edit: %d %s", resp.StatusCode, body)
	}
	before = queries.Load()
	resume, _ := json.Marshal(model.EventSearch{AccountID: account.ID, Cursor: page.NextCursor})
	resp, _ = do(t, client, "POST", ts.URL+"/api/v1/events/search", readerKey, string(resume))
	if resp.StatusCode != 400 || queries.Load() != before {
		t.Fatal("cursor survived source scope change")
	}
}
