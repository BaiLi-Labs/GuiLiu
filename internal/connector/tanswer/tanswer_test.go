package tanswer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const sampleAlarm = `{
  "doc_id": "a1b2c3",
  "name": "Webshell 连接",
  "timestamp": 1792749600000,
  "severity": "2",
  "tag": "webshell",
  "type": "webshell_connect",
  "tool": "chopper",
  "attacker": "203.0.113.10",
  "victim": "10.0.0.5",
  "src_ip": "203.0.113.10",
  "src_port": 51515,
  "dest_ip": "10.0.0.5",
  "dest_port": 8080,
  "proto": "tcp",
  "app_proto": "http",
  "result": "control",
  "phase": "goal",
  "direction": "in",
  "msg": "检测到 Webshell 通信",
  "attacker_asset": {"name": "unknown", "ip": "203.0.113.10"},
  "victim_asset": {"name": "web-01", "ip": "10.0.0.5"},
  "geo_attacker": {"country": "CN"},
  "appbrief": {"http": {"url": "https://app.example.test/shell", "host": "app.example.test", "method": "POST", "status": 200}}
}`

func TestNormalizeAlarm(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(sampleAlarm))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "a1b2c3" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.Severity != model.SeverityHigh || alert.OriginalSeverity != "2" {
		t.Fatalf("severity = %v/%q", alert.Severity, alert.OriginalSeverity)
	}
	if alert.Title != "Webshell 连接" || alert.AlertType != "webshell" {
		t.Fatalf("title/type = %q/%q", alert.Title, alert.AlertType)
	}
	if alert.VendorStatus != "control" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	if alert.SourceIP != "203.0.113.10" || alert.DestinationIP != "10.0.0.5" {
		t.Fatalf("ips = %q/%q", alert.SourceIP, alert.DestinationIP)
	}
	if alert.Resource.Name != "web-01" || alert.Resource.Type != "host" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	want := time.UnixMilli(1792749600000).UTC()
	if !alert.EventTime.Equal(want) {
		t.Fatalf("event time = %v want %v", alert.EventTime, want)
	}
	if len(alert.Observables) != 2 {
		t.Fatalf("observables = %+v", alert.Observables)
	}
	if !json.Valid(alert.Raw) {
		t.Fatal("raw payload was not preserved")
	}
}

func TestNormalizeNamedSeverityAndRFC3339(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(`{"doc_id":"a","severity":"low","timestamp":"2026-10-23T10:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if alert.Severity != model.SeverityLow {
		t.Fatalf("severity = %v", alert.Severity)
	}
	if alert.EventTime.IsZero() {
		t.Fatal("rfc3339 timestamp was not parsed")
	}
}

func newTestConnector(t *testing.T, handler http.Handler) *Connector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(connector.AccountConfig{
		Options:    map[string]string{"endpoint": srv.URL},
		Credential: connector.Credential{AccessKeyID: "test-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c.(*Connector)
}

func TestFetchSendsRPCContract(t *testing.T) {
	var request struct {
		JSONRPC string         `json:"jsonrpc"`
		Method  string         `json:"method"`
		Params  map[string]any `json:"params"`
		ID      string         `json:"id"`
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rpc" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Api-Token") != "test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"1","result":{"data":[{"doc_id":"a"}],"total":1,"page_total":1}}`)
	})
	c := newTestConnector(t, handler)
	start := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)

	page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.NextToken != "" {
		t.Fatalf("page = %+v", page)
	}
	if request.JSONRPC != "2.0" || request.Method != "AlarmService.SearchAlarmList" {
		t.Fatalf("rpc envelope = %+v", request)
	}
	if request.Params["time_range_start"] != float64(start.UnixMilli()) {
		t.Fatalf("start = %v", request.Params["time_range_start"])
	}
	if request.Params["offset"] != float64(0) || request.Params["count"] != float64(10) {
		t.Fatalf("paging = %+v", request.Params)
	}
	if request.Params["save_history"] != false {
		t.Fatalf("save_history = %v", request.Params["save_history"])
	}
	if request.ID == "" {
		t.Fatal("request id must be set")
	}
}

func TestFetchPaginatesByOffset(t *testing.T) {
	var offsets []float64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		offset, _ := request.Params["offset"].(float64)
		offsets = append(offsets, offset)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","result":{"data":[{"doc_id":"e%d"}],"total":3}}`, int(offset))
	})
	c := newTestConnector(t, handler)
	start := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)

	token := ""
	for i := 0; i < 3; i++ {
		page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1, Token: token})
		if err != nil {
			t.Fatal(err)
		}
		token = page.NextToken
	}
	if len(offsets) != 3 || offsets[0] != 0 || offsets[1] != 1 || offsets[2] != 2 {
		t.Fatalf("offsets = %v", offsets)
	}
	if token != "" {
		t.Fatalf("final token = %q", token)
	}
}

func TestFetchClassifiesRPCError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"1","error":{"code":-32001,"message":"token expired"}}`)
	})
	c := newTestConnector(t, handler)
	_, err := c.Fetch(context.Background(), connector.Query{
		Start: time.Now().Add(-time.Hour), End: time.Now(), PageSize: 10,
	})
	if err == nil || !connector.AuthError(err) {
		t.Fatalf("error = %v (auth classified: %v)", err, connector.AuthError(err))
	}
}

func TestFetchClassifiesHTTPUnauthorized(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	c := newTestConnector(t, handler)
	_, err := c.Fetch(context.Background(), connector.Query{
		Start: time.Now().Add(-time.Hour), End: time.Now(), PageSize: 10,
	})
	if err == nil || !connector.AuthError(err) {
		t.Fatalf("error = %v", err)
	}
}
