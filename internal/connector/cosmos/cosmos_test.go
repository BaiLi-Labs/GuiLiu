package cosmos

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
  "id": "alarm-1",
  "alarm_name": "SQL Injection",
  "alarm_level": 3,
  "alarm_major_type": "web",
  "alarm_minor_type": "sql_injection",
  "attack_ip_string": "203.0.113.10",
  "victim_ip_string": "10.0.0.5",
  "attack_method": "sqli",
  "attack_direction": "in",
  "attack_chain_phase": "goal",
  "disposed_state": "2",
  "judged_state": "1",
  "created_at": 1792749600000,
  "updated_at": 1792749600000,
  "tag": ["owasp"],
  "victim_web_url": "https://app.example.test/login"
}`

func TestNormalizeAlarm(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(sampleAlarm))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "alarm-1" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.Severity != model.SeverityUnknown {
		t.Fatalf("alarm_level semantics are unpublished; got %v", alert.Severity)
	}
	if alert.OriginalSeverity != "3" {
		t.Fatalf("original severity = %q", alert.OriginalSeverity)
	}
	if alert.Title != "SQL Injection" || alert.AlertType != "web" {
		t.Fatalf("title/type = %q/%q", alert.Title, alert.AlertType)
	}
	if alert.SourceIP != "203.0.113.10" || alert.DestinationIP != "10.0.0.5" {
		t.Fatalf("ips = %q/%q", alert.SourceIP, alert.DestinationIP)
	}
	if alert.VendorStatus != "2" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	want := time.UnixMilli(1792749600000).UTC()
	if !alert.EventTime.Equal(want) {
		t.Fatalf("event time = %v", alert.EventTime)
	}
	if alert.Unmapped["cosmos"].(map[string]any)["mapping_unverified"] != true {
		t.Fatal("an unverified mapping must be labelled")
	}
	if !json.Valid(alert.Raw) {
		t.Fatal("raw payload was not preserved")
	}
}

func TestSeverityIsOnlyDerivedWhenEnabled(t *testing.T) {
	alert, err := (&Connector{severityFrom: true}).Normalize(json.RawMessage(sampleAlarm))
	if err != nil {
		t.Fatal(err)
	}
	if alert.Severity != model.SeverityMedium {
		t.Fatalf("derived severity = %v", alert.Severity)
	}
}

func TestExtractAlarmsShapes(t *testing.T) {
	for name, result := range map[string]string{
		"array":         `[{"id":"a"},{"id":"b"}]`,
		"data list":     `{"data":[{"id":"a"}]}`,
		"data nested":   `{"data":{"list":[{"id":"a"}],"total":7}}`,
		"alarms":        `{"alarms":[{"id":"a"}]}`,
		"records total": `{"records":[{"id":"a"}],"total_count":2}`,
	} {
		items, total, err := extractAlarms(json.RawMessage(result))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(items) != 1 && name != "array" {
			t.Fatalf("%s: items = %d", name, len(items))
		}
		if name == "array" && len(items) != 2 {
			t.Fatalf("array items = %d", len(items))
		}
		if name == "data nested" && total != 7 {
			t.Fatalf("nested total = %d", total)
		}
		if name == "records total" && total != 2 {
			t.Fatalf("total_count = %d", total)
		}
	}
}

func TestExtractAlarmsRejectsUnknownShape(t *testing.T) {
	if _, _, err := extractAlarms(json.RawMessage(`{"unexpected":{}}`)); err == nil {
		t.Fatal("an unrecognized shape must be an error, not an empty page")
	}
}

func newTestConnector(t *testing.T, handler http.Handler) *Connector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(connector.AccountConfig{
		Options:    map[string]string{"endpoint": srv.URL},
		Credential: connector.Credential{AccessKeyID: "jwt-token"},
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
		if r.URL.Path != "/pedestal/rpc" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer jwt-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode: %v", err)
		}
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"1","result":{"data":{"list":[{"id":"a"}],"total":1}}}`)
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
	if request.JSONRPC != "2.0" || request.Method != "AlarmService.GetAlarmList" {
		t.Fatalf("rpc envelope = %+v", request)
	}
	wantRange := fmt.Sprintf("%d-%d", start.UnixMilli(), end.UnixMilli())
	if request.Params["created_at"] != wantRange {
		t.Fatalf("created_at = %v want %s", request.Params["created_at"], wantRange)
	}
	if request.Params["offset"] != float64(0) || request.Params["count"] != float64(10) {
		t.Fatalf("paging = %+v", request.Params)
	}
}

func TestFetchPaginatesWithoutTotal(t *testing.T) {
	var offsets []float64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		offset, _ := request.Params["offset"].(float64)
		offsets = append(offsets, offset)
		if offset == 0 {
			fmt.Fprint(w, `{"jsonrpc":"2.0","result":{"list":[{"id":"a"}]}}`)
			return
		}
		fmt.Fprint(w, `{"jsonrpc":"2.0","result":{"list":[]}}`)
	})
	c := newTestConnector(t, handler)
	start := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)

	first, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.NextToken == "" {
		t.Fatal("a full page without total must continue")
	}
	second, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1, Token: first.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	if second.NextToken != "" {
		t.Fatal("an empty page must end pagination")
	}
	if len(offsets) != 2 || offsets[1] != 1 {
		t.Fatalf("offsets = %v", offsets)
	}
}

func TestFetchClassifiesRPCError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"1","error":{"code":-32001,"message":"invalid token"}}`)
	})
	c := newTestConnector(t, handler)
	_, err := c.Fetch(context.Background(), connector.Query{
		Start: time.Now().Add(-time.Hour), End: time.Now(), PageSize: 10,
	})
	if err == nil || !connector.AuthError(err) {
		t.Fatalf("error = %v (auth classified: %v)", err, connector.AuthError(err))
	}
}

func TestBareArrayPageDoesNotTruncateCollection(t *testing.T) {
	c := newTestConnector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Params struct {
				Offset int `json:"offset"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		if request.Params.Offset == 0 {
			fmt.Fprint(w, `{"jsonrpc":"2.0","result":[{"id":"a"}]}`)
		} else {
			fmt.Fprint(w, `{"jsonrpc":"2.0","result":[]}`)
		}
	}))
	first, err := c.Fetch(context.Background(), connector.Query{PageSize: 1})
	if err != nil || first.NextToken != "1" {
		t.Fatalf("first bare page = %+v, %v", first, err)
	}
	last, err := c.Fetch(context.Background(), connector.Query{PageSize: 1, Token: first.NextToken})
	if err != nil || last.NextToken != "" || len(last.Records) != 0 {
		t.Fatalf("last bare page = %+v, %v", last, err)
	}
}

func TestFetchClassifiesUnknownShape(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"jsonrpc":"2.0","result":{"weird":[]}}`)
	})
	c := newTestConnector(t, handler)
	_, err := c.Fetch(context.Background(), connector.Query{
		Start: time.Now().Add(-time.Hour), End: time.Now(), PageSize: 10,
	})
	if err == nil {
		t.Fatal("an unknown result shape must fail loudly")
	}
}
