package dsensor

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
  "agent_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "alarm_type": "connection",
  "description": "SSH 暴力破解",
  "src_ip": "203.0.113.10",
  "dest_ip": "10.0.0.5",
  "risk_level": 3,
  "status": 1,
  "last_alarm_time": "2026-10-23T10:00:00Z",
  "node": "node-1",
  "history": {"2026-10-23T10:00:00Z": {"status": 1, "text": "open"}}
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
		t.Fatalf("risk_level ordering is unpublished; got %v", alert.Severity)
	}
	if alert.OriginalSeverity != "3" {
		t.Fatalf("original severity = %q", alert.OriginalSeverity)
	}
	if alert.Title != "SSH 暴力破解" || alert.AlertType != "connection" {
		t.Fatalf("title/type = %q/%q", alert.Title, alert.AlertType)
	}
	if alert.VendorStatus != "1" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	if alert.SourceIP != "203.0.113.10" || alert.DestinationIP != "10.0.0.5" {
		t.Fatalf("ips = %q/%q", alert.SourceIP, alert.DestinationIP)
	}
	want := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	if !alert.EventTime.Equal(want) {
		t.Fatalf("event time = %v", alert.EventTime)
	}
	if len(alert.Observables) != 2 {
		t.Fatalf("observables = %+v", alert.Observables)
	}
	if !json.Valid(alert.Raw) {
		t.Fatal("raw payload was not preserved")
	}
}

func TestSeverityDerivationIsOptInAndLabelled(t *testing.T) {
	alert, err := (&Connector{severityFrom: true}).Normalize(json.RawMessage(sampleAlarm))
	if err != nil {
		t.Fatal(err)
	}
	if alert.Severity != model.SeverityHigh {
		t.Fatalf("derived severity = %v", alert.Severity)
	}
	if alert.Unmapped["severity_source"] != "derived_from_risk_level" {
		t.Fatal("a derived severity must be labelled")
	}
}

func TestAlarmTypeFallbackTitle(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(`{"id":"a","alarm_type":"scanner","last_alarm_time":"2026-10-23T10:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if alert.Title != "Port scan event" {
		t.Fatalf("title = %q", alert.Title)
	}
}

func newTestConnector(t *testing.T, handler http.Handler) *Connector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(connector.AccountConfig{
		Options:    map[string]string{"endpoint": srv.URL},
		Credential: connector.Credential{AccessKeyID: "api-key"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c.(*Connector)
}

func TestFetchSendsRequiredFields(t *testing.T) {
	var body map[string]any
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/event/event_alarm/list" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("API-Token") != "api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode: %v", err)
		}
		fmt.Fprint(w, `{"data":{"total":1,"data":[{"id":"a"}],"unhandle_count":1,"handle_count":0},"err":"","msg":""}`)
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
	for _, key := range []string{"status", "id_order", "last_alarm_time_order", "risk_level_order", "status_order"} {
		if _, ok := body[key]; !ok {
			t.Fatalf("required field %s is missing: %v", key, body)
		}
	}
	if body["not_before"] != "2026-10-23T10:00:00Z" || body["not_after"] != "2026-10-23T11:00:00Z" {
		t.Fatalf("time window = %v / %v", body["not_before"], body["not_after"])
	}
	if body["limit"] != float64(10) || body["offset"] != float64(0) {
		t.Fatalf("paging = %v / %v", body["limit"], body["offset"])
	}
}

func TestFetchPaginatesByOffset(t *testing.T) {
	var offsets []float64
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		offset, _ := body["offset"].(float64)
		offsets = append(offsets, offset)
		fmt.Fprintf(w, `{"data":{"total":2,"data":[{"id":"e%d"}]},"err":""}`, int(offset))
	})
	c := newTestConnector(t, handler)
	start := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)

	first, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.NextToken != "1" {
		t.Fatalf("first token = %q", first.NextToken)
	}
	second, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1, Token: first.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	if second.NextToken != "" {
		t.Fatalf("second token = %q", second.NextToken)
	}
	if len(offsets) != 2 || offsets[1] != 1 {
		t.Fatalf("offsets = %v", offsets)
	}
}

func TestFetchClassifiesBusinessError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":null,"err":"unauthorized","msg":"token invalid"}`)
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
