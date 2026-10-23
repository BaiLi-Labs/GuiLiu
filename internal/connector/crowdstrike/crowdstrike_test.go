package crowdstrike

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const sampleAlert = `{
  "composite_id": "cid:ind:abc",
  "id": "abc",
  "display_name": "Suspicious PowerShell",
  "description": "Encoded command execution",
  "severity": 80,
  "severity_name": "High",
  "status": "new",
  "timestamp": "2026-10-23T10:00:00Z",
  "created_timestamp": "2026-10-23T10:00:01Z",
  "updated_timestamp": "2026-10-23T10:00:02Z",
  "product": "epp",
  "type": "ldt",
  "tactic": "Execution",
  "technique": "T1059.001",
  "scenario": "suspicious_script",
  "objective": "further_exploitation",
  "user_name": "alice",
  "file_name": "powershell.exe",
  "command_line": "powershell -enc AAAA",
  "sha256": "abc123",
  "device": {
    "device_id": "dev-1",
    "hostname": "win-01",
    "platform_name": "Windows",
    "local_ip": "10.0.0.5",
    "external_ip": "203.0.113.5"
  }
}`

func TestNormalizeAlert(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(sampleAlert))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "cid:ind:abc" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.Severity != model.SeverityHigh || alert.OriginalSeverity != "High" {
		t.Fatalf("severity = %v/%q", alert.Severity, alert.OriginalSeverity)
	}
	if alert.Resource.ID != "dev-1" || alert.Resource.Name != "win-01" || alert.Resource.Type != "host" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	if alert.Resource.Source != model.ResourceSourceVendorDeclared {
		t.Fatalf("resource source = %q", alert.Resource.Source)
	}
	if alert.Tactic != "Execution" || alert.Technique != "T1059.001" {
		t.Fatalf("attack = %q/%q", alert.Tactic, alert.Technique)
	}
	if alert.VendorStatus != "new" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	if alert.EventTime.IsZero() || alert.SourceCreatedAt.IsZero() {
		t.Fatal("timestamps were not parsed")
	}
	if len(alert.Observables) != 6 {
		t.Fatalf("observables = %+v", alert.Observables)
	}
	if len(alert.Evidences) != 1 || alert.Evidences[0].Type != "process" {
		t.Fatalf("evidences = %+v", alert.Evidences)
	}
	if !json.Valid(alert.Raw) {
		t.Fatal("raw payload was not preserved")
	}
}

func TestSeverityFallsBackToNumericScale(t *testing.T) {
	for _, tc := range []struct {
		value int
		want  model.Severity
	}{
		{0, model.SeverityUnknown},
		{10, model.SeverityInformational},
		{30, model.SeverityLow},
		{50, model.SeverityMedium},
		{70, model.SeverityHigh},
		{90, model.SeverityCritical},
	} {
		got, _ := severityOf("", tc.value)
		if got != tc.want {
			t.Fatalf("severity(%d) = %v want %v", tc.value, got, tc.want)
		}
	}
}

func newTestConnector(t *testing.T, handler http.Handler) *Connector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(connector.AccountConfig{
		Options:    map[string]string{"base_url": srv.URL},
		Credential: connector.Credential{AccessKeyID: "client", AccessKeySecret: "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c.(*Connector)
}

func TestFetchPaginatesAndCachesToken(t *testing.T) {
	var tokenCalls atomic.Int32
	var alertCalls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/token":
			tokenCalls.Add(1)
			if err := r.ParseForm(); err != nil || r.Form.Get("client_id") != "client" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, `{"access_token":"tok","expires_in":1799}`)
		case "/alerts/entities/alerts/v2":
			alertCalls.Add(1)
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			offset := r.URL.Query().Get("offset")
			item := fmt.Sprintf(`{"composite_id":"evt-%s","timestamp":"2026-10-23T10:00:00Z","severity":50}`, offset)
			fmt.Fprintf(w, `{"meta":{"pagination":{"offset":%s,"limit":1,"total":2}},"resources":[%s],"errors":[]}`, offset, item)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	c := newTestConnector(t, handler)
	start := time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)
	end := time.Date(2026, 10, 23, 11, 0, 0, 0, time.UTC)

	page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.NextToken != "1" || page.Total != 2 {
		t.Fatalf("first page = %+v", page)
	}
	second, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1, Token: page.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	if second.NextToken != "" {
		t.Fatalf("second token = %q", second.NextToken)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("token calls = %d (expected one cached token)", tokenCalls.Load())
	}
	if alertCalls.Load() != 2 {
		t.Fatalf("alert calls = %d", alertCalls.Load())
	}
}

func TestFetchClassifiesUnauthorized(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"access_denied","error_description":"bad client"}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	c := newTestConnector(t, handler)
	_, err := c.Fetch(context.Background(), connector.Query{Start: time.Now().Add(-time.Hour), End: time.Now()})
	if err == nil || !connector.AuthError(err) {
		t.Fatalf("error = %v (auth: %v)", err, connector.AuthError(err))
	}
}

func TestFetchClassifiesThrottling(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			fmt.Fprint(w, `{"access_token":"tok","expires_in":1799}`)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"errors":[{"code":429,"message":"rate limited"}]}`)
	})
	c := newTestConnector(t, handler)
	_, err := c.Fetch(context.Background(), connector.Query{Start: time.Now().Add(-time.Hour), End: time.Now()})
	if err == nil || !connector.Throttled(err) {
		t.Fatalf("error = %v (throttled: %v)", err, connector.Throttled(err))
	}
}
