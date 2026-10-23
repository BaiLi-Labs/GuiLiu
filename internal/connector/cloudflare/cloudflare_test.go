package cloudflare

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

const sampleEvent = `{
  "action": "block",
  "source": "waf",
  "clientIP": "203.0.113.10",
  "clientASN": 64512,
  "clientCountryName": "CN",
  "clientRequestPath": "/login",
  "clientRequestQuery": "next=/admin",
  "userAgent": "curl/8.0",
  "datetime": "2026-10-23T10:00:00Z",
  "ruleId": "100015"
}`

func TestNormalizeFirewallEvent(t *testing.T) {
	alert, err := (&Connector{zoneID: "zone-1"}).Normalize(json.RawMessage(sampleEvent))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID == "" {
		t.Fatal("an event without an id must fall back to a content hash")
	}
	if alert.Severity != model.SeverityUnknown {
		t.Fatalf("Cloudflare has no severity; got %v", alert.Severity)
	}
	if alert.OriginalSeverity != "" {
		t.Fatalf("original severity must stay empty, got %q", alert.OriginalSeverity)
	}
	if alert.VendorStatus != "block" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	if alert.SourceIP != "203.0.113.10" {
		t.Fatalf("source ip = %q", alert.SourceIP)
	}
	if alert.CloudAccountUID != "zone-1" {
		t.Fatalf("zone was not recorded: %q", alert.CloudAccountUID)
	}
	if alert.AlertType != "waf" || alert.RuleID != "100015" {
		t.Fatalf("type/rule = %q/%q", alert.AlertType, alert.RuleID)
	}
	want := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	if !alert.EventTime.Equal(want) {
		t.Fatalf("event time = %v", alert.EventTime)
	}
	if len(alert.Observables) != 1 || alert.Observables[0].Value != "203.0.113.10" {
		t.Fatalf("observables = %+v", alert.Observables)
	}
	if !json.Valid(alert.Raw) {
		t.Fatal("raw payload was not preserved")
	}
}

func TestNormalizeCanDeriveSeverity(t *testing.T) {
	alert, err := (&Connector{zoneID: "z", severityAction: true}).Normalize(json.RawMessage(sampleEvent))
	if err != nil {
		t.Fatal(err)
	}
	if alert.Severity != model.SeverityMedium {
		t.Fatalf("derived severity = %v", alert.Severity)
	}
	if alert.Unmapped["severity_source"] != "derived_from_action" {
		t.Fatalf("derived severity must be labelled: %+v", alert.Unmapped)
	}
}

func newTestConnector(t *testing.T, handler http.Handler) *Connector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(connector.AccountConfig{
		Options:    map[string]string{"zone_id": "zone-1", "endpoint": srv.URL},
		Credential: connector.Credential{AccessKeyID: "test-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c.(*Connector)
}

func TestFetchAdvancesOverTimeSlices(t *testing.T) {
	var variables []map[string]any
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		variables = append(variables, req.Variables)
		fmt.Fprint(w, `{"data":{"viewer":{"zones":[{"firewallEventsAdaptive":[]}]}}}`)
	})
	c := newTestConnector(t, handler)
	start := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)

	page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(variables) != 1 {
		t.Fatalf("requests = %d", len(variables))
	}
	if variables[0]["zoneTag"] != "zone-1" {
		t.Fatalf("zoneTag = %v", variables[0]["zoneTag"])
	}
	filter := variables[0]["filter"].(map[string]any)
	if filter["datetime_geq"] != "2026-10-23T00:00:00Z" {
		t.Fatalf("slice start = %v", filter["datetime_geq"])
	}
	if filter["datetime_leq"] != "2026-10-23T06:00:00Z" {
		t.Fatalf("slice end = %v", filter["datetime_leq"])
	}

	tok, err := decodeToken(page.NextToken, connector.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Next != "2026-10-23T06:00:00Z" {
		t.Fatalf("next cursor = %q", tok.Next)
	}
	if tok.Chunk != int64(defaultChunk) {
		t.Fatalf("chunk = %d", tok.Chunk)
	}
}

func TestFetchNarrowsSaturatedSlice(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		event := `{"action":"block","clientIP":"203.0.113.1","datetime":"2026-10-23T00:00:01Z"}`
		fmt.Fprintf(w, `{"data":{"viewer":{"zones":[{"firewallEventsAdaptive":[%s,%s]}]}}}`, event, event)
	})
	c := newTestConnector(t, handler)
	start := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)

	page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := decodeToken(page.NextToken, connector.Query{})
	if err != nil {
		t.Fatal(err)
	}
	if tok.Next != "2026-10-23T00:00:00Z" {
		t.Fatalf("a saturated slice must not advance, got %q", tok.Next)
	}
	if tok.Chunk != int64(3*time.Hour) {
		t.Fatalf("chunk should halve to 3h, got %d", tok.Chunk)
	}
}

func TestFetchClassifiesGraphQLErrors(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":null,"errors":[{"message":"not authorized for zone","extensions":{"code":"authz"}}]}`)
	})
	c := newTestConnector(t, handler)
	_, err := c.Fetch(context.Background(), connector.Query{
		Start: time.Now().Add(-time.Hour), End: time.Now(), PageSize: 10,
	})
	if err == nil || !connector.AuthError(err) {
		t.Fatalf("error = %v (auth classified: %v)", err, connector.AuthError(err))
	}
}

func TestFetchClassifiesMissingZone(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":{"viewer":{"zones":[]}}}`)
	})
	c := newTestConnector(t, handler)
	_, err := c.Fetch(context.Background(), connector.Query{
		Start: time.Now().Add(-time.Hour), End: time.Now(), PageSize: 10,
	})
	if err == nil || !connector.AuthError(err) {
		t.Fatalf("error = %v (auth classified: %v)", err, connector.AuthError(err))
	}
}

func TestNewRequiresZone(t *testing.T) {
	_, err := New(connector.AccountConfig{Credential: connector.Credential{AccessKeyID: "t"}})
	if err == nil {
		t.Fatal("zone_id must be required")
	}
}
