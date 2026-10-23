package safeline

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// The sample is synthetic. It mirrors the field names documented by the public
// chaitin-cli client and must be replaced with a real, redacted capture once a
// live appliance is available.
const sampleDetection = `{
  "event_id": "6edb4c7eb69042cd996045e3ee5526d9",
  "timestamp": "1792749600",
  "src_ip": "203.0.113.10",
  "host": "app.example.test",
  "url_path": "/api/login",
  "method": "POST",
  "attack_type": "SQL注入",
  "risk_level": "3",
  "action": {"translation": "拦截"},
  "sort": [1792749600, "6edb4c7eb69042cd996045e3ee5526d9"]
}`

func TestNormalizeDetection(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(sampleDetection))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "6edb4c7eb69042cd996045e3ee5526d9" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.Severity != model.SeverityHigh {
		t.Fatalf("severity = %v", alert.Severity)
	}
	if alert.OriginalSeverity != "3" {
		t.Fatalf("original severity = %q", alert.OriginalSeverity)
	}
	if alert.Title != "SQL注入" || alert.AlertType != "SQL注入" {
		t.Fatalf("title/type = %q/%q", alert.Title, alert.AlertType)
	}
	if alert.VendorStatus != "拦截" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	if alert.SourceIP != "203.0.113.10" {
		t.Fatalf("source ip = %q", alert.SourceIP)
	}
	if alert.Resource.ID != "app.example.test" || alert.Resource.Type != "domain" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	want := time.Unix(1792749600, 0).UTC()
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

func TestNormalizeKeepsMissingSeverityUnknown(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(`{"event_id":"a","timestamp":"1792749600"}`))
	if err != nil {
		t.Fatal(err)
	}
	if alert.Severity != model.SeverityUnknown {
		t.Fatalf("severity = %v", alert.Severity)
	}
	if alert.ExternalID != "a" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
}

func TestNormalizeFallsBackToContentHash(t *testing.T) {
	raw := json.RawMessage(`{"timestamp":"1792749600","src_ip":"203.0.113.10"}`)
	alert, err := (&Connector{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != connector.HashRaw(raw) {
		t.Fatalf("external id = %q", alert.ExternalID)
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

func TestFetchPaginatesWithTailSort(t *testing.T) {
	var requests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("API-Token") != "test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		requests.Add(1)
		page, _ := strconv.Atoi(r.URL.Query().Get("target_page"))
		item := fmt.Sprintf(`{"event_id":"evt-%d","timestamp":"1792749600","src_ip":"203.0.113.%d","sort":[1792749600,"evt-%d"]}`, page, page, page)
		fmt.Fprintf(w, `{"err":null,"data":{"items":[%s],"total":3}}`, item)
	})
	c := newTestConnector(t, handler)
	start := time.Unix(1792740000, 0).UTC()
	end := time.Unix(1792750000, 0).UTC()

	page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.NextToken == "" || page.Total != 3 {
		t.Fatalf("first page = %+v", page)
	}

	token := page.NextToken
	pages := 1
	for token != "" {
		next, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1, Token: token})
		if err != nil {
			t.Fatal(err)
		}
		if len(next.Records) != 1 {
			t.Fatalf("page %d records = %d", pages+1, len(next.Records))
		}
		token = next.NextToken
		pages++
		if pages > 5 {
			t.Fatal("pagination did not terminate")
		}
	}
	if pages != 3 {
		t.Fatalf("pages = %d", pages)
	}
	if requests.Load() != 3 {
		t.Fatalf("requests = %d", requests.Load())
	}
}

func TestFetchDegradesWhenTimeFilterIsRejected(t *testing.T) {
	var timeFiltered atomic.Int32
	var unfiltered atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["timestamp__gte"]; ok {
			timeFiltered.Add(1)
			fmt.Fprint(w, `{"err":"invalid_filter_key","data":null}`)
			return
		}
		unfiltered.Add(1)
		fmt.Fprint(w, `{"err":null,"data":{"items":[{"event_id":"evt-1","timestamp":"1792749600"}],"total":1}}`)
	})
	c := newTestConnector(t, handler)
	start := time.Unix(1792740000, 0).UTC()
	end := time.Unix(1792750000, 0).UTC()

	page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("records = %d", len(page.Records))
	}
	if timeFiltered.Load() != 1 || unfiltered.Load() != 1 {
		t.Fatalf("time-filtered=%d unfiltered=%d", timeFiltered.Load(), unfiltered.Load())
	}
}

func TestFetchKeepsRecordsOutsideWindow(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"err":null,"data":{"items":[
			{"event_id":"inside","timestamp":"1792749600"},
			{"event_id":"outside","timestamp":"1792000000"}
		],"total":2}}`)
	})
	c := newTestConnector(t, handler)
	start := time.Unix(1792740000, 0).UTC()
	end := time.Unix(1792750000, 0).UTC()
	page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 {
		t.Fatalf("records = %d", len(page.Records))
	}
	if !strings.Contains(string(page.Records[0].Raw), "inside") {
		t.Fatalf("wrong record kept: %s", page.Records[0].Raw)
	}
}

func TestNormalizeAcceptsNumericAttackType(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(`{"event_id":"a","timestamp":"1792749600","attack_type":5,"risk_level":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if alert.AlertType != "5" || alert.Title != "5" {
		t.Fatalf("numeric attack type was not preserved: %q/%q", alert.AlertType, alert.Title)
	}
	if alert.Severity != model.SeverityMedium {
		t.Fatalf("severity = %v", alert.Severity)
	}
}

func TestFetchStopsAfterWindowWithoutServerTimeFilter(t *testing.T) {
	var calls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["timestamp__gte"]; ok {
			fmt.Fprint(w, `{"err":"invalid_filter_key","data":null}`)
			return
		}
		calls.Add(1)
		fmt.Fprint(w, `{"err":null,"data":{"items":[{"event_id":"old","timestamp":"1792000000"}],"total":10000}}`)
	})
	c := newTestConnector(t, handler)
	start := time.Unix(1792740000, 0).UTC()
	end := time.Unix(1792750000, 0).UTC()

	page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 0 {
		t.Fatalf("records = %d", len(page.Records))
	}
	if page.NextToken != "" {
		t.Fatal("pagination must stop once the window has been passed")
	}
	if calls.Load() != 1 {
		t.Fatalf("unfiltered calls = %d", calls.Load())
	}
}

func TestFetchPaginatesWhenTotalIsMissing(t *testing.T) {
	var calls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			fmt.Fprint(w, `{"err":null,"data":{"items":[{"event_id":"a","timestamp":"1792749600"}]}}`)
			return
		}
		fmt.Fprint(w, `{"err":null,"data":{"items":[]}}`)
	})
	c := newTestConnector(t, handler)
	start := time.Unix(1792740000, 0).UTC()
	end := time.Unix(1792750000, 0).UTC()

	first, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.NextToken == "" {
		t.Fatal("a full page without data.total must continue paginating")
	}
	if first.Total != 1 {
		t.Fatalf("total fallback = %d", first.Total)
	}

	second, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1, Token: first.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	if second.NextToken != "" {
		t.Fatal("an empty page must end pagination")
	}
}

func TestFetchClassifiesUnauthorized(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"err":"unauthorized"}`)
	})
	c := newTestConnector(t, handler)
	_, err := c.Fetch(context.Background(), connector.Query{Start: time.Now().Add(-time.Hour), End: time.Now()})
	if err == nil || !connector.AuthError(err) {
		t.Fatalf("error = %v (auth classified: %v)", err, connector.AuthError(err))
	}
}
