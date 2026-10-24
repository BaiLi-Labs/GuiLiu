package safelinece

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

const sampleRecord = `{
  "id": 123,
  "event_id": "evt-abc",
  "timestamp": 1792749600,
  "created_at": "2026-10-23 10:00:00",
  "updated_at": "2026-10-23 10:05:00",
  "action": 1,
  "attack_type": 5,
  "risk_level": 3,
  "reason": "SQL注入攻击",
  "module": "semantic",
  "policy_name": "默认策略",
  "src_ip": "203.0.113.10",
  "dst_ip": "10.0.0.5",
  "src_port": 51515,
  "dst_port": 443,
  "host": "app.example.test",
  "url_path": "/login",
  "method": "POST",
  "query_string": "next=/admin",
  "rule_id": "1001",
  "short_rule_id": "S1001",
  "ja4_fingerprint": "t13d1516h2",
  "status_code": 403,
  "country": "CN",
  "province": "示例省",
  "city": "示例市",
  "site_uuid": "site-1",
  "payload": "large body stays in raw"
}`

func TestNormalizeRecord(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(sampleRecord))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "evt-abc" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.Severity != model.SeverityUnknown {
		t.Fatalf("risk_level ordering is unpublished; got %v", alert.Severity)
	}
	if alert.OriginalSeverity != "3" {
		t.Fatalf("original severity = %q", alert.OriginalSeverity)
	}
	if alert.VendorStatus != "blocked" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	if alert.Title != "SQL注入攻击" || alert.AlertType != "5" {
		t.Fatalf("title/type = %q/%q", alert.Title, alert.AlertType)
	}
	if alert.RuleID != "1001" {
		t.Fatalf("rule id = %q", alert.RuleID)
	}
	if alert.SourceIP != "203.0.113.10" || alert.DestinationIP != "10.0.0.5" {
		t.Fatalf("ips = %q/%q", alert.SourceIP, alert.DestinationIP)
	}
	if alert.Resource.ID != "app.example.test" || alert.Resource.Type != "domain" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	want := time.Unix(1792749600, 0).UTC()
	if !alert.EventTime.Equal(want) {
		t.Fatalf("event time = %v want %v", alert.EventTime, want)
	}
	if len(alert.Observables) != 3 {
		t.Fatalf("observables = %+v", alert.Observables)
	}
	if !json.Valid(alert.Raw) {
		t.Fatal("raw payload was not preserved")
	}
	// Large bodies must not be duplicated into Unmapped.
	ce := alert.Unmapped["safeline_ce"].(map[string]any)
	if _, ok := ce["payload"]; ok {
		t.Fatal("large payload must stay in Raw only")
	}
}

// liveSample is a redacted record captured from SafeLine CE 9.4.3. It keeps the
// real wire types: created_at and timestamp are integers, not strings.
const liveSample = `{
  "site_uuid": "1",
  "src_ip": "203.0.113.10",
  "socket_ip": "203.0.113.10",
  "protocol": 0,
  "host": "app.example.test",
  "url_path": "/etc/passwd",
  "dst_port": 80,
  "country": "B1",
  "risk_level": 3,
  "action": 1,
  "rule_id": "m_rule/33e75ff09dd601bbe69f351039152189",
  "created_at": 1792855532,
  "rule_id_list": ["65702"],
  "EventId": "",
  "src_port": 0,
  "dst_ip": "",
  "method": "",
  "query_string": "",
  "status_code": 0,
  "event_id": "19f2563411384662bce8dbc2d341e905",
  "website": "http://app.example.test/etc/passwd",
  "attack_type": 14,
  "module": "m_rule",
  "reason": "访问系统文件的请求",
  "short_rule_id": "65702",
  "timestamp": 1792855531
}`

func TestNormalizeLiveSample(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(liveSample))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "19f2563411384662bce8dbc2d341e905" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.VendorStatus != "blocked" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	// The live payload reports created_at as epoch seconds; it must not be
	// mistaken for milliseconds.
	want := time.Unix(1792855531, 0).UTC()
	if !alert.EventTime.Equal(want) {
		t.Fatalf("event time = %v want %v", alert.EventTime, want)
	}
	if alert.OriginalTime != "1792855531" {
		t.Fatalf("original time = %q", alert.OriginalTime)
	}
	ce := alert.Unmapped["safeline_ce"].(map[string]any)
	if ce["module"] != "m_rule" || ce["action"] != "1" {
		t.Fatalf("unmapped = %+v", ce)
	}
}

func TestSeverityDerivationIsOptIn(t *testing.T) {
	alert, err := (&Connector{severityFrom: true}).Normalize(json.RawMessage(sampleRecord))
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

func TestActionLabels(t *testing.T) {
	for value, want := range map[string]string{"0": "allowed", "1": "blocked", "": "", "7": "7"} {
		if got := actionLabel(value); got != want {
			t.Fatalf("actionLabel(%q) = %q want %q", value, got, want)
		}
	}
}

func newTestConnector(t *testing.T, handler http.Handler) *Connector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(connector.AccountConfig{
		Options:    map[string]string{"endpoint": srv.URL},
		Credential: connector.Credential{AccessKeyID: "slce-token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c.(*Connector)
}

func TestFetchSendsContract(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/open/records" || r.Method != http.MethodGet {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-SLCE-API-TOKEN") != "slce-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		query := r.URL.Query()
		if query.Get("page") != "1" || query.Get("page_size") != "10" {
			t.Errorf("paging = %s/%s", query.Get("page"), query.Get("page_size"))
		}
		if query.Get("start") != "1792749600000" || query.Get("end") != "1792753200000" {
			t.Errorf("window = %s/%s", query.Get("start"), query.Get("end"))
		}
		fmt.Fprint(w, `{"err":"","msg":"","data":{"data":[{"event_id":"a"}],"total":1}}`)
	})
	c := newTestConnector(t, handler)
	start := time.Unix(1792749600, 0).UTC()
	end := start.Add(time.Hour)

	page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.NextToken != "" || page.Total != 1 {
		t.Fatalf("page = %+v", page)
	}
}

func TestFetchPaginatesByPage(t *testing.T) {
	var pages []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages = append(pages, r.URL.Query().Get("page"))
		fmt.Fprintf(w, `{"err":"","data":{"data":[{"event_id":"e%s"}],"total":2}}`, r.URL.Query().Get("page"))
	})
	c := newTestConnector(t, handler)
	start := time.Unix(1792749600, 0).UTC()
	end := start.Add(time.Hour)

	first, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.NextToken != "2" {
		t.Fatalf("first token = %q", first.NextToken)
	}
	second, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 1, Token: first.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	if second.NextToken != "" {
		t.Fatalf("second token = %q", second.NextToken)
	}
	if len(pages) != 2 || pages[0] != "1" || pages[1] != "2" {
		t.Fatalf("pages = %v", pages)
	}
}

func TestFetchClassifiesBusinessError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"err":"unauthorized","msg":"invalid token","data":null}`)
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
