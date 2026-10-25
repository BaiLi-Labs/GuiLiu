package cloudwalker

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
  "id": 154,
  "event_type": "webshell",
  "level": 4,
  "state": 1,
  "created_at": "2026-10-23 10:00:00",
  "updated_at": "2026-10-23 10:05:00",
  "host_id": 162,
  "host_ip": "10.0.0.5",
  "host_name": "web-01",
  "file_name": "shell.php",
  "file_path": "/var/www/html/shell.php",
  "webshell_type": "php",
  "comment": "",
  "description": "检测到 PHP Webshell"
}`

func TestNormalizeEvent(t *testing.T) {
	alert, err := (&Connector{eventType: "webshell_event"}).Normalize(json.RawMessage(sampleEvent))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "154" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.Severity != model.SeverityCritical || alert.OriginalSeverity != "4" {
		t.Fatalf("severity = %v/%q", alert.Severity, alert.OriginalSeverity)
	}
	if alert.Title != "shell.php" {
		t.Fatalf("title = %q", alert.Title)
	}
	if alert.Resource.ID != "10.0.0.5" || alert.Resource.Name != "web-01" || alert.Resource.Type != "host" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	if alert.Resource.Source != model.ResourceSourceVendorDeclared {
		t.Fatalf("resource source = %q", alert.Resource.Source)
	}
	want := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	if !alert.EventTime.Equal(want) {
		t.Fatalf("event time = %v", alert.EventTime)
	}
	if alert.Unmapped["cloudwalker"].(map[string]any)["mapping_unverified"] != true {
		t.Fatal("the mapping must be labelled unverified")
	}
	if !json.Valid(alert.Raw) {
		t.Fatal("raw payload was not preserved")
	}
}

func TestSeverityOrdering(t *testing.T) {
	for value, want := range map[string]model.Severity{
		"1": model.SeverityLow,
		"2": model.SeverityMedium,
		"3": model.SeverityHigh,
		"4": model.SeverityCritical,
		"9": model.SeverityUnknown,
	} {
		got, _ := severityOf(json.RawMessage(`"` + value + `"`))
		if got != want {
			t.Fatalf("severity(%s) = %v want %v", value, got, want)
		}
	}
}

func newTestConnector(t *testing.T, eventType string, handler http.Handler) *Connector {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(connector.AccountConfig{
		Options:    map[string]string{"endpoint": srv.URL, "event_type": eventType},
		Credential: connector.Credential{AccessKeyID: "api-key"},
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
		cookie, err := r.Cookie("API-Token")
		if err != nil || cookie.Value != "api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode: %v", err)
		}
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":"1","result":{"data":{"list":[{"id":1}],"total":1}}}`)
	})
	c := newTestConnector(t, "webshell_event", handler)
	start := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)

	page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.NextToken != "" {
		t.Fatalf("page = %+v", page)
	}
	if request.JSONRPC != "2.0" || request.Method != "WebshellEventService.GetEventList" {
		t.Fatalf("rpc envelope = %+v", request)
	}
	created, ok := request.Params["created_at"].([]any)
	if !ok || len(created) != 2 {
		t.Fatalf("created_at = %v", request.Params["created_at"])
	}
	if created[0] != "2026-10-23 10:00:00" || created[1] != "2026-10-23 11:00:00" {
		t.Fatalf("created_at = %v", created)
	}
	if request.Params["count"] != float64(20) || request.Params["offset"] != float64(0) {
		t.Fatalf("paging = %+v", request.Params)
	}
}

func TestEventFamilySelectsService(t *testing.T) {
	var method string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		method = request.Method
		fmt.Fprint(w, `{"jsonrpc":"2.0","result":{"events":[]}}`)
	})
	c := newTestConnector(t, "malware_event", handler)
	_, err := c.Fetch(context.Background(), connector.Query{
		Start: time.Now().Add(-time.Hour), End: time.Now(), PageSize: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if method != "MalwareEventService.GetEventList" {
		t.Fatalf("method = %q", method)
	}
}

func TestExtractEventsShapes(t *testing.T) {
	for name, result := range map[string]string{
		"array":       `[{"id":1}]`,
		"data list":   `{"data":[{"id":1}]}`,
		"nested list": `{"data":{"list":[{"id":1}],"total":9}}`,
		"events":      `{"events":[{"id":1}]}`,
		"records":     `{"records":[{"id":1}],"total_count":3}`,
	} {
		items, total, err := extractEvents(json.RawMessage(result))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(items) != 1 {
			t.Fatalf("%s: items = %d", name, len(items))
		}
		if name == "nested list" && total != 9 {
			t.Fatalf("nested total = %d", total)
		}
		if name == "records" && total != 3 {
			t.Fatalf("records total = %d", total)
		}
	}
}

func TestExtractEventsRejectsUnknownShape(t *testing.T) {
	if _, _, err := extractEvents(json.RawMessage(`{"unexpected":{}}`)); err == nil {
		t.Fatal("an unknown shape must fail loudly")
	}
}

func TestFetchClassifiesRPCError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"jsonrpc":"2.0","error":{"code":-32001,"message":"token expired"}}`)
	})
	c := newTestConnector(t, "webshell_event", handler)
	_, err := c.Fetch(context.Background(), connector.Query{
		Start: time.Now().Add(-time.Hour), End: time.Now(), PageSize: 10,
	})
	if err == nil || !connector.AuthError(err) {
		t.Fatalf("error = %v (auth classified: %v)", err, connector.AuthError(err))
	}
}

func TestNewRejectsUnknownEventType(t *testing.T) {
	_, err := New(connector.AccountConfig{
		Options:    map[string]string{"endpoint": "https://example.test", "event_type": "nope"},
		Credential: connector.Credential{AccessKeyID: "k"},
	})
	if err == nil {
		t.Fatal("an unsupported event family must be rejected at construction")
	}
}

func TestBareArrayPageDoesNotTruncateCollection(t *testing.T) {
	c := newTestConnector(t, "webshell_event", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			fmt.Fprint(w, `{"jsonrpc":"2.0","result":[{"id":1}]}`)
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
