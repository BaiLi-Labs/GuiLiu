package elasticsearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func makeConnector(t *testing.T, handler http.HandlerFunc, options map[string]string) *Connector {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	if options == nil {
		options = map[string]string{}
	}
	options["endpoint"] = server.URL
	if options["indices"] == "" {
		options["indices"] = "logs-web-*"
	}
	conn, err := New(connector.AccountConfig{AccountID: "test-source", Options: options, Credential: connector.Credential{AccessKeyID: "test-user", AccessKeySecret: "test-only-es-credential"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.(*Connector).Close() })
	return conn.(*Connector)
}

func readBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var body map[string]any
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

func eventHit(id string, n int) string {
	return fmt.Sprintf(`{"_index":"logs-web-000001","_id":%q,"_source":{"@timestamp":"2026-10-01T00:00:00.123456789Z","message":"synthetic request","source":{"ip":["198.51.100.10","2001:db8::1"]},"host.name":"web-test","user":{"name":"test-user"},"log":{"level":"WARN"},"request_id":9007199254740993},"sort":["2026-10-01T00:00:00.123456789Z",%d]}`, id, n)
}

func queryRequest() model.EventSearch {
	return model.EventSearch{AccountID: "test-source", Start: "2026-10-01T00:00:00Z", End: "2026-10-02T00:00:00Z", Limit: 2}
}

func TestPaginationUsesPinnedScopeAndLastEmittedSort(t *testing.T) {
	searches, closed := 0, ""
	c := makeConnector(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "ApiKey test-only-es-credential" {
			t.Error("missing source API key")
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/logs-web-*/_pit":
			if r.URL.Query().Get("keep_alive") != "2m" {
				t.Error("PIT keep_alive must be a query parameter")
			}
			fmt.Fprint(w, `{"id":"pit-first"}`)
		case r.Method == "POST" && r.URL.Path == "/_search":
			body := readBody(t, r)
			if body["size"].(json.Number).String() != "3" {
				t.Error("missing lookahead hit")
			}
			if searches == 0 {
				if body["pit"].(map[string]any)["id"] != "pit-first" {
					t.Error("wrong initial PIT")
				}
				if _, ok := body["search_after"]; ok {
					t.Error("unexpected initial cursor")
				}
				serialized, _ := json.Marshal(body["query"])
				for _, fragment := range []string{`"gte":"2026-10-01T00:00:00Z"`, `"match_phrase":{"message":"jndi"}`, `"term":{"host.name":"web-test"}`, `"term":{"http.response.status_code":"500"}`} {
					if !strings.Contains(string(serialized), fragment) {
						t.Errorf("query missing %s: %s", fragment, serialized)
					}
				}
				fmt.Fprintf(w, `{"pit_id":"pit-updated","_shards":{"failed":0},"hits":{"total":{"value":3,"relation":"eq"},"hits":[%s,%s,%s]}}`, eventHit("one", 1), eventHit("two", 2), eventHit("three", 3))
			} else {
				if body["pit"].(map[string]any)["id"] != "pit-updated" {
					t.Error("rotated PIT was not reused")
				}
				after := body["search_after"].([]any)
				if after[1].(json.Number).String() != "2" {
					t.Errorf("cursor skipped lookahead hit: %v", after)
				}
				fmt.Fprintf(w, `{"pit_id":"pit-final","_shards":{"failed":0},"hits":{"total":{"value":3,"relation":"eq"},"hits":[%s]}}`, eventHit("three", 3))
			}
			searches++
		case r.Method == "DELETE" && r.URL.Path == "/_pit":
			closed = readBody(t, r)["id"].(string)
			fmt.Fprint(w, `{"succeeded":true}`)
		default:
			t.Errorf("unexpected source request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}, nil)
	q := queryRequest()
	q.Keyword, q.Host, q.IP = "jndi", "web-test", "198.51.100.10"
	q.Filters = map[string]string{"http.response.status_code": "500"}
	first, err := c.SearchEvents(context.Background(), q, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !first.HasMore || len(first.Events) != 2 || closed != "" || !first.Coverage.ExecutionComplete {
		t.Fatalf("first page: %+v; closed=%s", first, closed)
	}
	e := first.Events[0]
	if e.EventTime == nil || e.EventTime.Nanosecond() != 123456789 || len(e.SourceIPs) != 2 || e.HostNames[0] != "web-test" || e.SourceSeverity != "WARN" {
		t.Fatalf("mapping: %+v", e)
	}
	last, err := c.SearchEvents(context.Background(), q, first.Continuation)
	if err != nil {
		t.Fatal(err)
	}
	if last.HasMore || len(last.Events) != 1 || last.Events[0].Evidence.ID != "three" || closed != "pit-final" {
		t.Fatalf("last page: %+v; closed=%s", last, closed)
	}
}

func TestIncompleteSearchCannotAdvanceCursor(t *testing.T) {
	closed := false
	c := makeConnector(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logs-web-*/_pit":
			fmt.Fprint(w, `{"id":"pit-partial"}`)
		case "/_pit":
			closed = true
			fmt.Fprint(w, `{}`)
		case "/_search":
			fmt.Fprintf(w, `{"timed_out":true,"_shards":{"failed":1},"hits":{"total":{"value":10,"relation":"gte"},"hits":[%s,%s,%s]}}`, eventHit("one", 1), eventHit("two", 2), eventHit("three", 3))
		}
	}, nil)
	p, err := c.SearchEvents(context.Background(), queryRequest(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Coverage.ExecutionComplete || p.HasMore || len(p.Continuation) != 0 || !closed || p.Total.Relation != "gte" {
		t.Fatalf("incomplete page: %+v; closed=%t", p, closed)
	}
}

func TestEvidenceStaysWithinAliasAndPreservesSourceNumbers(t *testing.T) {
	c := makeConnector(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/production-logs/_search" {
			t.Fatalf("evidence escaped configured alias: %s", r.URL)
		}
		body := readBody(t, r)
		raw, _ := json.Marshal(body)
		if !strings.Contains(string(raw), `"_index":"logs-web-000001"`) || !strings.Contains(string(raw), `"values":["one"]`) {
			t.Errorf("missing exact reference: %s", raw)
		}
		fmt.Fprintf(w, `{"hits":{"hits":[%s]}}`, eventHit("one", 1))
	}, map[string]string{"indices": "production-logs"})
	evidence, err := c.EventEvidence(context.Background(), model.EventReference{AccountID: "test-source", Index: "logs-web-000001", ID: "one", RawHash: strings.Repeat("0", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.Changed || !evidence.HashCompared || !strings.Contains(string(evidence.Raw), "9007199254740993") {
		t.Fatalf("evidence lost fidelity: %+v", evidence)
	}
	obj, _ := sourceObject(json.RawMessage(`{"b":9007199254740993,"a":1}`))
	reordered, _ := sourceObject(json.RawMessage(`{ "a":1, "b":9007199254740993 }`))
	if sourceHash(obj) != sourceHash(reordered) {
		t.Fatal("hash must ignore object key order and whitespace")
	}
}

func TestAuthenticationErrorsAreClassifiedAndRedacted(t *testing.T) {
	for _, tc := range []struct {
		status int
		kind   connector.ErrorKind
	}{{401, connector.KindAuth}, {403, connector.KindPermission}, {429, connector.KindThrottled}, {503, connector.KindTransient}, {400, connector.KindPermanent}} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			c := makeConnector(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, `{"error":"test-only-es-credential private log body"}`)
			}, nil)
			err := c.Check(context.Background())
			var ce *connector.Error
			if !errors.As(err, &ce) || ce.Kind != tc.kind || strings.Contains(err.Error(), "test-only-es-credential") || strings.Contains(err.Error(), "private log") {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
}

func TestBasicBearerAndRedirectBoundaries(t *testing.T) {
	for _, authType := range []string{"basic", "bearer"} {
		t.Run(authType, func(t *testing.T) {
			c := makeConnector(t, func(w http.ResponseWriter, r *http.Request) {
				if authType == "basic" {
					username, password, ok := r.BasicAuth()
					if !ok || username != "test-user" || password != "test-only-es-credential" {
						t.Error("Basic credential mismatch")
					}
				} else if r.Header.Get("Authorization") != "Bearer test-only-es-credential" {
					t.Error("Bearer mismatch")
				}
				fmt.Fprint(w, `{"hits":{"hits":[]}}`)
			}, map[string]string{"auth_type": authType})
			if err := c.Check(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
	followed := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
	defer target.Close()
	c := makeConnector(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}, nil)
	if c.Check(context.Background()) == nil || followed {
		t.Fatal("credential-bearing requests must not follow redirects")
	}
}

func TestConfigurationAndMappingAreExplicit(t *testing.T) {
	for _, options := range []map[string]string{
		{"endpoint": "http://user:password@es.example.com", "indices": "logs-*"},
		{"endpoint": "https://es.example.com", "indices": "logs-*/_delete_by_query"},
		{"endpoint": "https://es.example.com", "indices": "remote:logs-*"},
		{"endpoint": "https://es.example.com", "indices": "logs-*", "auth_type": "none"},
		{"endpoint": "https://es.example.com", "indices": "logs-*", "field_mapping": `{"verdict":"message"}`},
		{"endpoint": "https://es.example.com", "indices": "logs-*", "field_mapping": `{"event_time":""}`},
	} {
		if _, err := New(connector.AccountConfig{Options: options, Credential: connector.Credential{AccessKeySecret: "test-only-key"}}); err == nil {
			t.Errorf("accepted invalid config: %v", options)
		}
	}
	c := makeConnector(t, func(http.ResponseWriter, *http.Request) {}, map[string]string{"field_mapping": `{"event_time":"time","message":"text","host_names":"computer","source_ips":"ips"}`, "timestamp_format": "epoch_seconds"})
	e, err := c.normalize(hit{Index: "logs-test", ID: "one", Source: json.RawMessage(`{"time":1767225600,"text":"test","computer":"test-host","ips":["invalid","198.51.100.1"],"extra":"retained in source"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if e.EventTime == nil || !e.EventTime.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) || e.Message != "test" || len(e.SourceIPs) != 1 || len(e.MappingWarnings) == 0 || e.FieldSources["message"] != "text" {
		t.Fatalf("custom mapping: %+v", e)
	}
	if _, err := c.Normalize(json.RawMessage(`{}`)); err == nil {
		t.Fatal("events must not masquerade as Findings")
	}
}

func TestFieldCapabilitiesAndAggregationsExposeLimitations(t *testing.T) {
	c := makeConnector(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/logs-web-*/_field_caps":
			fmt.Fprint(w, `{"fields":{"host.name":{"keyword":{"searchable":true,"aggregatable":true}},"source.ip":{"ip":{"searchable":true,"aggregatable":true},"keyword":{"searchable":true,"aggregatable":false}}}}`)
		case "/logs-web-*/_pit":
			fmt.Fprint(w, `{"id":"pit-group"}`)
		case "/_pit":
			fmt.Fprint(w, `{}`)
		case "/_search":
			body := readBody(t, r)
			if body["aggs"] == nil {
				t.Error("aggregation not translated")
			}
			fmt.Fprint(w, `{"hits":{"total":{"value":50,"relation":"eq"},"hits":[]},"aggregations":{"groups":{"buckets":[{"key":"198.51.100.1","doc_count":30}],"sum_other_doc_count":20,"doc_count_error_upper_bound":2}}}`)
		}
	}, nil)
	fields, err := c.EventFields(context.Background())
	if err != nil || len(fields.Fields) != 2 || !fields.Fields[1].Conflicting || fields.Fields[1].Aggregatable {
		t.Fatalf("field caps: %+v %v", fields, err)
	}
	q := queryRequest()
	q.GroupBy, q.TopN = "source.ip", 1
	page, err := c.SearchEvents(context.Background(), q, nil)
	if err != nil || page.Aggregation.OtherDocumentCount != 20 || page.Aggregation.DocumentCountErrorBound != 2 {
		t.Fatalf("aggregation: %+v %v", page, err)
	}
}
