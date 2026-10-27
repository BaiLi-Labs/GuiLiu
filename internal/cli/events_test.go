package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestEventAllUsesCursorOnlyAndStopsWithoutSkipping(t *testing.T) {
	for _, maxItems := range []string{"3", "5"} {
		t.Run(maxItems, func(t *testing.T) {
			requests := 0
			code, output, diagnostic := runCLI(t, []string{"events", "--account", "source", "--since", "24h", "--limit", "2", "--all", "--max-items", maxItems, "--ndjson", "--fields", "id,evidence.id"}, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/api/v1/events/search" || r.Header.Get("X-Guiliu-Client") != "cli" {
					t.Error("event command did not use shared REST endpoint")
				}
				var q map[string]any
				if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
					t.Fatal(err)
				}
				requests++
				if requests == 1 {
					if q["since"] != "24h" || q["limit"] != float64(2) {
						t.Error("missing query filters")
					}
					fmt.Fprint(w, `{"events":[{"id":"one","evidence":{"id":"doc-one"}},{"id":"two","evidence":{"id":"doc-two"}}],"has_more":true,"next_cursor":"sealed-next","query":{"limit":2,"start":"2026-10-01","end":"2026-10-02"},"coverage":{"execution_complete":true},"total":{"value":3,"relation":"eq"}}`)
				} else {
					if len(q) != 2 || q["account_id"] != "source" || q["cursor"] != "sealed-next" {
						t.Errorf("continuation changed pinned query: %v", q)
					}
					fmt.Fprint(w, `{"events":[{"id":"three","evidence":{"id":"doc-three"}}],"has_more":false,"next_cursor":"","query":{"limit":2},"coverage":{"execution_complete":true},"total":{"value":3,"relation":"eq"}}`)
				}
			})
			if code != 0 || !strings.Contains(output, "doc-two") {
				t.Fatalf("events: %d %s %s", code, output, diagnostic)
			}
			if maxItems == "3" && (requests != 1 || !strings.Contains(diagnostic, "sealed-next") || strings.Contains(output, "three")) {
				t.Fatal("budget stop skipped part of a page")
			}
			if maxItems == "5" && (requests != 2 || !strings.Contains(output, "doc-three")) {
				t.Fatal("cursor pagination failed")
			}
		})
	}
}

func TestEventRawPreservesLargeIntegersAndReportsChanged(t *testing.T) {
	code, output, diagnostic := runCLI(t, []string{"event", "--account", "source", "--index", "logs-0001", "--id", "doc-one", "--raw"}, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"raw":{"request_id":9007199254740993},"raw_hash":"synthetic-hash","changed":true,"hash_compared":true}`)
	})
	if code != 0 || strings.TrimSpace(output) != `{"request_id":9007199254740993}` || !strings.Contains(diagnostic, "changed=true") {
		t.Fatalf("evidence: %d %s %s", code, output, diagnostic)
	}
}

func TestIncompleteEventQueryFailsAfterEmittingExplicitMetadata(t *testing.T) {
	code, output, diagnostic := runCLI(t, []string{"events", "--account", "source", "--json"}, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"events":[],"coverage":{"execution_complete":false,"timed_out":true,"failed_shards":1}}`)
	})
	if code != 1 || !strings.Contains(output, `"execution_complete":false`) || !strings.Contains(diagnostic, "incomplete") {
		t.Fatalf("partial query appeared successful: %d %s %s", code, output, diagnostic)
	}
}
