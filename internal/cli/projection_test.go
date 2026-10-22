package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNDJSONProjectionPreservesNestedFieldsAndExactNumbers(t *testing.T) {
	calls := 0
	code, stdout, stderr := runCLI(t, []string{"alerts", "--all", "--ndjson", "--fields", "id,resource.id,occurrence_count,ocsf,evidences,source_country", "--limit", "1"}, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 2 && r.URL.Query().Get("snapshot_sequence") != "42" {
			t.Error("snapshot was not pinned")
		}
		if calls == 1 {
			_, _ = w.Write([]byte(`{"alerts":[{"id":"first","resource":{"id":"ins-synthetic","name":"not-selected"},"occurrence_count":9007199254740993,"ocsf":{"exact":9007199254740993},"evidences":[{"type":"synthetic","data":{"large":9007199254740993,"exponent":1.25e+8}}]}],"total":2,"limit":1,"offset":0,"has_more":true,"snapshot_sequence":42,"window":{"start":"2026-10-20T00:00:00Z","end":"2026-10-21T00:00:00Z"}}`))
		} else {
			_, _ = w.Write([]byte(`{"alerts":[{"id":"second","resource":{"id":"ins-2"}}],"total":2,"limit":1,"offset":1,"has_more":false,"snapshot_sequence":42,"window":{"start":"2026-10-20T00:00:00Z","end":"2026-10-21T00:00:00Z"}}`))
		}
	})
	if code != 0 || calls != 2 {
		t.Fatalf("%d %d %s", code, calls, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `9007199254740993`) || strings.Contains(stdout, "not-selected") || !strings.Contains(lines[0], `"source_country":null`) || !strings.Contains(lines[1], `"occurrence_count":null`) {
		t.Fatalf("projection: %s", stdout)
	}
	if !strings.Contains(lines[0], `"large":9007199254740993`) || !strings.Contains(lines[0], `"exponent":1.25e+8`) {
		t.Fatalf("evidence precision changed: %s", lines[0])
	}
	var first struct {
		Resource map[string]string `json:"resource"`
	}
	if json.Unmarshal([]byte(lines[0]), &first) != nil || first.Resource["id"] != "ins-synthetic" || len(first.Resource) != 1 {
		t.Fatalf("nested output=%s", lines[0])
	}
	if !strings.Contains(stderr, "UTC") || !strings.Contains(stderr, "snapshot 42") {
		t.Fatalf("metadata: %s", stderr)
	}
}

func TestNDJSONProjectionRejectsUnknownPathsBeforeRequest(t *testing.T) {
	for _, fields := range []string{"nope", "resource.nope", "id,", "resource,resource.id", "observables.value", "ocsf.unknown"} {
		t.Run(fields, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, []string{"alerts", "--ndjson", "--fields", fields}, func(http.ResponseWriter, *http.Request) { t.Fatal("request sent for invalid projection") })
			if code != 2 || stdout != "" || !strings.Contains(stderr, "JSON field path") {
				t.Fatalf("%d %s %s", code, stdout, stderr)
			}
		})
	}
}

func TestDescribeDocumentsResponseFieldsAndConditionalSummary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if Run([]string{"groups", "--describe", "--schema"}, &stdout, &stderr) != 0 {
		t.Fatal(stderr.String())
	}
	var description describeOutput
	if err := json.Unmarshal(stdout.Bytes(), &description); err != nil {
		t.Fatal(err)
	}
	props := description.Command.ResponseSchema["properties"].(map[string]any)
	if !strings.Contains(props["summary"].(map[string]any)["description"].(string), "null for signature") {
		t.Fatal("summary condition missing")
	}
	item := description.Command.NDJSONSchema["properties"].(map[string]any)
	for _, field := range []string{"finding_count", "revision_count", "max_severity", "top_titles", "key"} {
		if item[field] == nil {
			t.Fatalf("missing %s", field)
		}
	}
	if item["count"] != nil || item["samples"] != nil {
		t.Fatal("invented group fields")
	}
	stdout.Reset()
	if Run([]string{"describe"}, &stdout, &stderr) != 0 {
		t.Fatal(stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), &description); err != nil {
		t.Fatal(err)
	}
	if len(stdout.Bytes()) > 16000 {
		t.Fatalf("discovery expanded to %d bytes", stdout.Len())
	}
	for _, command := range description.Commands {
		if command.ResponseSchema != nil || len(command.Flags) != 0 {
			t.Fatalf("eager details for %s", command.Name)
		}
		stdout.Reset()
		if Run([]string{command.Name, "--describe"}, &stdout, &stderr) != 0 {
			t.Fatal(stderr.String())
		}
		var one describeOutput
		if err := json.Unmarshal(stdout.Bytes(), &one); err != nil {
			t.Fatal(err)
		}
		if one.Command.ResponseSchema != nil {
			t.Fatal("full schema must be opt-in")
		}
		if command.Name != "component" && command.Name != "health" && len(one.Command.ResponseFields) == 0 {
			t.Fatalf("no response fields for %s", command.Name)
		}
	}
}

func TestCLIStatsForwardsBoundedOptionsAndSnapshot(t *testing.T) {
	code, stdout, stderr := runCLI(t, []string{"stats", "--top-by", "title,source_ip,severity_day", "--top-n", "3", "--snapshot-sequence", "7", "--json"}, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("top_by") != "title,source_ip,severity_day" || q.Get("top_n") != "3" || q.Get("snapshot_sequence") != "7" {
			t.Error(q)
		}
		_, _ = w.Write([]byte(`{"statistics":{"total":0}}`))
	})
	if code != 0 || stdout != "{\"statistics\":{\"total\":0}}\n" {
		t.Fatalf("%d %s %s", code, stdout, stderr)
	}
	for _, args := range [][]string{{"stats", "--top-n", "0"}, {"stats", "--top-n", "101"}, {"stats", "--top-by", "arbitrary"}} {
		code, _, stderr = runCLI(t, args, func(http.ResponseWriter, *http.Request) { t.Fatal("invalid stats sent") })
		if code != 2 {
			t.Fatalf("%d %s", code, stderr)
		}
	}
}

func TestContinuationResumesSameSnapshotWithExactWindowAndFilters(t *testing.T) {
	for _, command := range []string{"alerts", "groups"} {
		t.Run(command, func(t *testing.T) {
			t.Setenv("GUILIU_API_KEY", "synthetic-key")
			calls := 0
			start, end := "2026-10-20T01:02:03.123456789Z", "2026-10-21T01:02:03.987654321Z"
			handler := func(w http.ResponseWriter, r *http.Request) {
				calls++
				q := r.URL.Query()
				if q.Get("provider") != "tencent" || q.Get("vendor_title") != " Exact Title " || q.Get("sort") != "id" {
					t.Error(q)
				}
				if calls > 1 && (q.Get("snapshot_sequence") != "42" || q.Get("asset_snapshot_sequence") != "9" || q.Get("start") != start || q.Get("end") != end || q.Get("offset") != "1") {
					t.Errorf("resume changed identity: %v", q)
				}
				field := "alerts"
				if command == "groups" {
					field = "groups"
				}
				items := []any{map[string]any{"id": "original-1"}, map[string]any{"id": "original-2"}}
				offset := 0
				if calls > 1 {
					items = items[1:]
					offset = 1
				}
				// A new upstream record exists between calls; only snapshot 42
				// retains the original two IDs. Assert the request, not wording.
				_ = json.NewEncoder(w).Encode(map[string]any{field: items, "total": 2, "offset": offset, "limit": len(items), "has_more": calls == 1, "snapshot_sequence": 42, "asset_snapshot_sequence": 9, "group_by": "asset", "window": map[string]any{"start": start, "end": end}})
			}
			server := httptest.NewServer(http.HandlerFunc(handler))
			defer server.Close()
			t.Setenv("GUILIU_URL", server.URL)
			var stdout, stderr bytes.Buffer
			args := []string{command, "--provider", "tencent", "--vendor-title", " Exact Title ", "--sort", "id", "--all", "--max-items", "1", "--limit", "2", "--ndjson"}
			if Run(args, &stdout, &stderr) != 0 {
				t.Fatal(stderr.String())
			}
			var next struct {
				Args []string `json:"args"`
			}
			for _, line := range strings.Split(stderr.String(), "\n") {
				if strings.HasPrefix(line, "continuation: ") {
					if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "continuation: ")), &next); err != nil {
						t.Fatal(err)
					}
				}
			}
			if len(next.Args) == 0 {
				t.Fatal("no resume checkpoint")
			}
			stderr.Reset()
			if Run(next.Args, &stdout, &stderr) != 0 || calls != 2 {
				t.Fatalf("resume: %d %s", calls, stderr.String())
			}
			if len(strings.Split(strings.TrimSpace(stdout.String()), "\n")) != 2 {
				t.Fatal(stdout.String())
			}
		})
	}
}

func TestSchemaIsExplicitAndDocumentsSourceOccurrenceSemantics(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if Run([]string{"alerts", "--schema"}, &stdout, &stderr) != 2 {
		t.Fatal("schema silently ignored")
	}
	stdout.Reset()
	stderr.Reset()
	if Run([]string{"alerts", "--describe", "--schema"}, &stdout, &stderr) != 0 {
		t.Fatal(stderr.String())
	}
	var out describeOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	props := out.Command.NDJSONSchema["properties"].(map[string]any)
	for _, key := range []string{"occurrence_count", "occurrence_scope"} {
		if props[key].(map[string]any)["description"] == nil {
			t.Fatalf("missing source semantics: %s", key)
		}
	}
}
