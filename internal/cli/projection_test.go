package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
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
	if Run([]string{"groups", "--describe"}, &stdout, &stderr) != 0 {
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
	for _, command := range description.Commands {
		if command.ResponseSchema == nil {
			t.Fatalf("missing schema for %s", command.Name)
		}
		if command.Name != "component" && command.Name != "health" && command.ResponseSchema["properties"] == nil {
			t.Fatalf("no response fields documented for %s", command.Name)
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
