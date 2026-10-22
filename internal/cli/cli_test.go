package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const alertFixture = `{"alerts":[{"id":"a1","provider":"tencent","account_id":"acc","account_name":"prod","title":"One","severity":"high","status":"open","event_time":"2026-10-21T00:00:00Z","source_ip":"203.0.113.9","resource":{"id":"ins-1","name":"web-1","type":"host"},"revision":1},{"id":"a2","provider":"tencent","account_id":"acc","title":"Two","severity":"medium","status":"open","event_time":"2026-10-20T23:00:00Z","resource":{"id":"ins-2","name":"web-2","type":"host"},"revision":2}],"total":2,"limit":2,"offset":0,"snapshot_sequence":10,"next_cursor":"","has_more":false,"window":{"start":"2026-10-20T00:00:00Z","end":"2026-10-21T00:00:00Z"}}`

func runCLI(t *testing.T, args []string, handler http.HandlerFunc) (int, string, string) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Setenv("GUILIU_URL", server.URL)
	t.Setenv("GUILIU_API_KEY", "glk_test")
	t.Setenv("GUILIU_API_KEY_FILE", "")
	t.Setenv("GUILIU_TIMEOUT", "")
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestQueryJSONIsExactRESTBodyAndUsesAgentWindow(t *testing.T) {
	var start, end string
	code, stdout, stderr := runCLI(t, []string{"alerts", "--since", "24h", "--limit", "2", "--json"}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/alerts" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer glk_test" {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("X-Guiliu-Client"); got != "cli" {
			t.Errorf("client header = %q", got)
		}
		query := r.URL.Query()
		if query.Get("limit") != "2" || query.Get("since") != "" {
			t.Errorf("unexpected query: %s", r.URL.RawQuery)
		}
		start, end = query.Get("start"), query.Get("end")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(alertFixture))
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if strings.TrimSpace(stdout) != strings.TrimSpace(alertFixture) {
		t.Fatalf("JSON was rewritten:\n%s", stdout)
	}
	if start == "" || end == "" {
		t.Fatal("CLI did not resolve an absolute window")
	}
	startAt, err := time.Parse(time.RFC3339Nano, start)
	if err != nil {
		t.Fatal(err)
	}
	endAt, err := time.Parse(time.RFC3339Nano, end)
	if err != nil {
		t.Fatal(err)
	}
	if endAt.Sub(startAt) != 24*time.Hour {
		t.Fatalf("window = %s .. %s", startAt, endAt)
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %s", stderr)
	}
}

func TestQueryFieldsExposeResourceAndSourceFacts(t *testing.T) {
	body := `{"alerts":[{"id":"a1","provider":"tencent","title":"One","severity":"high","status":"open","event_time":"2026-10-21T00:00:00Z","resource":{"id":"ins-1","name":"web-01","type":"host","account_uid":"1250000000","source":"vendor_declared","declared_name":"示例主机"},"source_country":"中国","response_action":"BlockAttackIP","revision":1}],"total":1,"limit":1,"offset":0,"snapshot_sequence":1,"has_more":false,"window":{"start":"2026-10-20T00:00:00Z","end":"2026-10-21T00:00:00Z"}}`
	code, stdout, stderr := runCLI(t, []string{"alerts", "--since", "24h", "--fields", "resource,resource_source,resource_declared_name,resource_account,source_country,response_action"}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"RESOURCE_SOURCE", "RESOURCE_DECLARED_NAME", "vendor_declared", "示例主机", "1250000000", "中国", "BlockAttackIP"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("missing %q in output:\n%s", want, stdout)
		}
	}
}

func TestQueryAllFollowsOffsetAndPinsSnapshot(t *testing.T) {
	firstWindow := "2026-10-20T00:00:00Z|2026-10-21T00:00:00Z"
	requests := 0
	code, stdout, stderr := runCLI(t, []string{"alerts", "--since", "7d", "--limit", "2", "--all", "--ndjson"}, func(w http.ResponseWriter, r *http.Request) {
		requests++
		query := r.URL.Query()
		switch query.Get("offset") {
		case "0":
			_, _ = w.Write([]byte(`{"alerts":[{"id":"a1","title":"One","severity":"high","status":"open","provider":"tencent","event_time":"2026-10-21T00:00:00Z"},{"id":"a2","title":"Two","severity":"low","status":"open","provider":"tencent","event_time":"2026-10-20T00:00:00Z"}],"total":3,"limit":2,"offset":0,"snapshot_sequence":10,"has_more":true,"next_cursor":"a2","window":{"start":"2026-10-20T00:00:00Z","end":"2026-10-21T00:00:00Z"}}`))
		case "2":
			if got := query.Get("snapshot_sequence"); got != "10" {
				t.Errorf("snapshot_sequence = %q", got)
			}
			if got := query.Get("start") + "|" + query.Get("end"); got != firstWindow {
				t.Errorf("window changed between pages: %q != %q", got, firstWindow)
			}
			_, _ = w.Write([]byte(`{"alerts":[{"id":"a3","title":"Three","severity":"medium","status":"open","provider":"tencent","event_time":"2026-10-19T00:00:00Z"}],"total":3,"limit":2,"offset":2,"snapshot_sequence":10,"has_more":false,"next_cursor":"","window":{"start":"2026-10-20T00:00:00Z","end":"2026-10-21T00:00:00Z"}}`))
		default:
			t.Errorf("unexpected offset %q", query.Get("offset"))
		}
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if requests != 2 {
		t.Fatalf("requests = %d", requests)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d: %s", len(lines), stdout)
	}
	for i, want := range []string{"a1", "a2", "a3"} {
		var item map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &item); err != nil {
			t.Fatal(err)
		}
		if item["id"] != want {
			t.Fatalf("line %d id = %v, want %s", i, item["id"], want)
		}
	}
	if !strings.Contains(stderr, "3 alert(s) of 3") || !strings.Contains(stderr, "snapshot 10") {
		t.Fatalf("stderr = %s", stderr)
	}
}

func TestQueryAPIErrorExitsOneAndHintsAuth(t *testing.T) {
	code, stdout, stderr := runCLI(t, []string{"alerts", "--json"}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"unauthorized","message":"authentication required"}}`))
	})
	if code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if stdout != "" {
		t.Fatalf("stdout = %s", stdout)
	}
	if !strings.Contains(stderr, "unauthorized") || !strings.Contains(stderr, "hint:") {
		t.Fatalf("stderr = %s", stderr)
	}
}

func TestQueryDescribeIsMachineReadable(t *testing.T) {
	t.Setenv("GUILIU_URL", "http://127.0.0.1:1")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"describe"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	var all describeOutput
	if err := json.Unmarshal(stdout.Bytes(), &all); err != nil {
		t.Fatal(err)
	}
	if len(all.Commands) < 10 {
		t.Fatalf("commands = %d", len(all.Commands))
	}
	var alerts *commandInfo
	for i := range all.Commands {
		if all.Commands[i].Name == "alerts" {
			alerts = &all.Commands[i]
		}
	}
	if alerts == nil {
		t.Fatal("alerts command missing")
	}
	if all.Limits.MaxRange != "90d" || all.Limits.GroupWindow != "24h" {
		t.Fatalf("limits = %+v", all.Limits)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"alerts", "--describe"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	var one describeOutput
	if err := json.Unmarshal(stdout.Bytes(), &one); err != nil {
		t.Fatal(err)
	}
	if one.Command == nil || one.Command.Name != "alerts" {
		t.Fatalf("command = %+v", one.Command)
	}
}

func TestQueryUsageErrors(t *testing.T) {
	t.Setenv("GUILIU_URL", "http://127.0.0.1:1")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"all with json", []string{"alerts", "--json", "--all"}, "--all requires table or --ndjson"},
		{"wide window", []string{"alerts", "--start", "2026-01-01", "--end", "2026-06-01"}, "time range exceeds"},
		{"bad field", []string{"alerts", "--fields", "nope"}, "unknown field"},
		{"fields with json", []string{"alerts", "--fields", "id", "--json"}, "--fields supports table or --ndjson"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(tc.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr = %s", stderr.String())
			}
		})
	}
}

func TestQueryRawPrintsExactBytes(t *testing.T) {
	code, stdout, stderr := runCLI(t, []string{"alert", "a1", "--raw", "--revision", "2"}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/alerts/a1/raw" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("revision"); got != "2" {
			t.Errorf("revision = %q", got)
		}
		_, _ = w.Write([]byte(`{"vendor":"exact"}`))
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if stdout != "{\"vendor\":\"exact\"}\n" {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestQueryComponentRaw(t *testing.T) {
	code, stdout, stderr := runCLI(t, []string{"component", "as1", "--revision", "2", "--component", "runtime"}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assets/as1/revisions/2/components/runtime/raw" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"exact":true}`))
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if stdout != "{\"exact\":true}\n" {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestQueryProvidersMappingAndFailures(t *testing.T) {
	code, stdout, stderr := runCLI(t, []string{"providers", "--ndjson"}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/providers" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"providers":[{"id":"tencent","name":"Tencent Cloud","vendor":"Tencent","product":"CSIP","mapper_version":"tencent/v1","api_version":"3.0","source_api":"CSIP DescribeAlertList"}]}`))
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if !strings.HasPrefix(stdout, "{") {
		t.Fatalf("NDJSON must start with a record, got %q", stdout)
	}
	if lines := strings.Split(strings.TrimSpace(stdout), "\n"); len(lines) != 1 || !strings.Contains(lines[0], `"tencent"`) {
		t.Fatalf("providers = %s", stdout)
	}

	code, stdout, stderr = runCLI(t, []string{"mapping", "--provider", "tencent", "--ndjson"}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/providers/tencent/mapping" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"provider":"tencent","mapper_version":"tencent/v1","fields":[{"field":"title","source_paths":["/Name"],"transform":""}]}`))
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, `"field":"title"`) {
		t.Fatalf("mapping = %s", stdout)
	}

	code, stdout, stderr = runCLI(t, []string{"failures", "--account", "acc", "--ndjson"}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/accounts/acc/failures" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"failures":[{"id":"f1","account_id":"acc","raw":{"bad":true},"error":"mapping failed","attempts":2,"mapper_version":"tencent/v1","created_at":"2026-10-21T00:00:00Z","last_attempt_at":"2026-10-21T01:00:00Z"}],"total":1,"limit":100}`))
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, `"id":"f1"`) {
		t.Fatalf("failures = %s", stdout)
	}
}

func TestQueryChangesFollowsCursor(t *testing.T) {
	code, stdout, stderr := runCLI(t, []string{"changes", "--limit", "1", "--all", "--ndjson"}, func(w http.ResponseWriter, r *http.Request) {
		cursor := r.URL.Query().Get("cursor")
		switch cursor {
		case "":
			_, _ = w.Write([]byte(`{"changes":[{"sequence":1,"alert_id":"a1","provider":"tencent","account_id":"acc","change_type":"created","revision":1,"captured_at":"2026-10-21T00:00:00Z","projection_updated":true}],"next_cursor":"1","has_more":true}`))
		case "1":
			_, _ = w.Write([]byte(`{"changes":[{"sequence":2,"alert_id":"a2","provider":"tencent","account_id":"acc","change_type":"updated","revision":2,"captured_at":"2026-10-21T01:00:00Z","projection_updated":false}],"next_cursor":"2","has_more":false}`))
		default:
			t.Errorf("unexpected cursor %q", cursor)
		}
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d: %s", len(lines), stdout)
	}
	if !strings.Contains(stderr, "next_cursor 2") {
		t.Fatalf("stderr = %s", stderr)
	}
}

func TestQueryGroupsFollowsOffsetAndPinsSnapshot(t *testing.T) {
	code, stdout, stderr := runCLI(t, []string{"groups", "--since", "24h", "--limit", "2", "--all", "--ndjson"}, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		switch query.Get("offset") {
		case "0":
			_, _ = w.Write([]byte(`{"groups":[{"id":"g1","group_by":"type_asset","key":{"provider":"tencent"},"title":"One","finding_count":2,"revision_count":1,"max_severity":"high","last_seen_at":"2026-10-21T00:00:00Z"},{"id":"g2","group_by":"type_asset","key":{"provider":"tencent"},"title":"Two","finding_count":1,"revision_count":0,"max_severity":"low","last_seen_at":"2026-10-20T00:00:00Z"}],"total":3,"limit":2,"offset":0,"snapshot_sequence":5,"asset_snapshot_sequence":0,"window":{"start":"2026-10-20T00:00:00Z","end":"2026-10-21T00:00:00Z"},"group_by":"type_asset"}`))
		case "2":
			if query.Get("asset_snapshot_sequence") != "0" {
				t.Errorf("asset watermark missing: %s", query.Get("asset_snapshot_sequence"))
			}
			if query.Get("snapshot_sequence") != "5" {
				t.Errorf("snapshot = %q", query.Get("snapshot_sequence"))
			}
			_, _ = w.Write([]byte(`{"groups":[{"id":"g3","group_by":"type_asset","key":{"provider":"tencent"},"title":"Three","finding_count":1,"revision_count":0,"max_severity":"medium","last_seen_at":"2026-10-19T00:00:00Z"}],"total":3,"limit":2,"offset":2,"snapshot_sequence":5,"asset_snapshot_sequence":0,"window":{"start":"2026-10-20T00:00:00Z","end":"2026-10-21T00:00:00Z"},"group_by":"type_asset"}`))
		default:
			t.Errorf("unexpected offset %q", query.Get("offset"))
		}
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if lines := strings.Split(strings.TrimSpace(stdout), "\n"); len(lines) != 3 {
		t.Fatalf("lines = %d: %s", len(lines), stdout)
	}
}

func TestQueryBaseURLPrefixAndAPIKeyFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, []byte("glk_file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/guiliu/api/v1/alerts" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer glk_file" {
			t.Errorf("authorization = %q", got)
		}
		_, _ = w.Write([]byte(alertFixture))
	}))
	t.Cleanup(server.Close)
	t.Setenv("GUILIU_URL", server.URL+"/guiliu")
	t.Setenv("GUILIU_API_KEY", "")
	t.Setenv("GUILIU_API_KEY_FILE", "")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--api-key-file", keyPath, "alerts", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestQueryTableAndEmptyResult(t *testing.T) {
	code, stdout, stderr := runCLI(t, []string{"alerts", "--limit", "2"}, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(alertFixture))
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stdout, "EVENT_TIME") || !strings.Contains(stdout, "a1") || !strings.Contains(stdout, "a2") {
		t.Fatalf("table = %s", stdout)
	}
	if !strings.Contains(stderr, "2 alert(s) of 2") {
		t.Fatalf("stderr = %s", stderr)
	}

	code, stdout, stderr = runCLI(t, []string{"alerts", "--json"}, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"alerts":[],"total":0,"limit":20,"offset":0,"snapshot_sequence":1,"has_more":false,"window":{"start":"2026-10-20T00:00:00Z","end":"2026-10-21T00:00:00Z"}}`))
	})
	if code != 0 || !strings.Contains(stdout, `"alerts":[]`) {
		t.Fatalf("exit = %d, stdout = %s, stderr = %s", code, stdout, stderr)
	}
}

func TestQueryAssetsFollowNextCursor(t *testing.T) {
	code, stdout, stderr := runCLI(t, []string{"assets", "--limit", "1", "--all", "--ndjson"}, func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("after_id")
		switch after {
		case "":
			_, _ = w.Write([]byte(`{"assets":[{"id":"as1","provider":"tencent","account_id":"acc","account_uid":"u","region":"r","resource_id":"ins-1","resource_type":"cvm","name":"web","public_ips":[],"private_ips":["10.0.0.1"],"security_group_ids":[],"tags":[],"components":{},"provenance":{},"observed_at":"2026-10-21T00:00:00Z","last_observed_at":"2026-10-21T00:00:00Z","revision":1,"synthetic":false}],"has_more":true,"next_cursor":"as1","limit":1}`))
		case "as1":
			_, _ = w.Write([]byte(`{"assets":[{"id":"as2","provider":"tencent","account_id":"acc","account_uid":"u","region":"r","resource_id":"ins-2","resource_type":"cvm","name":"db","public_ips":[],"private_ips":[],"security_group_ids":[],"tags":[],"components":{},"provenance":{},"observed_at":"2026-10-21T00:00:00Z","last_observed_at":"2026-10-21T00:00:00Z","revision":1,"synthetic":false}],"has_more":false,"next_cursor":"","limit":1}`))
		default:
			t.Errorf("unexpected after_id %q", after)
		}
	})
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d: %s", len(lines), stdout)
	}
	if !strings.Contains(lines[1], "as2") {
		t.Fatalf("second asset missing: %s", lines[1])
	}
}

func TestExpandNetworkGroupPreservesExactKeyTitleAndWatermarks(t *testing.T) {
	key := `{"provider":"tencent","account_uid":"synthetic","region":"region","resource_type":"security_group","resource_id":"sg-synthetic"}`
	code, _, stderr := runCLI(t, []string{"alerts", "--group-by", "security_group", "--group-key", key, "--snapshot-sequence", "10", "--asset-snapshot-sequence", "0", "--vendor-title", " Exact title ", "--json"}, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("group_key") != key || q.Get("vendor_title") != " Exact title " || q.Get("asset_snapshot_sequence") != "0" || q.Get("snapshot_sequence") != "10" {
			t.Errorf("changed group selection: %s", r.URL.RawQuery)
		}
		w.Write([]byte(alertFixture))
	})
	if code != 0 {
		t.Fatal(stderr)
	}
}
