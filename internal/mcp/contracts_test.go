package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func toolJSON(t *testing.T, srv *Server, name string, args map[string]any) map[string]any {
	t.Helper()
	resp := call(t, srv, "tools/call", map[string]any{"name": name, "arguments": args})
	if resp.Error != nil {
		t.Fatal(resp.Error)
	}
	result := resp.Result.(map[string]any)
	if result["isError"] != false {
		t.Fatal(result)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(result["content"].([]map[string]any)[0]["text"].(string)), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGroupExpansionUsesAdvertisedKeyDefaultAndSnapshot(t *testing.T) {
	srv, rec := newTestServer(t)
	page := toolJSON(t, srv, "list_alert_groups", map[string]any{"group_by": "signature"})
	group := page["groups"].([]any)[0].(map[string]any)
	window := page["window"].(map[string]any)
	args := map[string]any{"group_by": page["group_by"], "group_key": group["key"], "start": window["start"], "end": window["end"], "snapshot_sequence": page["snapshot_sequence"]}
	if seq := page["asset_snapshot_sequence"]; seq != nil {
		args["asset_snapshot_sequence"] = seq
	}
	members := toolJSON(t, srv, "get_alert_group", args)
	props := srv.tools["get_alert_group"].InputSchema["properties"].(map[string]any)
	if members["limit"] != float64(props["limit"].(map[string]any)["default"].(int)) {
		t.Fatalf("default mismatch: %v", members)
	}
	alerts := members["alerts"].([]any)
	if len(alerts) != 1 || alerts[0].(map[string]any)["id"] != rec.ID || members["snapshot_sequence"] != page["snapshot_sequence"] {
		t.Fatal(members)
	}
	if alerts[0].(map[string]any)["raw"] != nil {
		t.Fatal("summary unexpectedly contains raw evidence")
	}
	for name, duration := range map[string]time.Duration{"list_alerts": 7 * 24 * time.Hour, "list_alert_groups": 24 * time.Hour} {
		result := toolJSON(t, srv, name, map[string]any{})
		bounds := result["window"].(map[string]any)
		start, _ := time.Parse(time.RFC3339Nano, bounds["start"].(string))
		end, _ := time.Parse(time.RFC3339Nano, bounds["end"].(string))
		if end.Sub(start) != duration {
			t.Fatalf("%s default window: %v", name, bounds)
		}
	}
}

func TestDeclaredInputConstraintsAreEnforcedBeforeHandler(t *testing.T) {
	srv, _ := newTestServer(t)
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"list_alerts", map[string]any{"limit": 0}},
		{"list_alerts", map[string]any{"limit": 1.5}},
		{"list_alerts", map[string]any{"limit": "20"}},
		{"list_alerts", map[string]any{"limit": 10001}},
		{"list_alerts", map[string]any{"provider": false}},
		{"list_alerts", map[string]any{"invented": "value"}},
		{"list_alert_groups", map[string]any{"group_by": "attack"}},
		{"get_alert_group", map[string]any{"group_by": "asset"}},
		{"get_alert_group", map[string]any{"group_by": "asset", "group_key": map[string]any{"singleton": 12}}},
		{"get_asset_component", map[string]any{"asset_id": "synthetic", "component": "runtime"}},
		{"get_alert_statistics", map[string]any{"offset": 1}},
		{"get_data_coverage", map[string]any{"after_id": "invented"}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			tool := srv.tools[tc.tool]
			invoked := false
			old := tool.Handler
			tool.Handler = func(_ctx context.Context, _args map[string]any) (any, error) { invoked = true; return nil, nil }
			srv.tools[tc.tool] = tool
			defer func() { tool.Handler = old; srv.tools[tc.tool] = tool }()
			resp := call(t, srv, "tools/call", map[string]any{"name": tc.tool, "arguments": tc.args})
			if invoked || resp.Error != nil || resp.Result.(map[string]any)["isError"] != true {
				t.Fatalf("invalid args accepted: %+v", tc.args)
			}
		})
	}
}
