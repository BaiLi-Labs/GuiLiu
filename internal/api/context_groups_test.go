package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/asset"
	"github.com/BaiLi-Labs/GuiLiu/internal/cli"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestSyntheticNetworkGroupingAcrossCloudsAndSurfaces(t *testing.T) {
	for _, provider := range []string{"tencent", "aliyun", "huawei", "aws", "gcp", "azure"} {
		t.Run(provider, func(t *testing.T) {
			ts, st, _ := setup(t, true)
			client := newClient(t, ts)
			live := httptest.NewServer(ts.handler)
			defer live.Close()
			ctx := context.Background()
			a := model.Account{ID: "synthetic-account", Name: "synthetic", Provider: provider, AccountUID: "100000000001", Region: "region-1", Enabled: true, Options: map[string]string{"project_id": "mock-project", "workspace_id": "mock-workspace", "subscription_id": "11111111-1111-1111-1111-111111111111", "tenant_id": "mock-tenant"}}
			switch provider {
			case "aws":
				a.AccountUID = "123456789012"
				a.Region = "us-east-1"
			case "azure":
				a.AccountUID = a.Options["subscription_id"]
				a.Region = "eastasia"
			case "gcp":
				a.AccountUID = "mock-project"
				a.Region = "us-central1"
			case "tencent":
				a.Region = "ap-guangzhou"
			case "aliyun":
				a.Region = "cn-hangzhou"
			case "huawei":
				a.Region = "cn-north-4"
			}
			if err := st.CreateAccount(ctx, &a); err != nil {
				t.Fatal(err)
			}
			if err := asset.SeedSynthetic(ctx, st, a); err != nil {
				t.Fatal(err)
			}
			p, _ := asset.ProviderFor(provider)
			kind := map[string]string{"tencent": "host", "aliyun": "host", "huawei": "host", "aws": "AwsEc2Instance", "gcp": "google.compute.Instance", "azure": "microsoft.compute/virtualmachines"}[provider]
			ids := []string{p.SyntheticHostID}
			if p.AlertResourceIDs != nil {
				ids = p.AlertResourceIDs(a, p.SyntheticHostID)
			}
			at := time.Now().UTC().Truncate(time.Second)
			for i, id := range ids {
				r := &model.AlertRecord{AccountID: a.ID, Provider: provider, AccountUID: a.AccountUID, Alert: model.Alert{ExternalID: fmt.Sprintf("synthetic-%d", i), Title: " Exact source title ", Product: "synthetic-product", Region: a.Region, Resource: model.Resource{ID: id, Type: kind}, EventTime: at, FirstSeenAt: at, LastSeenAt: at, Raw: json.RawMessage(`{"synthetic":true}`)}}
				if _, err := st.UpsertAlert(ctx, r); err != nil {
					t.Fatal(err)
				}
			}
			// The same request must return identical counts, group keys and watermarks in all surfaces.
			start, end := at.Add(-time.Hour).Format(time.RFC3339), at.Add(time.Hour).Format(time.RFC3339)
			for _, by := range []string{"asset", "name_asset", "vpc", "subnet", "security_group", "nic"} {
				q := url.Values{"group_by": {by}, "start": {start}, "end": {end}, "limit": {"20"}}
				response, body := do(t, client, "GET", ts.URL+"/api/v1/alerts/groups?"+q.Encode(), "", "")
				if response.StatusCode != 200 {
					t.Fatalf("%s REST: %s", by, body)
				}
				var rest map[string]any
				if err := json.Unmarshal(body, &rest); err != nil {
					t.Fatal(err)
				}
				args := map[string]any{"group_by": by, "start": start, "end": end, "limit": 20}
				request, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "list_alert_groups", "arguments": args}})
				_, rpcBody := do(t, client, "POST", ts.URL+"/mcp", "", string(request))
				var rpc struct {
					Result struct {
						IsError bool `json:"isError"`
						Content []struct {
							Text string `json:"text"`
						} `json:"content"`
					} `json:"result"`
				}
				if json.Unmarshal(rpcBody, &rpc) != nil || rpc.Result.IsError || len(rpc.Result.Content) != 1 {
					t.Fatalf("MCP %s", rpcBody)
				}
				var mcp map[string]any
				json.Unmarshal([]byte(rpc.Result.Content[0].Text), &mcp)
				if !reflect.DeepEqual(rest, mcp) {
					t.Fatalf("%s REST/MCP mismatch", by)
				}
				var stdout, stderr bytes.Buffer
				t.Setenv("GUILIU_API_KEY", "")
				t.Setenv("GUILIU_API_KEY_FILE", "")
				code := cli.Run([]string{"--url", live.URL, "groups", "--group-by", by, "--start", start, "--end", end, "--limit", "20", "--json"}, &stdout, &stderr)
				var cliResult map[string]any
				if code != 0 || json.Unmarshal(stdout.Bytes(), &cliResult) != nil || !reflect.DeepEqual(rest, cliResult) {
					t.Fatalf("%s CLI mismatch: %d %s", by, code, stderr.String())
				}
				groups := rest["groups"].([]any)
				if len(groups) == 0 {
					t.Fatalf("%s missing group", by)
				}
				known := 0
				for _, raw := range groups {
					g := raw.(map[string]any)
					key := g["key"].(map[string]any)
					if key["singleton"] != nil {
						continue
					}
					known++
					if g["finding_count"] != float64(len(ids)) {
						t.Fatalf("%s count: %+v", by, g)
					}
					proofs, _ := g["relation_evidence"].([]any)
					for _, rawProof := range proofs {
						proof := rawProof.(map[string]any)
						ref := proof["reference"].(map[string]any)
						path := fmt.Sprintf("/api/v1/assets/%s/revisions/%.0f/components/%s/raw", proof["source_asset_id"], proof["source_revision"], url.PathEscape(ref["source_component"].(string)))
						evidenceResponse, evidenceBody := do(t, client, "GET", ts.URL+path, "", "")
						if evidenceResponse.StatusCode != 200 || !json.Valid(evidenceBody) {
							t.Fatalf("%s cannot retrieve exact relationship evidence: %s", by, evidenceBody)
						}
					}
					memberQ := url.Values{"group_by": {by}, "group_key": {mustJSON(t, key)}, "start": {start}, "end": {end}, "snapshot_sequence": {fmt.Sprint(rest["snapshot_sequence"])}, "asset_snapshot_sequence": {fmt.Sprint(rest["asset_snapshot_sequence"])}, "vendor_title": {" Exact source title "}}
					response, memberBody := do(t, client, "GET", ts.URL+"/api/v1/alerts?"+memberQ.Encode(), "", "")
					var members map[string]any
					json.Unmarshal(memberBody, &members)
					if response.StatusCode != 200 || members["total"] != float64(len(ids)) {
						t.Fatalf("%s expansion %s", by, memberBody)
					}
					// MCP must preserve exact source-title and key whitespace too.
					args["group_key"] = key
					args["snapshot_sequence"] = rest["snapshot_sequence"]
					args["asset_snapshot_sequence"] = rest["asset_snapshot_sequence"]
					args["vendor_title"] = " Exact source title "
					request, _ = json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "get_alert_group", "arguments": args}})
					_, rpcBody = do(t, client, "POST", ts.URL+"/mcp", "", string(request))
					json.Unmarshal(rpcBody, &rpc)
					if rpc.Result.IsError {
						t.Fatalf("MCP expansion %s", rpcBody)
					}
					json.Unmarshal([]byte(rpc.Result.Content[0].Text), &mcp)
					if mcp["total"] != members["total"] {
						t.Fatalf("MCP changed source-title equality: %s", rpcBody)
					}
					if by == "security_group" {
						memberQ.Del("asset_snapshot_sequence")
						response, _ = do(t, client, "GET", ts.URL+"/api/v1/alerts?"+memberQ.Encode(), "", "")
						if response.StatusCode != 400 {
							t.Fatal("network expansion accepted missing asset watermark")
						}
					}
				}
				if by == "asset" || by == "name_asset" || by == "vpc" {
					if known == 0 {
						t.Fatalf("%s alias identity failed", by)
					}
				}
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
