package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/asset"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

func TestAssetInvestigationRESTAndMCPUseIdenticalFacts(t *testing.T) {
	ts, st, _ := setup(t, true)
	client := newClient(t, ts)
	ctx := context.Background()
	a := model.Account{ID: "asset-account", Name: "synthetic", Provider: "tencent", AccountUID: "100000000001", Region: "ap-guangzhou", Enabled: true}
	if err := st.CreateAccount(ctx, &a); err != nil {
		t.Fatal(err)
	}
	create := func(id, uid, region, resource, kind string, secondary bool) *model.AlertRecord {
		now := time.Now().UTC()
		r := &model.AlertRecord{Provider: "tencent", AccountID: a.ID, AccountUID: uid, Alert: model.Alert{ExternalID: id, Title: id, Region: region, Resource: model.Resource{ID: resource, Type: kind}, SourceIP: "192.0.2.10", EventTime: now, Raw: json.RawMessage(`{"id":"` + id + `"}`)}}
		if secondary {
			r.Resources = []model.Resource{{ID: "ins-mock0001", Type: "host"}}
		}
		if _, err := st.UpsertAlert(ctx, r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	finding := create("matching", "100000000001", a.Region, "ins-mock0001", "host", false)
	create("other-account", "other-uid", a.Region, "ins-mock0001", "host", false)
	create("other-region", a.AccountUID, "ap-shanghai", "ins-mock0001", "host", false)
	create("same-ip", a.AccountUID, a.Region, "ins-other", "host", false)
	create("wrong-kind", a.AccountUID, a.Region, "ins-mock0001", "network", false)
	create("secondary-reference", a.AccountUID, a.Region, "ins-other", "host", true)
	sequence, _ := st.SnapshotSequence(ctx)
	value, err := asset.SyntheticTencent(ctx, a, "ins-mock0001", connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveAsset(ctx, value); err != nil {
		t.Fatal(err)
	}
	if after, _ := st.SnapshotSequence(ctx); after != sequence {
		t.Fatal("asset write changed Finding sequence")
	}
	compare := func(path, name string, args map[string]any) map[string]any {
		response, body := do(t, client, "GET", ts.URL+"/api/v1"+path, "", "")
		if response.StatusCode != 200 {
			t.Fatalf("REST %s: %d %s", path, response.StatusCode, body)
		}
		var rest map[string]any
		if err := json.Unmarshal(body, &rest); err != nil {
			t.Fatal(err)
		}
		request, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
		response, body = do(t, client, "POST", ts.URL+"/mcp", "", string(request))
		var rpc struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if response.StatusCode != 200 || json.Unmarshal(body, &rpc) != nil || rpc.Result.IsError || len(rpc.Result.Content) != 1 {
			t.Fatalf("MCP %s: %d %s", name, response.StatusCode, body)
		}
		var mcp map[string]any
		if err := json.Unmarshal([]byte(rpc.Result.Content[0].Text), &mcp); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rest, mcp) {
			t.Fatalf("REST/MCP mismatch %s:\n%+v\n%+v", name, rest, mcp)
		}
		return rest
	}
	contextResult := compare("/alerts/"+finding.ID+"/asset-context?revision=1", "get_alert_asset_context", map[string]any{"alert_id": finding.ID, "revision": 1})
	if contextResult["status"] != "available" || contextResult["asset"].(map[string]any)["resource_id"] != "ins-mock0001" {
		t.Fatal(contextResult)
	}
	compare("/assets?limit=1", "list_assets", map[string]any{"limit": 1})
	compare("/assets/"+value.ID+"?revision=1", "get_asset", map[string]any{"asset_id": value.ID, "revision": 1})
	related := compare("/assets/"+value.ID+"/findings?limit=1", "list_asset_findings", map[string]any{"asset_id": value.ID, "limit": 1})
	if related["total"] != float64(2) || related["has_more"] != true {
		t.Fatal("identity filter leaked or omitted records", related)
	}
	page := compare(fmt.Sprintf("/assets/%s/findings?limit=1&after_id=%s&snapshot_sequence=%.0f", value.ID, related["next_cursor"], related["snapshot_sequence"]), "list_asset_findings", map[string]any{"asset_id": value.ID, "limit": 1, "after_id": related["next_cursor"], "snapshot_sequence": related["snapshot_sequence"]})
	if page["has_more"] != false || len(page["alerts"].([]any)) != 1 {
		t.Fatal("cannot resume", page)
	}
	response, body := do(t, client, "GET", ts.URL+query.AssetView(*value).Components["instance"].RawURL, "", "")
	if response.StatusCode != 200 || string(body) != asset.SyntheticInstance || fmt.Sprintf("%x", sha256.Sum256(body)) != value.Components["instance"].RawHash {
		t.Fatal("exact evidence mismatch", string(body))
	}
	// An uncollected host must not link through its matching IP.
	other := create("uncollected", a.AccountUID, a.Region, "ins-nevercollected", "host", false)
	missing := compare("/alerts/"+other.ID+"/asset-context", "get_alert_asset_context", map[string]any{"alert_id": other.ID})
	if missing["reason"] != "not_collected" || missing["asset"] != nil || missing["refresh"] != nil {
		t.Fatal("IP incorrectly became identity", missing)
	}
	current, err := st.GetAlert(ctx, finding.ID)
	if err != nil || current.Revision != 1 {
		t.Fatal("asset changed Finding revision", err)
	}
	for _, suffix := range []string{"/assets?ip=192.0.2.10", "/assets?limit=0", "/assets?limit=1&limit=2", "/alerts/" + finding.ID + "/asset-context?revision=1&snapshot_sequence=0"} {
		resp, _ := do(t, client, "GET", ts.URL+"/api/v1"+suffix, "", "")
		if resp.StatusCode != 400 {
			t.Fatal("unsupported query accepted", suffix, resp.StatusCode)
		}
	}
	// Exact Finding evidence is still accessible through the existing surface.
	response, body = do(t, client, "GET", ts.URL+"/api/v1/alerts/"+finding.ID, "", "")
	var detail view.Alert
	if response.StatusCode != 200 || json.Unmarshal(body, &detail) != nil || detail.RawHash != finding.RawHash {
		t.Fatal("Finding contract changed")
	}
}

func TestAssetRoutesRequireAuthenticationAndRefreshRequiresAdmin(t *testing.T) {
	ts, _, authSvc := setup(t, false)
	client := newClient(t, ts)
	for _, path := range []string{"/api/v1/assets", "/api/v1/assets/x", "/api/v1/alerts/x/asset-context", "/api/v1/assets/x/findings", "/api/v1/assets/x/revisions/1/components/instance/raw"} {
		response, _ := do(t, client, "GET", ts.URL+path, "", "")
		if response.StatusCode != 401 {
			t.Fatal("unprotected route", path)
		}
	}
	if _, err := authSvc.CreateUser(context.Background(), "asset-viewer", "viewer-password-123", "viewer"); err != nil {
		t.Fatal(err)
	}
	response, body := do(t, client, "POST", ts.URL+"/api/v1/auth/login", "", `{"username":"asset-viewer","password":"viewer-password-123"}`)
	var login struct {
		Token string `json:"token"`
	}
	if response.StatusCode != 200 || json.Unmarshal(body, &login) != nil {
		t.Fatalf("login %s", body)
	}
	response, body = do(t, client, "POST", ts.URL+"/api/v1/accounts/x/assets/refresh", login.Token, `{"resource_id":"ins-1"}`)
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("viewer could refresh cloud data", response.StatusCode, string(body))
	}
	response, body = do(t, client, "POST", ts.URL+"/mcp", login.Token, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_assets","arguments":{}}}`)
	if response.StatusCode != 200 || !strings.Contains(string(body), `"isError":false`) {
		t.Fatal("viewer MCP read denied", string(body))
	}
}
