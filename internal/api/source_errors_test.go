package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
)

type sourceCheckConnector struct{ checkErr error }

func (c *sourceCheckConnector) Info() connector.Descriptor {
	return connector.Descriptor{SourceAPI: "CSIP DescribeAlertList"}
}
func (c *sourceCheckConnector) Check(context.Context) error { return c.checkErr }
func (c *sourceCheckConnector) Fetch(context.Context, connector.Query) (connector.Page, error) {
	return connector.Page{}, c.checkErr
}
func (c *sourceCheckConnector) Normalize(json.RawMessage) (model.Alert, error) {
	return model.Alert{}, nil
}

func TestConnectionCheckReportsOnlyTheTestedAPIAndSafeSourceErrors(t *testing.T) {
	conn := &sourceCheckConnector{}
	ts, _, _ := setup(t, true, func(reg *connector.Registry) {
		err := reg.Register(connector.Descriptor{ID: "sdk-check", Name: "SDK check", SourceAPI: "CSIP DescribeAlertList", Credential: []connector.CredentialField{{Name: "access_key_id", Required: true}, {Name: "access_key_secret", Required: true, Secret: true}}}, func(connector.AccountConfig) (connector.Connector, error) { return conn, nil })
		if err != nil {
			t.Fatal(err)
		}
	})
	client := newClient(t, ts)
	resp, body := do(t, client, "POST", ts.URL+"/api/v1/accounts", "", `{"name":"synthetic-sdk-check","provider":"sdk-check","access_key_id":"synthetic-key","access_key_secret":"synthetic-secret"}`)
	var account model.Account
	if resp.StatusCode != 201 || json.Unmarshal(body, &account) != nil {
		t.Fatal(resp.StatusCode, string(body))
	}
	resp, body = do(t, client, "POST", ts.URL+"/api/v1/accounts/"+account.ID+"/check", "", "")
	var result struct {
		OK          bool     `json:"ok"`
		API         string   `json:"checked_api"`
		Scope       string   `json:"check_scope"`
		Limitations []string `json:"limitations"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &result) != nil || !result.OK || result.API != "CSIP DescribeAlertList" || result.Scope != "finding_query_only" || len(result.Limitations) == 0 {
		t.Fatal(string(body))
	}
	for _, test := range []struct{ code, kind string }{{"UnauthorizedOperation", "permission"}, {"AuthFailure.SignatureFailure", "auth"}} {
		conn.checkErr = connector.WithSourceAPI("tencent", "CSIP DescribeAlertList", tcerrors.NewTencentCloudSDKError(test.code, "DO_NOT_LEAK", ""))
		resp, body = do(t, client, "POST", ts.URL+"/api/v1/accounts/"+account.ID+"/check", "", "")
		var failure struct {
			Error struct {
				SourceError *model.SourceError `json:"source_error"`
			} `json:"error"`
		}
		if resp.StatusCode != http.StatusUnprocessableEntity || json.Unmarshal(body, &failure) != nil || failure.Error.SourceError == nil || failure.Error.SourceError.Kind != test.kind || failure.Error.SourceError.Code != test.code || strings.Contains(string(body), "DO_NOT_LEAK") {
			t.Fatal(string(body))
		}
	}
}

func TestSourceDenialFactsAreIdenticalThroughRESTAndMCP(t *testing.T) {
	ts, st, _ := setup(t, true)
	client, ctx := newClient(t, ts), context.Background()
	account := model.Account{ID: "denied-connection", Name: "synthetic-denial", Provider: "tencent", AccountUID: "100000000001", Region: "ap-guangzhou", Enabled: true}
	if err := st.CreateAccount(ctx, &account); err != nil {
		t.Fatal(err)
	}
	finding := &model.AlertRecord{Provider: "tencent", AccountID: account.ID, AccountUID: account.AccountUID, Alert: model.Alert{ExternalID: "denied-finding", Region: account.Region, Resource: model.Resource{ID: "ins-mock0001", Type: "host"}, EventTime: time.Now().UTC(), Raw: json.RawMessage(`{"synthetic":true}`)}}
	if _, err := st.UpsertAlert(ctx, finding); err != nil {
		t.Fatal(err)
	}
	detail := connector.SourceError(connector.WithSourceAPI("tencent", "CVM DescribeInstances", tcerrors.NewTencentCloudSDKError("UnauthorizedOperation", "DO_NOT_LEAK", "")))
	attempt := model.AssetRefresh{AccountID: account.ID, Region: account.Region, ResourceID: "ins-mock0001", Status: "permission_denied", AttemptedAt: time.Now().UTC(), SourceError: detail}
	if _, err := st.BeginAssetRefresh(ctx, attempt, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishAssetRefresh(ctx, attempt); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSyncState(ctx, &model.SyncState{AccountID: account.ID, LastError: "safe denial", LastSourceError: &model.SourceError{Provider: "tencent", Kind: "permission", Code: "UnauthorizedOperation", SourceAPI: "CSIP DescribeAlertList"}, ConsecutiveFailures: 1}); err != nil {
		t.Fatal(err)
	}
	compare := func(path, tool string, args map[string]any) map[string]any {
		t.Helper()
		resp, body := do(t, client, "GET", ts.URL+"/api/v1"+path, "", "")
		var rest map[string]any
		if resp.StatusCode != 200 || json.Unmarshal(body, &rest) != nil {
			t.Fatal(string(body))
		}
		request, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
		_, body = do(t, client, "POST", ts.URL+"/mcp", "", string(request))
		var rpc struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &rpc) != nil || rpc.Result.IsError || len(rpc.Result.Content) != 1 {
			t.Fatal(string(body))
		}
		var mcp map[string]any
		if json.Unmarshal([]byte(rpc.Result.Content[0].Text), &mcp) != nil || !reflect.DeepEqual(rest, mcp) {
			t.Fatalf("different source diagnostics: %+v %+v", rest, mcp)
		}
		if strings.Contains(string(body), "DO_NOT_LEAK") {
			t.Fatal("SDK message leaked")
		}
		return rest
	}
	result := compare("/alerts/"+finding.ID+"/asset-context", "get_alert_asset_context", map[string]any{"alert_id": finding.ID})
	if result["reason"] != "permission_denied" || result["asset"] != nil || result["refresh"].(map[string]any)["source_error"].(map[string]any)["code"] != "UnauthorizedOperation" {
		t.Fatal(result)
	}
	q := url.Values{"provider": {"tencent"}, "account_id": {account.ID}, "account_uid": {account.AccountUID}, "region": {account.Region}, "resource_type": {"cvm"}, "resource_id": {"ins-mock0001"}}
	result = compare("/assets/lookup?"+q.Encode(), "get_asset_by_reference", map[string]any{"provider": "tencent", "account_id": account.ID, "account_uid": account.AccountUID, "region": account.Region, "resource_type": "cvm", "resource_id": "ins-mock0001"})
	if result["status"] != "permission_denied" {
		t.Fatal("denial looked like empty inventory", result)
	}
	start, end := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339)
	result = compare("/coverage?"+url.Values{"start": {start}, "end": {end}}.Encode(), "get_data_coverage", map[string]any{"start": start, "end": end})
	if result["complete"] != false || result["accounts"].([]any)[0].(map[string]any)["last_source_error"] == nil {
		t.Fatal(result)
	}
}
