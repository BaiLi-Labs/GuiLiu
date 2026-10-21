package api_test

import (
	"encoding/json"
	"testing"

	"github.com/BaiLi-Labs/GuiLiu/internal/version"
)

func TestProductVersionMatchesRESTAndMCPMetadata(t *testing.T) {
	ts, _, _ := setup(t, true)
	client := newClient(t, ts)
	response, body := do(t, client, "GET", ts.URL+"/api/v1/meta", "", "")
	var meta struct {
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		BuildDate string `json:"build_date"`
	}
	if response.StatusCode != 200 || json.Unmarshal(body, &meta) != nil || meta.Version != version.Version || meta.Commit != version.Commit || meta.BuildDate != version.BuildDate {
		t.Fatalf("REST build metadata differs from product version: %s", body)
	}
	response, body = do(t, client, "POST", ts.URL+"/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	var rpc struct {
		Result struct {
			ServerInfo struct {
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if response.StatusCode != 200 || json.Unmarshal(body, &rpc) != nil || rpc.Result.ServerInfo.Version != meta.Version {
		t.Fatalf("MCP/REST product version mismatch: %s", body)
	}
}
