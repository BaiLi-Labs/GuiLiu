package huawei

import (
	"context"
	"encoding/json"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	hw "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/secmaster/v1/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeAlertClient struct {
	fetch func(*hw.ListAlertsRequest) (*hw.ListAlertsResponse, error)
}

func (c fakeAlertClient) ListAlerts(r *hw.ListAlertsRequest) (*hw.ListAlertsResponse, error) {
	return c.fetch(r)
}

func TestFetchPreservesEnvelopeAndAllPages(t *testing.T) {
	c := &Connector{workspaceID: "workspace", pageSize: 1, limiter: connector.NewLimiter(10000)}
	fake := fakeAlertClient{func(r *hw.ListAlertsRequest) (*hw.ListAlertsResponse, error) {
		if r.WorkspaceId != "workspace" || r.Body.Condition != nil {
			t.Fatalf("scope=%+v", r)
		}
		id, project := "alert", "project"
		total := int32(2)
		items := []hw.ListAlertDetail{{Id: &id, ProjectId: &project, DataObject: &hw.ListAlertRsp{Id: &id}}}
		return &hw.ListAlertsResponse{Total: &total, Data: &items}, nil
	}}
	c.fetchJSON = func(req *hw.ListAlertsRequest) (json.RawMessage, error) {
		response, err := fake.ListAlerts(req)
		if err != nil {
			return nil, err
		}
		return json.Marshal(response)
	}
	q := connector.Query{Start: time.Now().Add(-time.Hour), End: time.Now()}
	page, err := c.Fetch(context.Background(), q)
	if err != nil || page.NextToken != "1" || len(page.Records) != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if !strings.Contains(string(page.Records[0].Raw), `"project_id":"project"`) {
		t.Fatalf("envelope lost: %s", page.Records[0].Raw)
	}
	q.Token = page.NextToken
	page, err = c.Fetch(context.Background(), q)
	if err != nil || page.NextToken != "" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}

func TestSignedHTTPFetchRetainsUnknownSourceAndEnvelopeFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("request was not signed")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"total":1,"data":[{"id":"a","futureEnvelope":"retained","data_object":{"id":"a","futureNested":{"large":9007199254740993}}}]}`))
	}))
	defer server.Close()
	conn, err := New(connector.AccountConfig{Credential: connector.Credential{AccessKeyID: "test-key", AccessKeySecret: "test-secret"}, Options: map[string]string{"project_id": "project", "workspace_id": "workspace", "endpoint": server.URL}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := conn.Fetch(context.Background(), connector.Query{Start: time.Now().Add(-time.Hour), End: time.Now()})
	if err != nil || len(p.Records) != 1 {
		t.Fatalf("page=%+v %v", p, err)
	}
	raw := string(p.Records[0].Raw)
	if !strings.Contains(raw, "9007199254740993") || !strings.Contains(raw, "futureEnvelope") {
		t.Fatalf("source fields lost: %s", raw)
	}
}
