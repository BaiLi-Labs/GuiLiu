package tencent

import (
	"context"
	"encoding/json"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	csip "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/csip/v20221121"
	"strings"
	"testing"
	"time"
)

type fakeAlertClient struct {
	fetch func(*csip.DescribeAlertListRequest) (*csip.DescribeAlertListResponse, error)
}

func (c fakeAlertClient) DescribeAlertListWithContext(_ context.Context, r *csip.DescribeAlertListRequest) (*csip.DescribeAlertListResponse, error) {
	return c.fetch(r)
}

func TestFetchAllTypesAndOffsetPages(t *testing.T) {
	c := &Connector{pageSize: 2, limiter: connector.NewLimiter(10000)}
	fake := fakeAlertClient{func(r *csip.DescribeAlertListRequest) (*csip.DescribeAlertListResponse, error) {
		if len(r.Filter.Filters) != 0 || r.AssetType != nil {
			t.Fatalf("unexpected type/asset restriction: %+v", r)
		}
		ids := []string{"one", "two"}
		if *r.Filter.Offset == 2 {
			ids = []string{"three"}
		}
		items := []*csip.AlertInfo{}
		for _, id := range ids {
			items = append(items, &csip.AlertInfo{ID: &id})
		}
		total := uint64(3)
		return &csip.DescribeAlertListResponse{Response: &csip.DescribeAlertListResponseParams{TotalCount: &total, AlertList: items}}, nil
	}}
	c.fetchJSON = func(ctx context.Context, req *csip.DescribeAlertListRequest) (json.RawMessage, error) {
		response, err := fake.DescribeAlertListWithContext(ctx, req)
		if err != nil {
			return nil, err
		}
		return json.Marshal(response.Response)
	}
	q := connector.Query{Start: time.Now().Add(-time.Hour), End: time.Now()}
	page, err := c.Fetch(context.Background(), q)
	if err != nil || len(page.Records) != 2 || page.NextToken != "2" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	q.Token = page.NextToken
	page, err = c.Fetch(context.Background(), q)
	if err != nil || len(page.Records) != 1 || page.NextToken != "" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}

func TestFetchRetainsUnknownWireFields(t *testing.T) {
	c := &Connector{pageSize: 10, limiter: connector.NewLimiter(10000), fetchJSON: func(context.Context, *csip.DescribeAlertListRequest) (json.RawMessage, error) {
		return json.RawMessage(`{"TotalCount":1,"AlertList":[{"ID":"wire","FutureNested":{"large":9007199254740993},"Attacker":{"IP":"203.0.113.4","FutureRole":"retained"}}]}`), nil
	}}
	p, err := c.Fetch(context.Background(), connector.Query{})
	if err != nil || len(p.Records) != 1 {
		t.Fatalf("page=%+v %v", p, err)
	}
	if !strings.Contains(string(p.Records[0].Raw), "9007199254740993") || !strings.Contains(string(p.Records[0].Raw), "FutureRole") {
		t.Fatal("unknown wire fields lost")
	}
}
