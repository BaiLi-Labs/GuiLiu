package aliyun

import (
	"context"
	"encoding/json"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	sas "github.com/alibabacloud-go/sas-20181203/v3/client"
	"github.com/alibabacloud-go/tea-utils/v2/service"
	"strings"
	"testing"
	"time"
)

type fakeAlertClient struct {
	fetch func(*sas.DescribeSuspEventsRequest) (*sas.DescribeSuspEventsResponse, error)
}

func (c fakeAlertClient) DescribeSuspEventsWithOptions(r *sas.DescribeSuspEventsRequest, _ *service.RuntimeOptions) (*sas.DescribeSuspEventsResponse, error) {
	return c.fetch(r)
}

func TestFetchAllStatusesAndPages(t *testing.T) {
	start := time.Now().UTC().Add(-time.Hour)
	c := &Connector{pageSize: 2, limiter: connector.NewLimiter(10000)}
	fake := fakeAlertClient{func(r *sas.DescribeSuspEventsRequest) (*sas.DescribeSuspEventsResponse, error) {
		if *r.Status != "0" || r.Levels != nil || r.ParentEventTypes != nil || r.Dealed != nil {
			t.Fatalf("unexpected scope filters: %+v", r)
		}
		if *r.TimeStart != connector.FormatBeijing(start) {
			t.Fatalf("start=%s", *r.TimeStart)
		}
		ids := []int64{1, 2}
		if *r.CurrentPage == "2" {
			ids = []int64{3}
		}
		items := []*sas.DescribeSuspEventsResponseBodySuspEvents{}
		for _, id := range ids {
			items = append(items, &sas.DescribeSuspEventsResponseBodySuspEvents{Id: &id})
		}
		total := int32(3)
		return &sas.DescribeSuspEventsResponse{Body: &sas.DescribeSuspEventsResponseBody{TotalCount: &total, SuspEvents: items}}, nil
	}}
	c.fetchJSON = func(req *sas.DescribeSuspEventsRequest, runtime *service.RuntimeOptions) (json.RawMessage, error) {
		response, err := fake.DescribeSuspEventsWithOptions(req, runtime)
		if err != nil {
			return nil, err
		}
		return json.Marshal(response.Body)
	}
	q := connector.Query{Start: start, End: start.Add(time.Hour)}
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
	c := &Connector{pageSize: 10, limiter: connector.NewLimiter(10000), fetchJSON: func(*sas.DescribeSuspEventsRequest, *service.RuntimeOptions) (json.RawMessage, error) {
		return json.RawMessage(`{"TotalCount":1,"SuspEvents":[{"Id":9007199254740993,"FutureNested":{"value":"retained"}}]}`), nil
	}}
	p, err := c.Fetch(context.Background(), connector.Query{})
	if err != nil || len(p.Records) != 1 {
		t.Fatalf("page=%+v %v", p, err)
	}
	a, err := c.Normalize(p.Records[0].Raw)
	if err != nil || a.ExternalID != "9007199254740993" || !strings.Contains(string(a.Raw), "FutureNested") {
		t.Fatalf("source record changed: %+v %v", a, err)
	}
}
