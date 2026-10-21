package aws

import (
	"context"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"testing"
	"time"
)

type fakeAlertClient struct {
	fetch func(*securityhub.GetFindingsV2Input) (*securityhub.GetFindingsV2Output, error)
}

func (c fakeAlertClient) GetFindingsV2(_ context.Context, r *securityhub.GetFindingsV2Input, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsV2Output, error) {
	return c.fetch(r)
}

func TestFetchIncludesNewObservedAndModifiedFindings(t *testing.T) {
	c := &Connector{pageSize: 100, limiter: connector.NewLimiter(10000)}
	c.client = fakeAlertClient{func(r *securityhub.GetFindingsV2Input) (*securityhub.GetFindingsV2Output, error) {
		filters := r.Filters.CompositeFilters
		if len(filters) != 1 || filters[0].Operator != types.AllowedOperatorsOr || len(filters[0].StringFilters) != 0 {
			t.Fatalf("filters=%+v", filters)
		}
		fields := map[types.OcsfDateField]bool{}
		for _, f := range filters[0].DateFilters {
			fields[f.FieldName] = true
		}
		if !fields[types.OcsfDateFieldFindingInfoCreatedTimeDt] || !fields[types.OcsfDateFieldFindingInfoLastSeenTimeDt] || !fields[types.OcsfDateFieldFindingInfoModifiedTimeDt] {
			t.Fatalf("missing date field: %+v", fields)
		}
		if r.NextToken == nil {
			next := "page-two"
			return &securityhub.GetFindingsV2Output{NextToken: &next}, nil
		}
		if *r.NextToken != "page-two" {
			t.Fatalf("token=%s", *r.NextToken)
		}
		return &securityhub.GetFindingsV2Output{}, nil
	}}
	q := connector.Query{Start: time.Now().Add(-time.Hour), End: time.Now()}
	page, err := c.Fetch(context.Background(), q)
	if err != nil || page.NextToken != "page-two" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	q.Token = page.NextToken
	page, err = c.Fetch(context.Background(), q)
	if err != nil || page.NextToken != "" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}
