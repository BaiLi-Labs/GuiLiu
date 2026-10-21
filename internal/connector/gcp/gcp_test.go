package gcp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
)

func TestFindingFilterIncludesInactiveFindings(t *testing.T) {
	start := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	filter := findingFilter(start, end)
	if strings.Contains(filter, "state") {
		t.Fatalf("filter must not drop non-ACTIVE findings: %s", filter)
	}
	if !strings.Contains(filter, `event_time >= "2026-10-20T00:00:00Z"`) ||
		!strings.Contains(filter, `event_time < "2026-10-20T01:00:00Z"`) {
		t.Fatalf("unexpected time filter: %s", filter)
	}
}

func TestQueryScopeV2AndLegacyV1(t *testing.T) {
	for _, tc := range []struct {
		options                   map[string]string
		version, parent, endpoint string
	}{
		{map[string]string{"parent": "organizations/123"}, "v2", "organizations/123/sources/-/locations/global", ""},
		{map[string]string{"parent": "folders/123", "location": "eu"}, "v2", "folders/123/sources/-/locations/eu", "securitycenter.eu.rep.googleapis.com:443"},
		{map[string]string{"parent": "projects/p/sources/s/locations/us"}, "v2", "projects/p/sources/s/locations/us", "securitycenter.us.rep.googleapis.com:443"},
		{map[string]string{"parent": "organizations/123", "api_version": "v1"}, "v1", "organizations/123/sources/-", ""},
	} {
		v, p, e, err := queryScope(tc.options)
		if err != nil || v != tc.version || p != tc.parent || e != tc.endpoint {
			t.Fatalf("options=%v scope=%s %s %s err=%v", tc.options, v, p, e, err)
		}
	}
	for _, options := range []map[string]string{{"parent": ""}, {"parent": "projects/p/findings/a"}, {"parent": "projects/p", "api_version": "v3"}, {"parent": "projects/p", "api_version": "v1", "location": "eu"}, {"parent": "projects/p/sources/-/locations/us", "location": "eu"}} {
		if _, _, _, err := queryScope(options); err == nil {
			t.Fatalf("invalid scope accepted: %v", options)
		}
	}
}

func TestFetchV2PreservesResourceAndPageToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/organizations/123/sources/-/locations/eu/findings" || strings.Contains(r.URL.Query().Get("filter"), "state") {
			t.Errorf("request=%s", r.URL)
		}
		next := "second"
		if r.URL.Query().Get("pageToken") == "second" {
			next = ""
		}
		fmt.Fprintf(w, `{"nextPageToken":%q,"listFindingsResults":[{"finding":{"name":"organizations/123/sources/s/locations/eu/findings/a","category":"arbitrary-new-category","futureField":{"integer":9007199254740993}},"resource":{"name":"resource-id","displayName":"vendor-display","location":"eu"},"futureEnvelope":"retained"}]}`, next)
	}))
	defer server.Close()
	c := &Connector{client: server.Client(), endpoint: server.URL, apiVersion: "v2", parent: "organizations/123/sources/-/locations/eu", limiter: connector.NewLimiter(10000), pageSize: 100}
	q := connector.Query{Start: time.Now().Add(-time.Hour), End: time.Now()}
	page, err := c.Fetch(context.Background(), q)
	if err != nil || page.NextToken != "second" || len(page.Records) != 1 {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if !strings.Contains(string(page.Records[0].Raw), "9007199254740993") || !strings.Contains(string(page.Records[0].Raw), "futureEnvelope") {
		t.Fatal("unknown source fields lost")
	}
	alert, err := c.Normalize(page.Records[0].Raw)
	if err != nil || alert.Resource.Name != "vendor-display" || alert.AlertType != "arbitrary-new-category" {
		t.Fatalf("alert=%+v err=%v", alert, err)
	}
	q.Token = page.NextToken
	page, err = c.Fetch(context.Background(), q)
	if err != nil || page.NextToken != "" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}
