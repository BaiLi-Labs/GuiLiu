package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
)

type fakeCredential struct{}

func (fakeCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestFetchPaginatesAndFiltersTimeWindow(t *testing.T) {
	start := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	inside := `{"id":"/subscriptions/sub/providers/Microsoft.Security/locations/centralus/alerts/a1","name":"a1","properties":{"timeGeneratedUtc":"2026-10-20T08:15:00Z","startTimeUtc":"2026-10-20T08:10:00Z","endTimeUtc":"2026-10-20T08:20:00Z"}}`
	outside := `{"id":"/subscriptions/sub/providers/Microsoft.Security/locations/centralus/alerts/a2","name":"a2","properties":{"timeGeneratedUtc":"2026-10-19T08:15:00Z"}}`

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/subscriptions/sub/providers/Microsoft.Security/alerts":
			if r.URL.Query().Get("api-version") != apiVersion {
				t.Errorf("api-version = %q", r.URL.Query().Get("api-version"))
			}
			_, _ = w.Write([]byte(`{"nextLink":"` + server.URL + `/next","value":[` + inside + `,` + outside + `]}`))
		case "/next":
			_, _ = w.Write([]byte(`{"value":[` + inside + `]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := &Connector{
		credential:     fakeCredential{},
		subscriptionID: "sub",
		endpoint:       server.URL,
		scope:          server.URL + "/.default",
		limiter:        connector.NewLimiter(100),
		client:         server.Client(),
	}
	page, err := c.Fetch(context.Background(), connector.Query{Start: start, End: end, PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.NextToken == "" {
		t.Fatalf("first page = %+v", page)
	}
	if !strings.Contains(string(page.Records[0].Raw), `"a1"`) {
		t.Fatalf("wrong record: %s", page.Records[0].Raw)
	}

	page, err = c.Fetch(context.Background(), connector.Query{Start: start, End: end, Token: page.NextToken})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Records) != 1 || page.NextToken != "" {
		t.Fatalf("second page = %+v", page)
	}
}

func TestFetchClassifiesHTTPErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()
	c := &Connector{
		credential:     fakeCredential{},
		subscriptionID: "sub",
		endpoint:       server.URL,
		scope:          server.URL + "/.default",
		limiter:        connector.NewLimiter(100),
		client:         server.Client(),
	}
	_, err := c.Fetch(context.Background(), connector.Query{Start: time.Now().Add(-time.Hour), End: time.Now()})
	if !connector.AuthError(err) {
		t.Fatalf("error = %v, want auth error", err)
	}
}

func TestNewRequiresCompleteServicePrincipal(t *testing.T) {
	_, err := New(connector.AccountConfig{
		Options:    map[string]string{"subscription_id": "sub", "tenant_id": "tenant"},
		Credential: connector.Credential{AccessKeyID: "client"},
	})
	if err == nil {
		t.Fatal("expected missing secret error")
	}
}
