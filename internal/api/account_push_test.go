package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/BaiLi-Labs/GuiLiu/internal/config"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector/cef"
	"github.com/BaiLi-Labs/GuiLiu/internal/intake"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

func TestPushAccountCreationRotationAndSecretRedaction(t *testing.T) {
	ts, st, _ := setup(t, true, func(reg *connector.Registry) {
		c, err := cef.New(connector.AccountConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Register(c.Info(), cef.New); err != nil {
			t.Fatal(err)
		}
	})
	client := newClient(t, ts)
	resp, body := do(t, client, http.MethodPost, ts.URL+"/api/v1/accounts", "", `{"name":"edge sensor","provider":"cef"}`)
	var created struct {
		view.Account
		Token string `json:"push_token"`
	}
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(body, &created) != nil || created.Token == "" {
		t.Fatalf("create push source = %d: %s", resp.StatusCode, body)
	}
	if !created.PushOnly || !created.PushConfigured || created.CredentialSet || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("push capabilities = %+v", created.Account)
	}
	account, err := st.GetAccount(context.Background(), created.ID)
	if err != nil || account.Options["push_token_sha256"] != intake.HashToken(created.Token) {
		t.Fatalf("only token hash must be persisted: %v", err)
	}
	resp, body = do(t, client, http.MethodPost, ts.URL+"/ingest/edge%20sensor", created.Token, "CEF:0|Acme|Sensor|1|42|probe|5|eventId=evt-1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initial token rejected = %d: %s", resp.StatusCode, body)
	}
	resp, body = do(t, client, http.MethodPost, ts.URL+"/api/v1/accounts/"+created.ID+"/push-token", "", "")
	var rotated struct {
		Token string `json:"push_token"`
		Path  string `json:"webhook_path"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &rotated) != nil || rotated.Token == "" || rotated.Token == created.Token || rotated.Path != "/ingest/edge%20sensor" {
		t.Fatalf("rotation response = %d: %s", resp.StatusCode, body)
	}
	resp, _ = do(t, client, http.MethodPost, ts.URL+rotated.Path, created.Token, "CEF:0|Acme|Sensor|1|42|probe|5|eventId=evt-2")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old token remained valid: %d", resp.StatusCode)
	}
	resp, body = do(t, client, http.MethodPost, ts.URL+rotated.Path, rotated.Token, "CEF:0|Acme|Sensor|1|42|probe|5|eventId=evt-2")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("new token rejected = %d: %s", resp.StatusCode, body)
	}
	for _, path := range []string{"/accounts", "/accounts/" + created.ID, "/audit-events"} {
		resp, body = do(t, client, http.MethodGet, ts.URL+"/api/v1"+path, "", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("read %s = %d: %s", path, resp.StatusCode, body)
		}
		for _, secret := range []string{created.Token, rotated.Token, intake.HashToken(rotated.Token), "push_token_sha256"} {
			if strings.Contains(string(body), secret) {
				t.Fatalf("secret exposed through %s", path)
			}
		}
	}
	// An unrelated account edit must not clear its newly generated token.
	resp, _ = do(t, client, http.MethodPatch, ts.URL+"/api/v1/accounts/"+created.ID, "", `{"options":{"default_device":"edge"}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("edit push source = %d", resp.StatusCode)
	}
	account, err = st.GetAccount(context.Background(), created.ID)
	if err != nil || account.Options["push_token_sha256"] != intake.HashToken(rotated.Token) {
		t.Fatal("editing options removed the push token")
	}
	ts.config.Accounts = []config.AccountConfig{{Name: created.Name, Provider: "cef", PushToken: "configuration-owned-token"}}
	resp, _ = do(t, client, http.MethodPost, ts.URL+"/api/v1/accounts/"+created.ID+"/push-token", "", "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("configuration-managed rotation = %d", resp.StatusCode)
	}
}

func TestPollingSourceCannotGeneratePushToken(t *testing.T) {
	ts, _, _ := setup(t, true)
	client := newClient(t, ts)
	id := createAccount(t, ts, client, "")
	resp, _ := do(t, client, http.MethodPost, ts.URL+"/api/v1/accounts/"+id+"/push-token", "", "")
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("polling-only rotation = %d", resp.StatusCode)
	}
}
