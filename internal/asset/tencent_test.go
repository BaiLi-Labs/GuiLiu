package asset

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/credential"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func TestTencentSourceBytesMappingAndPartialPolicies(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "tencent", AccountUID: "123", Region: "ap-guangzhou"}
	calls := 0
	call := func(_ context.Context, service, action string, params map[string]any) (json.RawMessage, error) {
		calls++
		if service == "cvm" {
			ids := params["InstanceIds"].([]string)
			if len(ids) != 1 || ids[0] != "ins-mock0001" || params["Limit"] != 1 {
				t.Fatal(params)
			}
			return json.RawMessage(`{"InstanceSet":[` + SyntheticInstance + `]}`), nil
		}
		if action == "DescribeNetworkInterfaces" {
			if _, ok := params["Filters"]; !ok {
				t.Fatal("ENI discovery must be scoped to the instance", params)
			}
			return json.RawMessage(`{"NetworkInterfaceSet":[` + SyntheticTencentENI + `],"TotalCount":1}`), nil
		}
		if action != "DescribeSecurityGroupPolicies" || params["SecurityGroupId"] != "sg-synthetic" {
			t.Fatal(action, params)
		}
		return nil, errors.New("AuthFailure: SECRET_DO_NOT_EXPOSE")
	}
	value, err := ReadTencent(context.Background(), a, "ins-mock0001", call, connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || value.OS != "TencentOS Server 3.1" || value.VPCID != "vpc-synthetic" || len(value.Tags) != 1 || value.Provenance["region"].Source != "configuration" {
		t.Fatalf("mapping: %+v", value)
	}
	if value.Components["network_interfaces"].Status != "available" {
		t.Fatalf("ENI discovery: %+v", value.Components["network_interfaces"])
	}
	foundNIC := false
	for _, ref := range value.References {
		if ref.ResourceType == "nic" && ref.ResourceID == "eni-mock0001" {
			foundNIC = true
		}
	}
	if !foundNIC {
		t.Fatalf("host lost ENI reference: %+v", value.References)
	}
	c := value.Components["instance"]
	if string(c.Raw) != SyntheticInstance || c.RawHash != fmt.Sprintf("%x", sha256.Sum256(c.Raw)) {
		t.Fatal("raw bytes or hash changed")
	}
	if c = value.Components["security_group:sg-synthetic"]; c.Status != "failed" || strings.Contains(c.Reason, "SECRET") {
		t.Fatalf("policy failure: %+v", c)
	}
	if value.Components["listening_ports"].Status != "not_collected" || value.Components["reachability"].ObservedAt != nil {
		t.Fatal("invented port observation")
	}
}

func TestTencentRequestBudgetAndUnknownFields(t *testing.T) {
	var instance map[string]json.RawMessage
	_ = json.Unmarshal([]byte(SyntheticInstance), &instance)
	instance["SecurityGroupIds"] = json.RawMessage(`["sg-1","sg-2","sg-3","sg-4","sg-5","sg-6"]`)
	delete(instance, "OsName")
	raw, _ := json.Marshal(instance)
	calls := 0
	call := func(_ context.Context, service, action string, _ map[string]any) (json.RawMessage, error) {
		calls++
		if service == "cvm" {
			return json.RawMessage(`{"InstanceSet":[` + string(raw) + `]}`), nil
		}
		if action == "DescribeNetworkInterfaces" {
			return json.RawMessage(`{"NetworkInterfaceSet":[],"TotalCount":0}`), nil
		}
		return json.RawMessage(SyntheticPolicy), nil
	}
	a, err := ReadTencent(context.Background(), model.Account{ID: "c", AccountUID: "123", Region: "r"}, "ins-mock0001", call, connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 7 || a.Components["security_group:sg-6"].Reason != "request_budget_exceeded" || a.OS != "" {
		t.Fatalf("unbounded or invented fields: %d %+v", calls, a)
	}
	if _, ok := a.Provenance["os"]; ok {
		t.Fatal("missing field received provenance")
	}
	if !strings.Contains(string(a.Components["instance"].Raw), "9007199254740993") {
		t.Fatal("unknown integer lost")
	}
	for _, id := range []string{"", "*", "ins-a/other"} {
		if _, err := ReadTencent(context.Background(), model.Account{}, id, call, connector.NewLimiter(100000)); err == nil {
			t.Fatal("invalid ID accepted")
		}
	}
	if calls != 7 {
		t.Fatal("invalid input invoked source")
	}
}

func TestRefreshCacheFailureAndDurableIndependentRevisions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "assets.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := secret.Load(base64.StdEncoding.EncodeToString(make([]byte, 32)), "")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := credential.Encrypt(cipher, connector.Credential{AccessKeyID: "synthetic-key", AccessKeySecret: "synthetic-secret"})
	if err != nil {
		t.Fatal(err)
	}
	a := model.Account{ID: "c", Name: "synthetic", Provider: "tencent", AccountUID: "123", Region: "ap-guangzhou", Enabled: true, CredentialEncrypted: blob}
	if err := st.CreateAccount(ctx, &a); err != nil {
		t.Fatal(err)
	}
	s := New(st, cipher, false)
	s.limiter = connector.NewLimiter(100000)
	calls := 0
	fail := false
	changed := false
	s.Factory = func(cred connector.Credential, region string) Call {
		if cred.AccessKeySecret != "synthetic-secret" || region != a.Region {
			t.Fatal("credential or region missing")
		}
		return func(ctx context.Context, service, action string, params map[string]any) (json.RawMessage, error) {
			calls++
			if fail {
				return nil, errors.New("AuthFailure: synthetic-secret")
			}
			if service == "cvm" {
				raw := SyntheticInstance
				if changed {
					raw = strings.Replace(raw, "synthetic-web-01", "renamed", 1)
				}
				return json.RawMessage(`{"InstanceSet":[` + raw + `]}`), nil
			}
			return SyntheticCall()(ctx, service, action, params)
		}
	}
	first, err := s.Refresh(ctx, a.ID, "cvm", "ins-mock0001")
	if err != nil || first.Status != "available" || first.Asset == nil || first.Asset.Revision != 1 {
		t.Fatalf("first: %+v %v", first, err)
	}
	if _, err = s.Refresh(ctx, a.ID, "cvm", "ins-mock0001"); err != nil || calls != 6 {
		t.Fatalf("cache: calls=%d %v", calls, err)
	}
	base := time.Now()
	s.now = func() time.Time { return base.Add(6 * time.Minute) }
	fail = true
	failed, err := s.Refresh(ctx, a.ID, "cvm", "ins-mock0001")
	if err != nil || failed.Status != "permission_denied" || failed.Asset.Revision != 1 {
		t.Fatalf("failure should retain observation: %+v %v", failed, err)
	}
	fail = false
	changed = true
	s.now = func() time.Time { return base.Add(12 * time.Minute) }
	updated, err := s.Refresh(ctx, a.ID, "cvm", "ins-mock0001")
	if err != nil || updated.Asset.Revision != 2 || updated.Asset.Name != "renamed" {
		t.Fatalf("revision: %+v %v", updated, err)
	}
	// A semantically identical observation does not create a third revision.
	s.now = func() time.Time { return base.Add(18 * time.Minute) }
	unchanged, err := s.Refresh(ctx, a.ID, "cvm", "ins-mock0001")
	if err != nil || unchanged.Asset.Revision != 2 {
		t.Fatalf("repeated observation: %+v %v", unchanged, err)
	}
	sequence, err := st.SnapshotSequence(ctx)
	if err != nil || sequence != 0 {
		t.Fatal("asset refresh changed Finding feed", sequence, err)
	}
	assetID := first.Asset.ID
	st.Close()
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	historical, err := st.GetAsset(ctx, assetID, 1)
	if err != nil || historical.Name != "synthetic-web-01" || string(historical.Components["instance"].Raw) != SyntheticInstance {
		t.Fatalf("historical evidence moved: %+v %v", historical, err)
	}
	otherProcess := New(st, cipher, false)
	otherProcess.Factory = func(connector.Credential, string) Call {
		t.Fatal("durable cache was bypassed after restart")
		return nil
	}
	cached, err := otherProcess.Refresh(ctx, a.ID, "cvm", "ins-mock0001")
	if err != nil || cached.Status != "cached" || cached.Asset.Revision != 2 {
		t.Fatalf("restart cache: %+v %v", cached, err)
	}
	old := *historical
	old.ObservedAt = historical.ObservedAt.Add(-time.Hour)
	if err := st.SaveAsset(ctx, &old); err == nil {
		t.Fatal("old observation replaced current asset")
	}
	a.Region = "ap-shanghai"
	if err := st.UpdateAccount(ctx, &a, nil); !errors.Is(err, store.ErrConflict) {
		t.Fatal("asset connection scope was mutable", err)
	}
}

func TestResponseBudgetRejectsOversizedAndTimeout(t *testing.T) {
	reader := &boundedBody{ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponseBytes+1))), remaining: maxResponseBytes}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("oversized response accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := ReadTencent(ctx, model.Account{}, "ins-1", func(context.Context, string, string, map[string]any) (json.RawMessage, error) {
		called = true
		return nil, nil
	}, connector.NewLimiter(1))
	if err == nil || called {
		t.Fatal("cancelled refresh called source")
	}
}
