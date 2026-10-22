package asset

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/credential"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
)

func networkService(t *testing.T, call Call) (*Service, model.Account) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "network.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cipher, err := secret.Load(base64.StdEncoding.EncodeToString(make([]byte, 32)), "")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := credential.Encrypt(cipher, connector.Credential{AccessKeyID: "synthetic-key", AccessKeySecret: "synthetic-secret"})
	if err != nil {
		t.Fatal(err)
	}
	a := model.Account{ID: "synthetic", Name: "synthetic", Provider: "tencent", AccountUID: "100000000001", Region: "ap-guangzhou", Enabled: true, CredentialEncrypted: blob}
	if err := st.CreateAccount(context.Background(), &a); err != nil {
		t.Fatal(err)
	}
	s := New(st, cipher, false)
	s.limiter = connector.NewLimiter(100000)
	s.Factory = func(connector.Credential, string) Call { return call }
	return s, a
}

func TestNetworkSourceMappingIdentityAndExactEvidence(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "tencent", AccountUID: "123", Region: "ap-guangzhou"}
	for _, spec := range []struct{ kind, id, raw, name, cidr string }{
		{"vpc", "vpc-synthetic", SyntheticVPC, "synthetic-production-network", "10.0.0.0/16"},
		{"subnet", "subnet-synthetic", SyntheticSubnet, "synthetic-web-subnet", "10.0.0.0/24"},
		{"security_group", "sg-synthetic", SyntheticSecurityGroup, "synthetic-web-access", ""},
	} {
		t.Run(spec.kind, func(t *testing.T) {
			calls := 0
			call := func(ctx context.Context, service, action string, params map[string]any) (json.RawMessage, error) {
				calls++
				if service != "vpc" {
					t.Fatal("unexpected service", service)
				}
				if action != "DescribeSecurityGroupPolicies" {
					_, _, field := networkAPI(spec.kind)
					if params["Limit"] != "1" || !reflect.DeepEqual(params[field+"s"], []string{spec.id}) || len(params) != 2 {
						t.Fatal("query escaped exact scope", params)
					}
				}
				return SyntheticCall()(ctx, service, action, params)
			}
			value, err := readNetwork(context.Background(), a, spec.kind, spec.id, call, connector.NewLimiter(100000))
			if err != nil {
				t.Fatal(err)
			}
			if value.Name != spec.name || value.Network.CIDRBlock != spec.cidr || value.AccountUID != a.AccountUID || value.Region != a.Region || value.Network.IsDefault == nil || *value.Network.IsDefault {
				t.Fatalf("mapping: %+v", value)
			}
			c := value.Components["details"]
			if string(c.Raw) != spec.raw || c.RawHash != fmt.Sprintf("%x", sha256.Sum256(c.Raw)) {
				t.Fatal("source evidence changed")
			}
			if value.Provenance["name"].Source != "component:details" || value.Provenance["account_uid"].Source != "configuration" {
				t.Fatal("missing provenance")
			}
			if spec.kind == "subnet" {
				if value.Tags == nil || len(value.Tags) != 0 || len(value.References) != 1 || value.References[0].SourcePath != "/VpcId" || value.References[0].AccountUID != a.AccountUID {
					t.Fatal("subnet source facts lost")
				}
				if !strings.Contains(string(c.Raw), "NetworkAclId") {
					t.Fatal("unmodeled fields lost")
				}
			}
			wantCalls := 1
			if spec.kind == "security_group" {
				wantCalls = 2
				if value.Network.Description == "" || value.Components["policies"].Status != "available" {
					t.Fatal("missing policy or description")
				}
			}
			if calls != wantCalls {
				t.Fatal("unexpected fanout", calls)
			}
		})
	}
}

func TestNetworkRejectsUnscopedAndMalformedSourceResults(t *testing.T) {
	for _, raw := range []string{`{}`, `{"VpcSet":null}`, `{"VpcSet":{}}`, `{"VpcSet":[null]}`, `{"VpcSet":[{"VpcId":"vpc-other"}]}`, `{"VpcSet":[{"VpcId":"vpc-synthetic"},{"VpcId":"vpc-synthetic"}]}`} {
		_, err := readNetworkBatch(context.Background(), model.Account{}, "vpc", []string{"vpc-synthetic"}, func(context.Context, string, string, map[string]any) (json.RawMessage, error) {
			return json.RawMessage(raw), nil
		}, connector.NewLimiter(100000))
		if err == nil {
			t.Fatal("invalid source accepted", raw)
		}
	}
	called := false
	call := func(context.Context, string, string, map[string]any) (json.RawMessage, error) {
		called = true
		return nil, nil
	}
	for _, ids := range [][]string{nil, {"vpc-*"}, {"vpc-a", "vpc-a"}, {"vpc-a", "vpc-b", "vpc-c", "vpc-d", "vpc-e", "vpc-f"}} {
		if _, err := readNetworkBatch(context.Background(), model.Account{}, "vpc", ids, call, connector.NewLimiter(100000)); err == nil {
			t.Fatal("invalid scope accepted", ids)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readNetworkBatch(ctx, model.Account{}, "vpc", []string{"vpc-a"}, call, connector.NewLimiter(100000)); err == nil || called {
		t.Fatal("invalid/cancelled query accessed cloud")
	}
	missing, err := readNetwork(context.Background(), model.Account{}, "vpc", "vpc-unseen", SyntheticCall(), connector.NewLimiter(100000))
	if !errors.Is(err, ErrNotVisible) || missing != nil {
		t.Fatal("absence became a fact", missing, err)
	}
}

func TestHostRefreshNetworkBudgetSharedCacheAndFailures(t *testing.T) {
	ctx := context.Background()
	counts := map[string]int{}
	call := func(ctx context.Context, service, action string, params map[string]any) (json.RawMessage, error) {
		counts[action]++
		if action == "DescribeInstances" {
			id := params["InstanceIds"].([]string)[0]
			raw := strings.Replace(SyntheticInstance, "ins-mock0001", id, 1)
			raw = strings.Replace(raw, `["sg-synthetic"]`, `["sg-a","sg-b","sg-c","sg-d","sg-e","sg-f"]`, 1)
			return json.RawMessage(`{"InstanceSet":[` + raw + `]}`), nil
		}
		if action == "DescribeSecurityGroups" {
			ids := params["SecurityGroupIds"].([]string)
			if len(ids) != 5 || params["Limit"] != "5" {
				t.Fatal("SG batch budget", params)
			}
			items := []json.RawMessage{}
			for _, id := range ids {
				items = append(items, json.RawMessage(strings.Replace(SyntheticSecurityGroup, "sg-synthetic", id, 1)))
			}
			return json.Marshal(map[string]any{"SecurityGroupSet": items})
		}
		return SyntheticCall()(ctx, service, action, params)
	}
	s, a := networkService(t, call)
	result, err := s.Refresh(ctx, a.ID, "cvm", "ins-first")
	if err != nil || result.Status != "partial" || result.Asset == nil {
		t.Fatalf("refresh %+v %v", result, err)
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if total != MaxRefreshRequests || counts["DescribeSecurityGroupPolicies"] != 5 || counts["DescribeSecurityGroups"] != 1 {
		t.Fatal("exceeded source budget", counts)
	}
	second, err := s.Refresh(ctx, a.ID, "cvm", "ins-second")
	if err != nil || second.Asset == nil {
		t.Fatal(second, err)
	}
	if counts["DescribeSecurityGroups"] != 1 || counts["DescribeVpcs"] != 1 || counts["DescribeSubnets"] != 1 {
		t.Fatal("shared network cache bypassed", counts)
	}
	before := counts["DescribeVpcs"]
	cached, err := s.Refresh(ctx, a.ID, "vpc", "vpc-synthetic")
	if err != nil || cached.Status != "cached" || cached.Asset == nil || counts["DescribeVpcs"] != before {
		t.Fatal("direct refresh ignored shared cooldown", cached, err)
	}
	seq, err := s.Store.SnapshotSequence(ctx)
	if err != nil || seq != 0 {
		t.Fatal("network updates changed Finding feed", seq, err)
	}
}

func TestOptionalNetworkTimeoutPreservesHostAndFailedAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	call := func(ctx context.Context, service, action string, params map[string]any) (json.RawMessage, error) {
		if action == "DescribeSecurityGroups" {
			cancel()
			return nil, context.Canceled
		}
		return SyntheticCall()(ctx, service, action, params)
	}
	s, a := networkService(t, call)
	result, err := s.Refresh(ctx, a.ID, "cvm", "ins-mock0001")
	if err != nil || result.Status != "partial" || result.Asset == nil || result.Asset.Name != "synthetic-web-01" {
		t.Fatal("optional timeout discarded host", result, err)
	}
	attempt, err := s.Store.GetAssetRefresh(context.Background(), a.ID, a.Region, "sg-synthetic")
	if err != nil || attempt.Status != "timeout" {
		t.Fatal("failed attempt lost", attempt, err)
	}
}

func TestIndependentNetworkRevisionCacheAndPermissionFailure(t *testing.T) {
	ctx := context.Background()
	fail, changed, calls := false, false, 0
	call := func(ctx context.Context, service, action string, params map[string]any) (json.RawMessage, error) {
		calls++
		if fail {
			return nil, tcerrors.NewTencentCloudSDKError("UnauthorizedOperation", "DO_NOT_LEAK", "synthetic-request")
		}
		raw, err := SyntheticCall()(ctx, service, action, params)
		if changed && action == "DescribeVpcs" {
			raw = json.RawMessage(strings.Replace(string(raw), "10.0.0.0/16", "10.1.0.0/16", 1))
		}
		return raw, err
	}
	s, a := networkService(t, call)
	base := time.Now()
	first, err := s.Refresh(ctx, a.ID, "vpc", "vpc-synthetic")
	if err != nil || first.Status != "available" || calls != 1 {
		t.Fatal(first, err, calls)
	}
	fail = true
	s.now = func() time.Time { return base.Add(6 * time.Minute) }
	failed, err := s.Refresh(ctx, a.ID, "vpc", "vpc-synthetic")
	if err != nil || failed.Status != "permission_denied" || failed.Asset.Revision != 1 {
		t.Fatal("failed refresh replaced old evidence", failed, err)
	}
	if _, err := s.Refresh(ctx, a.ID, "vpc", "vpc-synthetic"); err != nil || calls != 2 {
		t.Fatal("failure cooldown bypassed", calls, err)
	}
	fail = false
	changed = true
	s.now = func() time.Time { return base.Add(12 * time.Minute) }
	updated, err := s.Refresh(ctx, a.ID, "vpc", "vpc-synthetic")
	if err != nil || updated.Asset.Revision != 2 || updated.Asset.Network.CIDRBlock != "10.1.0.0/16" {
		t.Fatal(updated, err)
	}
	historical, err := s.Store.GetAsset(ctx, first.Asset.ID, 1)
	if err != nil || string(historical.Components["details"].Raw) != SyntheticVPC {
		t.Fatal("historical network evidence changed", historical, err)
	}
	before := calls
	if _, err := s.Refresh(ctx, a.ID, "subnet", "vpc-synthetic"); !errors.Is(err, ErrInvalidRequest) || calls != before {
		t.Fatal("resource type mismatch reached source")
	}
}
