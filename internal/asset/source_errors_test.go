package asset

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
)

func TestOfficialTencentDenialPreservesOtherComponents(t *testing.T) {
	ctx := context.Background()
	call := func(ctx context.Context, service, action string, params map[string]any) (json.RawMessage, error) {
		if action == "DescribeSecurityGroupPolicies" || action == "DescribeVpcs" {
			return nil, connector.WithSourceAPI("tencent", "VPC "+action, tcerrors.NewTencentCloudSDKError("UnauthorizedOperation", "DO_NOT_LEAK", "synthetic-request"))
		}
		return SyntheticCall()(ctx, service, action, params)
	}
	s, account := networkService(t, call)
	result, err := s.Refresh(ctx, account.ID, "cvm", "ins-mock0001")
	if err != nil || result.Status != "partial" || result.Asset == nil {
		t.Fatal(result, err)
	}
	policy := result.Asset.Components["security_group:sg-synthetic"]
	if policy.Status != "failed" || policy.Reason != "permission_denied" || policy.SourceError == nil || policy.SourceError.Code != "UnauthorizedOperation" || policy.SourceError.SourceAPI != "VPC DescribeSecurityGroupPolicies" || len(policy.Raw) != 0 {
		t.Fatalf("lost policy denial: %+v", policy)
	}
	if result.Asset.Components["instance"].Status != "available" || result.Asset.VPCID != "vpc-synthetic" {
		t.Fatal("lost observed instance facts")
	}
	attempt, err := s.Store.GetAssetRefresh(ctx, account.ID, account.Region, "vpc-synthetic")
	if err != nil || attempt.Status != "permission_denied" || attempt.SourceError == nil || attempt.SourceError.SourceAPI != "VPC DescribeVpcs" {
		t.Fatal(attempt, err)
	}
	stored, err := s.Store.GetAsset(ctx, result.Asset.ID, result.Asset.Revision)
	if err != nil || stored.Components["security_group:sg-synthetic"].SourceError.Code != "UnauthorizedOperation" {
		t.Fatal("component diagnostics were not persisted", err)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "DO_NOT_LEAK") {
		t.Fatal("SDK message leaked")
	}
}

func TestSourceCredentialsAreNotPresentedAsMissingPermissions(t *testing.T) {
	ctx := context.Background()
	s, account := networkService(t, func(context.Context, string, string, map[string]any) (json.RawMessage, error) {
		return nil, connector.WithSourceAPI("tencent", "CVM DescribeInstances", tcerrors.NewTencentCloudSDKError("AuthFailure.SignatureFailure", "DO_NOT_LEAK", ""))
	})
	result, err := s.Refresh(ctx, account.ID, "cvm", "ins-mock0001")
	if err != nil || result.Status != "authentication_failed" || result.Asset != nil || result.Attempt.SourceError.Kind != "auth" {
		t.Fatal(result, err)
	}
	for _, code := range []string{"ResourceNotFound", "RequestLimitExceeded"} {
		want := map[string]string{"ResourceNotFound": "not_found_or_not_visible", "RequestLimitExceeded": "throttled"}[code]
		if got := errorCode(tcerrors.NewTencentCloudSDKError(code, "ignored", ""), "tencent"); got != want {
			t.Fatalf("%s: %s", code, got)
		}
	}
}

func TestAzurePartialNetworkAuthorizationAndReferenceEvidence(t *testing.T) {
	account := model.Account{ID: "synthetic-azure", Provider: "azure", AccountUID: SyntheticAzureSubscription, Region: "eastasia", Options: map[string]string{"subscription_id": SyntheticAzureSubscription}}
	for _, denied := range []string{"NIC", "PublicIP", "NSG"} {
		t.Run(denied, func(t *testing.T) {
			call := func(ctx context.Context, action string, params map[string]string) (json.RawMessage, error) {
				if action == denied {
					return nil, &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}
				}
				return SyntheticAzureRaw()(ctx, action, params)
			}
			value, err := ReadAzure(context.Background(), account, SyntheticAzureVMID, call, connector.NewLimiter(100000))
			if err != nil || value == nil || value.Components["instance"].Status != "available" {
				t.Fatal("related denial discarded VM", err)
			}
			failed := false
			for _, c := range value.Components {
				if c.SourceError != nil && c.SourceError.Code == "AuthorizationFailed" && c.Reason == "permission_denied" {
					failed = true
				}
			}
			if !failed {
				t.Fatal("component denial not exposed")
			}
			for _, ref := range value.References {
				c, ok := value.Components[ref.SourceComponent]
				if !ok || len(c.Raw) == 0 || !sourcePointerExists(c.Raw, ref.SourcePath) {
					t.Fatalf("reference has no exact evidence: %+v", ref)
				}
			}
			if denied == "NSG" && len(value.SecurityGroupIDs) == 0 {
				t.Fatal("denied rule read discarded NIC's security group identity")
			}
		})
	}
}

func sourcePointerExists(raw json.RawMessage, path string) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	for _, key := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		switch current := value.(type) {
		case map[string]any:
			value = current[strings.ReplaceAll(strings.ReplaceAll(key, "~1", "/"), "~0", "~")]
		case []any:
			n, err := strconv.Atoi(key)
			if err != nil || n < 0 || n >= len(current) {
				return false
			}
			value = current[n]
		default:
			return false
		}
	}
	return value != nil
}
