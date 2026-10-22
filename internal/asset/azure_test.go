package asset

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func azureAccount() model.Account {
	return model.Account{ID: "connection", Provider: "azure", AccountUID: SyntheticAzureSubscription, Region: "eastasia", Options: map[string]string{"subscription_id": SyntheticAzureSubscription, "tenant_id": "synthetic-tenant"}}
}

func TestAzureInstanceMappingAndExactEvidence(t *testing.T) {
	value, err := ReadAzure(context.Background(), azureAccount(), SyntheticAzureVMID, SyntheticAzureRaw(), connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if value.Provider != "azure" || value.ResourceType != "vm" || value.Name != "synthetic-web-01" || value.OS != "Linux" {
		t.Fatalf("identity: %+v", value)
	}
	if value.State != "running" || value.InstanceType != "Standard_D2s_v5" || value.Zone != "1" {
		t.Fatalf("hardware: %+v", value)
	}
	if value.VPCID != SyntheticAzureVNetID || value.SubnetID != SyntheticAzureSubnetID || len(value.SecurityGroupIDs) != 1 || value.SecurityGroupIDs[0] != SyntheticAzureNSGID {
		t.Fatalf("network: %+v", value)
	}
	if len(value.PublicIPs) != 1 || value.PublicIPs[0] != "192.0.2.60" || len(value.PrivateIPs) != 1 || value.PrivateIPs[0] != "10.50.0.4" {
		t.Fatalf("addresses: %+v", value)
	}
	if len(value.Tags) != 1 || value.Tags[0].Key != "environment" {
		t.Fatalf("tags: %+v", value.Tags)
	}
	if len(value.References) != 4 {
		t.Fatalf("references: %+v", value.References)
	}
	c := value.Components["instance"]
	if c.RawHash != fmt.Sprintf("%x", sha256.Sum256(c.Raw)) || c.RawForm != "exact_bytes" {
		t.Fatal("source evidence changed")
	}
	if !strings.Contains(string(c.Raw), "9007199254740993") {
		t.Fatal("unknown integer lost")
	}
	if len(value.Components) < 5 || value.Components["security_group:"+SyntheticAzureNSGID].Status != "available" {
		t.Fatalf("components: %+v", value.Components)
	}
	if !strings.HasPrefix(value.ResourceID, "/subscriptions/") || value.ResourceID != strings.ToLower(value.ResourceID) {
		t.Fatal("ARM identity must be lowercase")
	}
}

func TestAzureSubscriptionScopeAndIdentity(t *testing.T) {
	other := azureAccount()
	other.Options = map[string]string{"subscription_id": "22222222-2222-2222-2222-222222222222"}
	calls := 0
	call := func(context.Context, string, map[string]string) (json.RawMessage, error) {
		calls++
		return nil, errors.New("scope check must run before any source call")
	}
	_, err := ReadAzure(context.Background(), other, SyntheticAzureVMID, call, connector.NewLimiter(100000))
	if !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("cross-subscription ID: err=%v, want ErrScopeMismatch", err)
	}
	if calls != 0 {
		t.Fatalf("scope mismatch called the source %d time(s)", calls)
	}
	for _, id := range []string{"synthetic-web-01", SyntheticAzureVMID + "/extra", "i-mock0001"} {
		if _, err := ReadAzure(context.Background(), azureAccount(), id, SyntheticAzureRaw(), connector.NewLimiter(100000)); err == nil {
			t.Fatal("invalid ID accepted", id)
		}
	}
}

func TestAzureNetworkMapping(t *testing.T) {
	a := azureAccount()
	for _, spec := range []struct {
		kind, id, raw, name, cidr string
	}{
		{"vpc", SyntheticAzureVNetID, SyntheticAzureVNet, "synthetic-vnet", "10.50.0.0/16"},
		{"subnet", SyntheticAzureSubnetID, SyntheticAzureSubnet, "synthetic-web-subnet", "10.50.0.0/24"},
		{"security_group", SyntheticAzureNSGID, SyntheticAzureNSG, "synthetic-nsg", ""},
	} {
		t.Run(spec.kind, func(t *testing.T) {
			items, err := readAzureNetworkBatch(context.Background(), a, spec.kind, []string{spec.id}, SyntheticAzureRaw(), connector.NewLimiter(100000))
			if err != nil {
				t.Fatal(err)
			}
			value := items[spec.id]
			if value == nil || value.Name != spec.name || value.Network.CIDRBlock != spec.cidr || value.Provider != "azure" {
				t.Fatalf("mapping: %+v", value)
			}
			c := value.Components["details"]
			if c.RawHash != fmt.Sprintf("%x", sha256.Sum256([]byte(spec.raw))) {
				t.Fatal("source evidence changed")
			}
			if spec.kind == "subnet" && (value.VPCID != SyntheticAzureVNetID || len(value.References) != 2) {
				t.Fatalf("subnet scope: %+v", value)
			}
			if spec.kind == "security_group" && value.Components["policies"].Status != "available" {
				t.Fatal("inline NSG rules missing")
			}
		})
	}
}

func TestAzureProviderIdentityAndValidation(t *testing.T) {
	p, ok := ProviderFor("azure")
	if !ok || p.HostType != "vm" || !p.RequiresRegion || !p.PoliciesInDetails {
		t.Fatalf("provider: %+v", p)
	}
	if id, ok := p.HostID(model.Resource{ID: strings.ToUpper(SyntheticAzureVMID), Type: "host"}); !ok || id != SyntheticAzureVMID {
		t.Fatalf("host identity: %s %v", id, ok)
	}
	if p.Valid("vm", strings.ToUpper(SyntheticAzureVMID)) {
		t.Fatal("validated a non-normalized ID")
	}
	if err := p.ValidateAccount(model.Account{}); err == nil {
		t.Fatal("missing subscription accepted")
	}
	if err := p.ValidateAccount(azureAccount()); err != nil {
		t.Fatal(err)
	}
	var instance map[string]json.RawMessage
	if err := json.Unmarshal([]byte(SyntheticAzureVM), &instance); err != nil {
		t.Fatal(err)
	}
}
