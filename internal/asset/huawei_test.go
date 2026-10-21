package asset

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestHuaweiInstanceMappingAndExactEvidence(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "huawei", AccountUID: "project-1", Region: "cn-north-4"}
	value, err := ReadHuawei(context.Background(), a, SyntheticHuaweiServerID, SyntheticHuaweiRaw(), connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if value.Provider != "huawei" || value.ResourceType != "ecs" || value.OS != "Huawei Cloud EulerOS 2.0" || value.State != "ACTIVE" {
		t.Fatalf("identity: %+v", value)
	}
	if value.InstanceType != "c6.large.2" || value.Zone != "cn-north-4a" || value.VPCID != SyntheticHuaweiVPCID || value.SubnetID != "" {
		t.Fatalf("hardware: %+v", value)
	}
	if len(value.PublicIPs) != 1 || value.PublicIPs[0] != "192.0.2.30" || len(value.PrivateIPs) != 1 || value.PrivateIPs[0] != "10.20.0.11" {
		t.Fatalf("addresses: %+v", value)
	}
	if len(value.Tags) != 1 || value.Tags[0].Key != "environment" || value.Tags[0].Value != "demo" {
		t.Fatalf("tags: %+v", value.Tags)
	}
	if value.Provenance["public_ips"].Transform != "source_field_filter_by_ip_type" || value.Provenance["region"].Source != "configuration" {
		t.Fatalf("provenance: %+v", value.Provenance)
	}
	c := value.Components["instance"]
	if string(c.Raw) != SyntheticHuaweiInstance || c.RawHash != fmt.Sprintf("%x", sha256.Sum256(c.Raw)) {
		t.Fatal("source evidence changed")
	}
	if !strings.Contains(string(c.Raw), "9007199254740993") {
		t.Fatal("unknown integer lost")
	}
	policy := value.Components["security_group:"+SyntheticHuaweiGroupID]
	if policy.Status != "available" || policy.SourceAPI != "VPC ShowSecurityGroup" || !strings.Contains(string(policy.Raw), "port_range_min") {
		t.Fatalf("policies: %+v", policy)
	}
	if len(value.References) != 2 || value.References[0].Relation != "belongs_to_vpc" || value.References[1].Relation != "attached_security_group" {
		t.Fatalf("references: %+v", value.References)
	}
}

func TestHuaweiRequestBudget(t *testing.T) {
	var server map[string]json.RawMessage
	if err := json.Unmarshal([]byte(SyntheticHuaweiInstance), &server); err != nil {
		t.Fatal(err)
	}
	groups := []map[string]string{}
	for i := 1; i <= 6; i++ {
		groups = append(groups, map[string]string{"id": fmt.Sprintf("00000000-0000-0000-0000-00000000000%d", i)})
	}
	encoded, _ := json.Marshal(groups)
	server["security_groups"] = encoded
	rawServer, _ := json.Marshal(server)
	calls := 0
	raw := func(_ context.Context, action string, _ map[string]string) (json.RawMessage, error) {
		calls++
		if action == "ShowServer" {
			return json.RawMessage(`{"server":` + string(rawServer) + `}`), nil
		}
		return json.RawMessage(`{"security_group":` + SyntheticHuaweiSecurityGroup + `}`), nil
	}
	a, err := ReadHuawei(context.Background(), model.Account{ID: "c", AccountUID: "p", Region: "cn-north-4"}, SyntheticHuaweiServerID, raw, connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 6 {
		t.Fatalf("request budget: %d", calls)
	}
	if a.Components["security_group:00000000-0000-0000-0000-000000000006"].Reason != "request_budget_exceeded" {
		t.Fatal("budget not visible")
	}
	if len(a.References) != 7 {
		t.Fatalf("references must preserve every source declaration: %d", len(a.References))
	}
	for _, id := range []string{"", "*", "ins-mock0001", "1111"} {
		if _, err := ReadHuawei(context.Background(), model.Account{}, id, raw, connector.NewLimiter(100000)); err == nil {
			t.Fatal("invalid ID accepted", id)
		}
	}
	if calls != 6 {
		t.Fatal("invalid input invoked source")
	}
}

func TestHuaweiNetworkAndInlinePolicies(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "huawei", AccountUID: "project-1", Region: "cn-north-4"}
	for _, spec := range []struct {
		kind, id, raw, name, cidr string
	}{
		{"vpc", SyntheticHuaweiVPCID, SyntheticHuaweiVPC, "synthetic-production-network", "10.20.0.0/16"},
		{"subnet", SyntheticHuaweiSubnetID, SyntheticHuaweiSubnet, "synthetic-web-subnet", "10.20.0.0/24"},
		{"security_group", SyntheticHuaweiGroupID, SyntheticHuaweiSecurityGroup, "synthetic-web-access", ""},
	} {
		t.Run(spec.kind, func(t *testing.T) {
			items, err := readHuaweiNetworkBatch(context.Background(), a, spec.kind, []string{spec.id}, SyntheticHuaweiRaw(), connector.NewLimiter(100000))
			if err != nil {
				t.Fatal(err)
			}
			value := items[spec.id]
			if value == nil || value.Name != spec.name || value.Network.CIDRBlock != spec.cidr || value.Provider != "huawei" {
				t.Fatalf("mapping: %+v", value)
			}
			c := value.Components["details"]
			if string(c.Raw) != spec.raw || c.RawHash != fmt.Sprintf("%x", sha256.Sum256([]byte(spec.raw))) {
				t.Fatal("source evidence changed")
			}
			if spec.kind == "security_group" {
				if value.Components["policies"].Status != "available" {
					t.Fatal("inline rules missing")
				}
				if value.VPCID != SyntheticHuaweiVPCID {
					t.Fatalf("security group vpc: %+v", value)
				}
			}
			if spec.kind == "subnet" && (value.VPCID != SyntheticHuaweiVPCID || len(value.References) != 1 || value.References[0].Provider != "huawei") {
				t.Fatalf("subnet reference: %+v", value)
			}
		})
	}
}

func TestHuaweiProviderIdentity(t *testing.T) {
	p, ok := ProviderFor("huawei")
	if !ok || p.HostType != "ecs" || !p.PoliciesInDetails || !p.Supports("subnet") {
		t.Fatalf("provider: %+v", p)
	}
	for _, kind := range []string{"host", "server", "vm", "ecs"} {
		if id, ok := p.HostID(model.Resource{ID: SyntheticHuaweiServerID, Type: kind}); !ok || id != SyntheticHuaweiServerID {
			t.Fatal("host identity rejected", kind)
		}
	}
	if _, ok := p.HostID(model.Resource{ID: "i-mock0001", Type: "host"}); ok {
		t.Fatal("non-UUID accepted")
	}
}
