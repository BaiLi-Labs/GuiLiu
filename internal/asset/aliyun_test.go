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

func TestAliyunInstanceMappingAndExactEvidence(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "aliyun", AccountUID: "123456789", Region: "cn-hangzhou"}
	value, err := ReadAliyun(context.Background(), a, "i-mock0001", SyntheticAliyunCall(), connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if value.Provider != "aliyun" || value.ResourceType != "ecs" || value.OS != "Alibaba Cloud Linux 3" || value.State != "Running" {
		t.Fatalf("identity: %+v", value)
	}
	if len(value.PublicIPs) != 1 || value.PublicIPs[0] != "192.0.2.20" || len(value.PrivateIPs) != 1 || value.PrivateIPs[0] != "10.10.0.11" {
		t.Fatalf("addresses: %+v", value)
	}
	if value.VPCID != "vpc-synthetic" || value.SubnetID != "vsw-synthetic" || len(value.SecurityGroupIDs) != 1 || value.SecurityGroupIDs[0] != "sg-synthetic" {
		t.Fatalf("network: %+v", value)
	}
	if len(value.Tags) != 1 || value.Tags[0].Key != "environment" || value.Tags[0].Value != "demo" {
		t.Fatalf("tags: %+v", value.Tags)
	}
	if value.Provenance["public_ips"].Transform != "source_field_merge" || value.Provenance["region"].Source != "configuration" {
		t.Fatalf("provenance: %+v", value.Provenance)
	}
	c := value.Components["instance"]
	if string(c.Raw) != SyntheticAliyunInstance || c.RawHash != fmt.Sprintf("%x", sha256.Sum256(c.Raw)) || c.APIVersion != aliyunECSAV {
		t.Fatal("source evidence changed")
	}
	if !strings.Contains(string(c.Raw), "9007199254740993") {
		t.Fatal("unknown integer lost")
	}
	if p := value.Components["security_group:sg-synthetic"]; p.Status != "available" || p.SourceAPI != "ECS DescribeSecurityGroupAttribute" {
		t.Fatalf("policies: %+v", p)
	}
	if value.Components["listening_ports"].Status != "not_collected" || value.Components["reachability"].ObservedAt != nil {
		t.Fatal("invented port observation")
	}
}

func TestAliyunRequestBudgetAndIdentity(t *testing.T) {
	var instance map[string]json.RawMessage
	if err := json.Unmarshal([]byte(SyntheticAliyunInstance), &instance); err != nil {
		t.Fatal(err)
	}
	instance["SecurityGroupIds"] = json.RawMessage(`{"SecurityGroupId":["sg-1","sg-2","sg-3","sg-4","sg-5","sg-6"]}`)
	raw, _ := json.Marshal(instance)
	calls := 0
	call := func(_ context.Context, service, action string, _ map[string]any) (json.RawMessage, error) {
		calls++
		if service == "ecs" && action == "DescribeInstances" {
			return json.RawMessage(`{"Instances":{"Instance":[` + string(raw) + `]},"TotalCount":1}`), nil
		}
		return json.RawMessage(SyntheticAliyunPolicy), nil
	}
	a, err := ReadAliyun(context.Background(), model.Account{ID: "c", AccountUID: "1", Region: "cn-hangzhou"}, "i-mock0001", call, connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 6 || a.Components["security_group:sg-6"].Reason != "request_budget_exceeded" {
		t.Fatalf("unbounded request budget: %d %+v", calls, a.Components)
	}
	for _, id := range []string{"", "*", "i-a/other", "ins-mock0001"} {
		if _, err := ReadAliyun(context.Background(), model.Account{}, id, call, connector.NewLimiter(100000)); err == nil {
			t.Fatal("invalid ID accepted", id)
		}
	}
	if calls != 6 {
		t.Fatal("invalid input invoked source")
	}
}

func TestAliyunNetworkMapping(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "aliyun", AccountUID: "123456789", Region: "cn-hangzhou"}
	for _, spec := range []struct {
		kind, id, raw, name, cidr string
	}{
		{"vpc", "vpc-synthetic", SyntheticAliyunVPC, "synthetic-production-network", "10.10.0.0/16"},
		{"subnet", "vsw-synthetic", SyntheticAliyunVSwitch, "synthetic-web-subnet", "10.10.0.0/24"},
		{"security_group", "sg-synthetic", SyntheticAliyunSecurityGroup, "synthetic-web-access", ""},
	} {
		t.Run(spec.kind, func(t *testing.T) {
			items, err := readAliyunNetworkBatch(context.Background(), a, spec.kind, []string{spec.id}, SyntheticAliyunCall(), connector.NewLimiter(100000))
			if err != nil {
				t.Fatal(err)
			}
			value := items[spec.id]
			if value == nil || value.Name != spec.name || value.Network.CIDRBlock != spec.cidr || value.Provider != "aliyun" {
				t.Fatalf("mapping: %+v", value)
			}
			if spec.kind != "security_group" && (value.Network.IsDefault == nil || *value.Network.IsDefault) {
				t.Fatal("default flag lost")
			}
			c := value.Components["details"]
			if string(c.Raw) != spec.raw || c.RawHash != fmt.Sprintf("%x", sha256.Sum256([]byte(spec.raw))) {
				t.Fatal("source evidence changed")
			}
			if spec.kind == "subnet" && (value.VPCID != "vpc-synthetic" || len(value.References) != 1 || value.References[0].ResourceType != "vpc") {
				t.Fatalf("subnet reference: %+v", value)
			}
		})
	}
}

func TestAliyunProviderIdentity(t *testing.T) {
	p, ok := ProviderFor("aliyun")
	if !ok || p.HostType != "ecs" || !p.Supports("subnet") || !p.Supports("security_group") {
		t.Fatalf("provider: %+v", p)
	}
	if id, ok := p.HostID(model.Resource{ID: "i-mock0001", Type: "host"}); !ok || id != "i-mock0001" {
		t.Fatal("host identity rejected")
	}
	if _, ok := p.HostID(model.Resource{ID: "vpc-synthetic", Type: "host"}); ok {
		t.Fatal("non-instance accepted as host")
	}
	for _, bad := range [][2]string{{"ecs", "ins-mock"}, {"vpc", "vsw-1"}, {"subnet", "vpc-1"}, {"security_group", "sg-1/2"}} {
		if p.Valid(bad[0], bad[1]) {
			t.Fatal("invalid resource accepted", bad)
		}
	}
}
