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

func TestAWSInstanceMappingAndExactEvidence(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "aws", AccountUID: "123456789012", Region: "ap-southeast-1"}
	value, err := ReadAWS(context.Background(), a, SyntheticAWSInstanceID, SyntheticAWSRaw(), connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if value.Provider != "aws" || value.ResourceType != "ec2" || value.Name != "synthetic-web-01" || value.OS != "Linux/UNIX" {
		t.Fatalf("identity: %+v", value)
	}
	if value.State != "running" || value.InstanceType != "m7g.large" || value.Zone != "ap-southeast-1a" {
		t.Fatalf("hardware: %+v", value)
	}
	if value.VPCID != SyntheticAWSVPCID || value.SubnetID != SyntheticAWSSubnetID || len(value.SecurityGroupIDs) != 1 {
		t.Fatalf("network: %+v", value)
	}
	if len(value.PublicIPs) != 1 || value.PublicIPs[0] != "192.0.2.40" || len(value.PrivateIPs) != 1 || value.PrivateIPs[0] != "10.30.0.11" {
		t.Fatalf("addresses: %+v", value)
	}
	if len(value.Tags) != 2 || len(value.References) != 4 {
		t.Fatalf("tags/references: %+v %+v", value.Tags, value.References)
	}
	c := value.Components["instance"]
	if c.RawHash != fmt.Sprintf("%x", sha256.Sum256(c.Raw)) || !strings.Contains(string(c.Raw), "9007199254740993") {
		t.Fatal("source evidence changed")
	}
	if !strings.Contains(string(c.Raw), `"FutureVendorField"`) {
		t.Fatal("unknown field lost from component bytes")
	}
	policy := value.Components["security_group:"+SyntheticAWSGroupID]
	if policy.Status != "available" || !strings.Contains(string(policy.Raw), "IpPermissions") {
		t.Fatalf("policies: %+v", policy)
	}
	if value.Provenance["public_ips"].Transform != "source_field_projection" || value.Provenance["name"].Transform != "source_tag_name_projection" {
		t.Fatalf("provenance: %+v", value.Provenance)
	}
}

func TestAWSRequestBudgetAndIdentity(t *testing.T) {
	var instance map[string]json.RawMessage
	if err := json.Unmarshal([]byte(SyntheticAWSInstance), &instance); err != nil {
		t.Fatal(err)
	}
	groups := []map[string]string{}
	for i := 1; i <= 6; i++ {
		groups = append(groups, map[string]string{"GroupId": fmt.Sprintf("sg-0000000000000000%d", i)})
	}
	encoded, _ := json.Marshal(groups)
	instance["SecurityGroups"] = encoded
	rawInstance, _ := json.Marshal(instance)
	calls := 0
	raw := func(_ context.Context, action string, _ []string) (json.RawMessage, error) {
		calls++
		if action == "DescribeInstances" {
			return json.RawMessage(`{"Reservations":[{"Instances":[` + string(rawInstance) + `]}]}`), nil
		}
		return json.RawMessage(`{"SecurityGroups":[` + SyntheticAWSSecurityGroup + `]}`), nil
	}
	a, err := ReadAWS(context.Background(), model.Account{ID: "c", AccountUID: "1", Region: "r"}, SyntheticAWSInstanceID, raw, connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if calls != 6 || a.Components["security_group:sg-00000000000000006"].Reason != "request_budget_exceeded" {
		t.Fatalf("budget: %d %+v", calls, a.Components)
	}
	if len(a.References) != 9 {
		t.Fatalf("source references dropped: %d", len(a.References))
	}
	for _, id := range []string{"", "*", "ins-mock0001", "i-ABC"} {
		if _, err := ReadAWS(context.Background(), model.Account{}, id, raw, connector.NewLimiter(100000)); err == nil {
			t.Fatal("invalid ID accepted", id)
		}
	}
	if calls != 6 {
		t.Fatal("invalid input invoked source")
	}
}

func TestAWSNetworkMapping(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "aws", AccountUID: "123456789012", Region: "ap-southeast-1"}
	for _, spec := range []struct {
		kind, id, raw, name, cidr string
	}{
		{"vpc", SyntheticAWSVPCID, SyntheticAWSVPC, "synthetic-production-network", "10.30.0.0/16"},
		{"subnet", SyntheticAWSSubnetID, SyntheticAWSSubnet, "synthetic-web-subnet", "10.30.0.0/24"},
		{"security_group", SyntheticAWSGroupID, SyntheticAWSSecurityGroup, "synthetic-web-access", ""},
	} {
		t.Run(spec.kind, func(t *testing.T) {
			items, err := readAWSNetworkBatch(context.Background(), a, spec.kind, []string{spec.id}, SyntheticAWSRaw(), connector.NewLimiter(100000))
			if err != nil {
				t.Fatal(err)
			}
			value := items[spec.id]
			if value == nil || value.Name != spec.name || value.Network.CIDRBlock != spec.cidr || value.Provider != "aws" {
				t.Fatalf("mapping: %+v", value)
			}
			if spec.kind == "vpc" && (value.Network.IsDefault == nil || *value.Network.IsDefault) {
				t.Fatal("default flag lost")
			}
			if spec.kind == "security_group" && value.Components["policies"].Status != "available" {
				t.Fatal("inline rules missing")
			}
			c := value.Components["details"]
			if c.RawHash != fmt.Sprintf("%x", sha256.Sum256([]byte(spec.raw))) {
				t.Fatal("source evidence changed")
			}
		})
	}
}

func TestAWSProviderHostIdentityFromARN(t *testing.T) {
	p, ok := ProviderFor("aws")
	if !ok || p.HostType != "ec2" || !p.Supports("security_group") {
		t.Fatalf("provider: %+v", p)
	}
	arn := "arn:aws:ec2:ap-southeast-1:123456789012:instance/" + SyntheticAWSInstanceID
	if id, ok := p.HostID(model.Resource{ID: arn, Type: "AwsEc2Instance"}); !ok || id != SyntheticAWSInstanceID {
		t.Fatalf("ARN identity: %s %v", id, ok)
	}
	if _, ok := p.HostID(model.Resource{ID: "arn:aws:s3:::bucket", Type: "AwsS3Bucket"}); ok {
		t.Fatal("non-instance ARN accepted")
	}
}
