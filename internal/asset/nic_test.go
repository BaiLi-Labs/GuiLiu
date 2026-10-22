package asset

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestTencentNICMappingAndExactEvidence(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "tencent", AccountUID: "123", Region: "ap-guangzhou"}
	items, err := readTencentNICBatch(context.Background(), a, []string{"eni-mock0001"}, SyntheticCall(), connector.NewLimiter(100000), nil)
	if err != nil {
		t.Fatal(err)
	}
	value := items["eni-mock0001"]
	if value == nil || value.ResourceType != "nic" || value.ResourceID != "eni-mock0001" {
		t.Fatalf("identity: %+v", value)
	}
	if value.VPCID != "vpc-synthetic" || value.SubnetID != "subnet-synthetic" || len(value.SecurityGroupIDs) != 1 {
		t.Fatalf("network: %+v", value)
	}
	if len(value.PrivateIPs) != 1 || value.PrivateIPs[0] != "10.0.0.11" || value.Network == nil || value.Network.MACAddress == "" || value.Network.Primary == nil || !*value.Network.Primary {
		t.Fatalf("addresses/primary: %+v", value)
	}
	if len(value.Tags) != 1 || value.Tags[0].Key != "environment" {
		t.Fatalf("tags: %+v", value.Tags)
	}
	if !hasReference(value.References, "cvm", "ins-mock0001", "attached_to_host") || !hasReference(value.References, "security_group", "sg-synthetic", "attached_security_group") {
		t.Fatalf("references: %+v", value.References)
	}
	c := value.Components["details"]
	if string(c.Raw) != SyntheticTencentENI || c.RawHash != fmt.Sprintf("%x", sha256.Sum256(c.Raw)) {
		t.Fatal("source evidence changed")
	}
	if !strings.Contains(string(c.Raw), "9007199254740993") {
		t.Fatal("unknown integer lost")
	}
}

func TestAliyunNICMappingAndExactEvidence(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "aliyun", AccountUID: "123456789", Region: "cn-hangzhou"}
	items, err := readAliyunNICBatch(context.Background(), a, []string{"eni-mock0001"}, SyntheticAliyunCall(), connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	value := items["eni-mock0001"]
	if value == nil || value.VPCID != "vpc-synthetic" || value.SubnetID != "vsw-synthetic" || len(value.PrivateIPs) != 1 {
		t.Fatalf("identity/network: %+v", value)
	}
	if value.Network == nil || value.Network.MACAddress == "" || value.Network.Primary == nil || !*value.Network.Primary {
		t.Fatalf("primary/mac: %+v", value.Network)
	}
	if !hasReference(value.References, "ecs", "i-mock0001", "attached_to_host") {
		t.Fatalf("host reference: %+v", value.References)
	}
	c := value.Components["details"]
	if string(c.Raw) != SyntheticAliyunENI || c.RawHash != fmt.Sprintf("%x", sha256.Sum256(c.Raw)) {
		t.Fatal("source evidence changed")
	}
}

func TestAWSNICMappingAndExactEvidence(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "aws", AccountUID: "123456789012", Region: "ap-southeast-1"}
	items, err := readAWSNICBatch(context.Background(), a, []string{"eni-0123456789abcdef0"}, SyntheticAWSRaw(), connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	value := items["eni-0123456789abcdef0"]
	if value == nil || value.VPCID != SyntheticAWSVPCID || value.SubnetID != SyntheticAWSSubnetID {
		t.Fatalf("identity/network: %+v", value)
	}
	if len(value.PrivateIPs) != 1 || len(value.PublicIPs) != 1 || value.PublicIPs[0] != "192.0.2.40" {
		t.Fatalf("addresses: %+v", value)
	}
	if value.Network == nil || value.Network.Primary == nil || !*value.Network.Primary {
		t.Fatalf("primary: %+v", value.Network)
	}
	if !hasReference(value.References, "ec2", SyntheticAWSInstanceID, "attached_to_host") {
		t.Fatalf("host reference: %+v", value.References)
	}
	c := value.Components["details"]
	if c.RawForm != "api_projection" || c.RawHash != fmt.Sprintf("%x", sha256.Sum256(c.Raw)) {
		t.Fatalf("evidence form: %+v", c)
	}
}

func TestAzureNICMappingAndExactEvidence(t *testing.T) {
	a := azureAccount()
	items, err := readAzureNICBatch(context.Background(), a, []string{SyntheticAzureNICID}, SyntheticAzureRaw(), connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	value := items[SyntheticAzureNICID]
	if value == nil || value.ResourceType != "nic" || value.Name != "synthetic-nic-1" {
		t.Fatalf("identity: %+v", value)
	}
	if len(value.PrivateIPs) != 1 || value.PrivateIPs[0] != "10.50.0.4" || value.SubnetID != SyntheticAzureSubnetID || value.VPCID != SyntheticAzureVNetID {
		t.Fatalf("addresses/network: %+v", value)
	}
	if value.Network == nil || value.Network.Primary == nil || !*value.Network.Primary || value.Network.MACAddress == "" {
		t.Fatalf("primary/mac: %+v", value.Network)
	}
	if len(value.SecurityGroupIDs) != 1 || value.SecurityGroupIDs[0] != SyntheticAzureNSGID {
		t.Fatalf("security group: %+v", value.SecurityGroupIDs)
	}
	if !hasReference(value.References, "vm", SyntheticAzureVMID, "attached_to_host") {
		t.Fatalf("host reference: %+v", value.References)
	}
	if c := value.Components["details"]; c.RawForm != "exact_bytes" || c.RawHash != fmt.Sprintf("%x", sha256.Sum256(c.Raw)) {
		t.Fatalf("evidence: %+v", c)
	}
}

func hasReference(refs []model.AssetReference, kind, id, relation string) bool {
	for _, ref := range refs {
		if ref.ResourceType == kind && ref.ResourceID == id && ref.Relation == relation {
			return true
		}
	}
	return false
}
