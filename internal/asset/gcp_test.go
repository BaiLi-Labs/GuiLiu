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

func TestGCPInstanceMappingAndExactEvidence(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "gcp", AccountUID: SyntheticGCPProject, Region: ""}
	value, err := ReadGCP(context.Background(), a, SyntheticGCPInstanceID, SyntheticGCPRaw(), SyntheticGCPProject, connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if value.Provider != "gcp" || value.ResourceType != "gce" || value.Name != "synthetic-web-01" || value.State != "RUNNING" {
		t.Fatalf("identity: %+v", value)
	}
	if value.InstanceType != "e2-medium" || value.Zone != SyntheticGCPZone || value.OS != "debian-12" {
		t.Fatalf("hardware: %+v", value)
	}
	if value.VPCID != SyntheticGCPVPCID || value.SubnetID != SyntheticGCPSubnetID {
		t.Fatalf("network identity: %+v", value)
	}
	if len(value.PublicIPs) != 1 || value.PublicIPs[0] != "192.0.2.50" || len(value.PrivateIPs) != 1 || value.PrivateIPs[0] != "10.40.0.11" {
		t.Fatalf("addresses: %+v", value)
	}
	if len(value.Tags) != 1 || value.Tags[0].Key != "environment" || len(value.References) != 2 {
		t.Fatalf("tags/references: %+v %+v", value.Tags, value.References)
	}
	c := value.Components["instance"]
	if c.RawHash != fmt.Sprintf("%x", sha256.Sum256(c.Raw)) || c.RawForm != "exact_bytes" {
		t.Fatal("source evidence changed")
	}
	if !strings.Contains(string(c.Raw), "9007199254740993") {
		t.Fatal("unknown integer lost")
	}
	if value.Components["security_groups"].Reason != "source_has_no_instance_security_group_attachment" {
		t.Fatal("host must not claim a security group attachment")
	}
	if value.Provenance["vpc_id"].Transform != "source_url_to_resource_path" || value.Provenance["os"].Transform != "source_license_projection" {
		t.Fatalf("provenance: %+v", value.Provenance)
	}
}

func TestGCPNetworkMapping(t *testing.T) {
	a := model.Account{ID: "connection", Provider: "gcp", AccountUID: SyntheticGCPProject}
	for _, spec := range []struct {
		kind, id, raw, name, cidr string
	}{
		{"vpc", SyntheticGCPVPCID, SyntheticGCPVPC, "synthetic-vpc", "10.40.0.0/16"},
		{"subnet", SyntheticGCPSubnetID, SyntheticGCPSubnet, "synthetic-web-subnet", "10.40.0.0/24"},
		{"security_group", SyntheticGCPFirewallID, SyntheticGCPFirewall, "synthetic-allow-https", ""},
	} {
		t.Run(spec.kind, func(t *testing.T) {
			items, err := readGCPNetworkBatch(context.Background(), a, spec.kind, []string{spec.id}, SyntheticGCPRaw(), connector.NewLimiter(100000))
			if err != nil {
				t.Fatal(err)
			}
			value := items[spec.id]
			if value == nil || value.Name != spec.name || value.Network.CIDRBlock != spec.cidr || value.Provider != "gcp" {
				t.Fatalf("mapping: %+v", value)
			}
			c := value.Components["details"]
			if c.RawHash != fmt.Sprintf("%x", sha256.Sum256([]byte(spec.raw))) {
				t.Fatal("source evidence changed")
			}
			if spec.kind == "subnet" {
				if value.VPCID != SyntheticGCPVPCID || len(value.References) != 1 {
					t.Fatalf("subnet scope: %+v", value)
				}
			}
			if spec.kind == "security_group" {
				if value.Components["policies"].Status != "available" {
					t.Fatal("inline firewall rules missing")
				}
			}
		})
	}
}

func TestGCPProviderIdentity(t *testing.T) {
	p, ok := ProviderFor("gcp")
	if !ok || p.HostType != "gce" || p.RequiresRegion || !p.PoliciesInDetails {
		t.Fatalf("provider: %+v", p)
	}
	if id, ok := p.HostID(model.Resource{ID: "//compute.googleapis.com/" + SyntheticGCPInstanceID, Type: "host"}); !ok || id != SyntheticGCPInstanceID {
		t.Fatalf("host identity: %s %v", id, ok)
	}
	for _, bad := range []string{"synthetic-web-01", "projects/p/zones/z", "projects/p/zones/z/instances/n/extra"} {
		if p.Valid("gce", bad) {
			t.Fatal("invalid instance path accepted", bad)
		}
	}
	if p.Valid("vpc", SyntheticGCPSubnetID) || !p.Valid("subnet", SyntheticGCPSubnetID) || !p.Valid("security_group", SyntheticGCPFirewallID) {
		t.Fatal("resource kind validation broken")
	}
}

func TestGCPUnknownFieldsAndNoInference(t *testing.T) {
	var instance map[string]json.RawMessage
	if err := json.Unmarshal([]byte(SyntheticGCPInstance), &instance); err != nil {
		t.Fatal(err)
	}
	delete(instance, "disks")
	raw, _ := json.Marshal(instance)
	synthetic := func(_ context.Context, action string, params map[string]string) (json.RawMessage, error) {
		if action == "Instance" {
			return raw, nil
		}
		return SyntheticGCPRaw()(context.Background(), action, params)
	}
	a, err := ReadGCP(context.Background(), model.Account{ID: "c", AccountUID: SyntheticGCPProject}, SyntheticGCPInstanceID, synthetic, "", connector.NewLimiter(100000))
	if err != nil {
		t.Fatal(err)
	}
	if a.OS != "" {
		t.Fatalf("invented OS: %q", a.OS)
	}
	if _, ok := a.Provenance["os"]; ok {
		t.Fatal("missing field received provenance")
	}
}
