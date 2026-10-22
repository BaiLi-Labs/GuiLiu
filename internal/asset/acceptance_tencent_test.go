package asset

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// TestRealTencentAssetAcceptance is opt-in. It performs read-only Tencent
// Cloud calls against one explicitly supplied host and prints the observed
// identity, NIC and network references. It never runs in the normal suite.
func TestRealTencentAssetAcceptance(t *testing.T) {
	if os.Getenv("GUILIU_REAL_ACCEPTANCE") != "1" {
		t.Skip("set GUILIU_REAL_ACCEPTANCE=1 and the TENCENTCLOUD_* credentials to run")
	}
	hostID := os.Getenv("GUILIU_ACCEPT_HOST")
	accountUID := os.Getenv("GUILIU_ACCEPT_ACCOUNT_UID")
	region := os.Getenv("GUILIU_ACCEPT_REGION")
	ak, sk := os.Getenv("TENCENTCLOUD_SECRET_ID"), os.Getenv("TENCENTCLOUD_SECRET_KEY")
	if hostID == "" || accountUID == "" || region == "" || ak == "" || sk == "" {
		t.Fatal("GUILIU_ACCEPT_HOST, GUILIU_ACCEPT_ACCOUNT_UID, GUILIU_ACCEPT_REGION and TENCENTCLOUD_* credentials are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	a := model.Account{ID: "acceptance", Provider: "tencent", AccountUID: accountUID, Region: region}
	call := TencentCall(connector.Credential{AccessKeyID: ak, AccessKeySecret: sk}, region)
	limiter := connector.NewLimiter(2)
	cache := &nicCache{}

	host, err := readTencent(ctx, a, hostID, call, limiter, cache)
	if errors.Is(err, ErrNotVisible) {
		// The supplied ID can be stale. Discover one host in this account and
		// continue the same read path instead of guessing another ID.
		raw, listErr := call(ctx, "cvm", "DescribeInstances", map[string]any{"Limit": 5})
		if listErr != nil {
			t.Fatal(listErr)
		}
		var page struct{ InstanceSet []struct{ InstanceId string } }
		if json.Unmarshal(raw, &page) != nil || len(page.InstanceSet) == 0 {
			t.Fatalf("no host visible in %s; supplied ID %s may be stale or the credential may belong to another account", region, hostID)
		}
		hostID = page.InstanceSet[0].InstanceId
		t.Logf("supplied host not visible; discovered %s", hostID)
		host, err = readTencent(ctx, a, hostID, call, limiter, cache)
	}
	if err != nil {
		t.Fatal(err)
	}
	if host.ResourceID != hostID || host.Provider != "tencent" || host.Region != region {
		t.Fatalf("host identity: %+v", host)
	}
	if host.Components["network_interfaces"].Status != "available" {
		t.Fatalf("ENI discovery failed: %+v", host.Components["network_interfaces"])
	}
	var nicIDs []string
	for _, ref := range host.References {
		if ref.ResourceType == "nic" {
			nicIDs = append(nicIDs, ref.ResourceID)
		}
	}
	if len(nicIDs) == 0 {
		t.Fatal("host has no NIC reference")
	}
	nics, err := readTencentNICBatch(ctx, a, nicIDs, call, limiter, cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range nicIDs {
		nic := nics[id]
		if nic == nil || nic.ResourceType != "nic" || nic.VPCID == "" || nic.SubnetID == "" || len(nic.PrivateIPs) == 0 || nic.Network == nil || nic.Network.MACAddress == "" || len(nic.Components["details"].Raw) == 0 {
			t.Fatalf("NIC incomplete: %+v", nic)
		}
		attached := false
		for _, ref := range nic.References {
			if ref.ResourceType == "cvm" && ref.ResourceID == hostID && ref.Relation == "attached_to_host" {
				attached = true
			}
		}
		if !attached {
			t.Fatalf("NIC %s lost host relation: %+v", id, nic.References)
		}
	}

	var kinds []string
	verified := map[string]string{}
	for _, ref := range host.References {
		switch ref.ResourceType {
		case "vpc", "subnet", "security_group":
			if verified[ref.ResourceType] != "" {
				continue
			}
			items, err := readNetworkBatch(ctx, a, ref.ResourceType, []string{ref.ResourceID}, call, limiter)
			if err != nil || items[ref.ResourceID] == nil || items[ref.ResourceID].Name == "" {
				t.Fatalf("network resource %s/%s: %v %+v", ref.ResourceType, ref.ResourceID, err, items)
			}
			kinds = append(kinds, ref.ResourceType)
			verified[ref.ResourceType] = ref.ResourceID
		}
	}
	t.Logf("verified provider=tencent account=%s region=%s host=%s name=%q os=%q public_ips=%v private_ips=%v nics=%v refs=%v network=%v components=%d",
		accountUID, region, host.ResourceID, host.Name, host.OS, host.PublicIPs, host.PrivateIPs, nicIDs, kinds, verified, len(host.Components))
}
