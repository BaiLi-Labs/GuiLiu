// Azure control-plane assets.
//
// Source APIs (read-only, exact ARM resource IDs only):
//
//	Microsoft.Compute/virtualMachines (with instanceView)
//	Microsoft.Network networkInterfaces, publicIPAddresses,
//	virtualNetworks, subnets, networkSecurityGroups
//
// The ARM pipeline transport captures exact response bytes. A VM's addresses,
// VPC, subnet and security group live on its NICs, so a host refresh follows
// only the NICs explicitly referenced by the VM (bounded) and never lists.
package asset

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const azureAPIVersion = "2024-07-01"
const azureMapperVersion = "azure-vm/v1"
const maxAzureNICs = 3
const maxAzurePublicIPs = 3

var azureProviderKinds = map[string]string{
	"vm":             "virtualmachines",
	"vpc":            "virtualnetworks",
	"subnet":         "subnets",
	"security_group": "networksecuritygroups",
}

type azureRecorderKey struct{}

type azureRecorder struct {
	mu   sync.Mutex
	body []byte
}

func (r *azureRecorder) store(data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.body = data
}

func (r *azureRecorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body
}

// azureCapture keeps exact ARM response bytes before the SDK decodes them.
type azureCapture struct{}

func (t *azureCapture) Do(req *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	recorder, ok := req.Context().Value(azureRecorderKey{}).(*azureRecorder)
	if !ok || response.Body == nil {
		return response, nil
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("asset response exceeds size limit")
	}
	recorder.store(data)
	response.Body = io.NopCloser(bytes.NewReader(data))
	return response, nil
}

// azureRaw performs one exact ARM read. Actions are limited to the declared
// read-only resource types.
type azureRaw func(ctx context.Context, action string, params map[string]string) (json.RawMessage, error)

func AzureRaw(cred connector.Credential, a model.Account) (azureRaw, error) {
	subscription := ""
	tenant := ""
	if a.Options != nil {
		subscription = a.Options["subscription_id"]
		tenant = a.Options["tenant_id"]
	}
	if subscription == "" {
		return nil, fmt.Errorf("Azure subscription_id option is required")
	}
	if tenant == "" {
		return nil, fmt.Errorf("Azure tenant_id option is required")
	}
	credential, err := azidentity.NewClientSecretCredential(tenant, cred.AccessKeyID, cred.AccessKeySecret, nil)
	if err != nil {
		return nil, err
	}
	options := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{Transport: &azureCapture{}}}
	vms, err := armcompute.NewVirtualMachinesClient(subscription, credential, options)
	if err != nil {
		return nil, err
	}
	nics, err := armnetwork.NewInterfacesClient(subscription, credential, options)
	if err != nil {
		return nil, err
	}
	pips, err := armnetwork.NewPublicIPAddressesClient(subscription, credential, options)
	if err != nil {
		return nil, err
	}
	vnets, err := armnetwork.NewVirtualNetworksClient(subscription, credential, options)
	if err != nil {
		return nil, err
	}
	subnets, err := armnetwork.NewSubnetsClient(subscription, credential, options)
	if err != nil {
		return nil, err
	}
	groups, err := armnetwork.NewSecurityGroupsClient(subscription, credential, options)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, action string, params map[string]string) (json.RawMessage, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		recorder := &azureRecorder{}
		ctx = context.WithValue(ctx, azureRecorderKey{}, recorder)
		var callErr error
		switch action {
		case "VM":
			expand := armcompute.InstanceViewTypesInstanceView
			_, callErr = vms.Get(ctx, params["resourceGroup"], params["name"], &armcompute.VirtualMachinesClientGetOptions{Expand: &expand})
		case "NIC":
			_, callErr = nics.Get(ctx, params["resourceGroup"], params["name"], nil)
		case "PublicIP":
			_, callErr = pips.Get(ctx, params["resourceGroup"], params["name"], nil)
		case "VNet":
			_, callErr = vnets.Get(ctx, params["resourceGroup"], params["name"], nil)
		case "Subnet":
			_, callErr = subnets.Get(ctx, params["resourceGroup"], params["vnet"], params["name"], nil)
		case "NSG":
			_, callErr = groups.Get(ctx, params["resourceGroup"], params["name"], nil)
		default:
			return nil, fmt.Errorf("unsupported asset action")
		}
		if callErr != nil {
			return nil, callErr
		}
		if raw := recorder.bytes(); len(raw) > 0 {
			return append(json.RawMessage(nil), raw...), nil
		}
		return nil, fmt.Errorf("Azure API returned no response bytes")
	}, nil
}

type azureClient struct {
	raw     azureRaw
	limiter *connector.Limiter
}

func (c *azureClient) ReadInstance(ctx context.Context, a model.Account, id string) (*model.Asset, error) {
	return ReadAzure(ctx, a, id, c.raw, c.limiter)
}

func (c *azureClient) ReadNetwork(ctx context.Context, a model.Account, kind string, ids []string) (map[string]*model.Asset, error) {
	return readAzureNetworkBatch(ctx, a, kind, ids, c.raw, c.limiter)
}

func (c *azureClient) ReadPolicies(ctx context.Context, a model.Account, id string) (model.AssetComponent, error) {
	return model.AssetComponent{Status: "not_collected", Reason: "policies_included_in_details"}, nil
}

func azureLower(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func azureSegments(id string) []string {
	return strings.Split(strings.Trim(azureLower(id), "/"), "/")
}

func azureNameAfter(id, key string) string {
	parts := azureSegments(id)
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == key {
			return parts[i+1]
		}
	}
	return ""
}

func azureResourceGroup(id string) string { return azureNameAfter(id, "resourcegroups") }

func azureSubscription(id string) string { return azureNameAfter(id, "subscriptions") }

func azureHasProvider(id, provider, kind string) bool {
	lower := azureLower(id)
	return strings.Contains(lower, "/providers/"+provider+"/"+kind+"/") && azureNameAfter(id, kind) != ""
}

// azureVMID accepts the native ARM ID only; names alone cannot identify a VM.
func azureVMID(value string) (string, bool) {
	id := azureLower(value)
	if !azureHasProvider(id, "microsoft.compute", "virtualmachines") {
		return "", false
	}
	if azureResourceGroup(id) == "" || azureSubscription(id) == "" {
		return "", false
	}
	return id, true
}

// ReadAzure requests exactly one VM plus the NICs it explicitly references.
func ReadAzure(ctx context.Context, a model.Account, id string, raw azureRaw, limiter *connector.Limiter) (*model.Asset, error) {
	vmID, ok := azureVMID(id)
	if !ok {
		return nil, fmt.Errorf("invalid Azure virtual machine resource ID")
	}
	subscription := ""
	if a.Options != nil {
		subscription = a.Options["subscription_id"]
	}
	if subscription != "" && !strings.EqualFold(azureSubscription(vmID), subscription) {
		return nil, ErrNotVisible
	}
	rg := azureResourceGroup(vmID)
	name := azureNameAfter(vmID, "virtualmachines")
	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}
	vmRaw, err := raw(ctx, "VM", map[string]string{"resourceGroup": rg, "name": name})
	if err != nil {
		return nil, err
	}
	var vm struct {
		ID         string             `json:"id"`
		Name       string             `json:"name"`
		Location   string             `json:"location"`
		Tags       map[string]*string `json:"tags"`
		Zones      []string           `json:"zones"`
		Properties struct {
			HardwareProfile struct {
				VMSize string `json:"vmSize"`
			} `json:"hardwareProfile"`
			StorageProfile struct {
				OSDisk struct {
					OSType string `json:"osType"`
				} `json:"osDisk"`
			} `json:"storageProfile"`
			NetworkProfile struct {
				NetworkInterfaces []struct {
					ID string `json:"id"`
				} `json:"networkInterfaces"`
			} `json:"networkProfile"`
			InstanceView struct {
				Statuses []struct {
					Code string `json:"code"`
				} `json:"statuses"`
			} `json:"instanceView"`
		} `json:"properties"`
	}
	if json.Unmarshal(vmRaw, &vm) != nil || !strings.EqualFold(vm.ID, vmID) {
		return nil, fmt.Errorf("virtual machine identity mismatch")
	}
	state := ""
	for _, status := range vm.Properties.InstanceView.Statuses {
		if strings.HasPrefix(status.Code, "PowerState/") {
			state = strings.TrimPrefix(status.Code, "PowerState/")
		}
	}
	truncatedNICs := len(vm.Properties.NetworkProfile.NetworkInterfaces) > maxAzureNICs
	if truncatedNICs {
		// Bounded refresh: read the declared order, never widen the scope.
		vm.Properties.NetworkProfile.NetworkInterfaces = vm.Properties.NetworkProfile.NetworkInterfaces[:maxAzureNICs]
	}
	var publicIPs, privateIPs []string
	var references []model.AssetReference
	var networkComponents = map[string]model.AssetComponent{}
	var nicRaw []json.RawMessage
	seenRef := map[string]bool{}
	publicRefs := []string{}
	nsgRefs := []string{}
	for n, nicRef := range vm.Properties.NetworkProfile.NetworkInterfaces {
		nicID := azureLower(nicRef.ID)
		nicName := azureNameAfter(nicID, "networkinterfaces")
		if nicName == "" {
			continue
		}
		if !seenRef["nic|"+nicID] {
			seenRef["nic|"+nicID] = true
			references = append(references, reference(a, "nic", nicID, "attached_network_interface", "instance", fmt.Sprintf("/properties/networkProfile/networkInterfaces/%d/id", n)))
		}
		if err := limiter.Wait(ctx); err != nil {
			return nil, err
		}
		nicPayload, err := raw(ctx, "NIC", map[string]string{"resourceGroup": azureResourceGroup(nicID), "name": nicName})
		if err != nil {
			return nil, err
		}
		var nic struct {
			ID         string `json:"id"`
			Properties struct {
				IPConfigurations []struct {
					Properties struct {
						PrivateIPAddress string `json:"privateIPAddress"`
						PublicIPAddress  struct {
							ID string `json:"id"`
						} `json:"publicIPAddress"`
						Subnet struct {
							ID string `json:"id"`
						} `json:"subnet"`
					} `json:"properties"`
				} `json:"ipConfigurations"`
				NetworkSecurityGroup struct {
					ID string `json:"id"`
				} `json:"networkSecurityGroup"`
			} `json:"properties"`
		}
		if json.Unmarshal(nicPayload, &nic) != nil || !strings.EqualFold(nic.ID, nicID) {
			return nil, fmt.Errorf("network interface identity mismatch")
		}
		nicRaw = append(nicRaw, nicPayload)
		for _, config := range nic.Properties.IPConfigurations {
			if config.Properties.PrivateIPAddress != "" {
				privateIPs = append(privateIPs, config.Properties.PrivateIPAddress)
			}
			if pip := azureLower(config.Properties.PublicIPAddress.ID); pip != "" {
				publicRefs = append(publicRefs, pip)
			}
			if subnet := azureLower(config.Properties.Subnet.ID); subnet != "" {
				if !seenRef["subnet|"+subnet] {
					seenRef["subnet|"+subnet] = true
					references = append(references, reference(a, "subnet", subnet, "in_subnet", "network_interface", "/properties/ipConfigurations/0/properties/subnet/id"))
				}
				if vnet := azureIDBefore(subnet, "subnets"); vnet != "" && !seenRef["vpc|"+vnet] {
					seenRef["vpc|"+vnet] = true
					references = append(references, reference(a, "vpc", vnet, "belongs_to_vpc", "network_interface", "/properties/ipConfigurations/0/properties/subnet/id"))
				}
			}
		}
		if nsg := azureLower(nic.Properties.NetworkSecurityGroup.ID); nsg != "" {
			nsgRefs = append(nsgRefs, nsg)
		}
	}
	publicRefs = dedupeSort(publicRefs)
	truncatedPublicIPs := len(publicRefs) > maxAzurePublicIPs
	if truncatedPublicIPs {
		publicRefs = publicRefs[:maxAzurePublicIPs]
	}
	for _, pipID := range publicRefs {
		name := azureNameAfter(pipID, "publicipaddresses")
		if name == "" {
			continue
		}
		if err := limiter.Wait(ctx); err != nil {
			return nil, err
		}
		pipPayload, err := raw(ctx, "PublicIP", map[string]string{"resourceGroup": azureResourceGroup(pipID), "name": name})
		if err != nil {
			return nil, err
		}
		var pip struct {
			Properties struct {
				IPAddress string `json:"ipAddress"`
			} `json:"properties"`
		}
		if json.Unmarshal(pipPayload, &pip) != nil {
			return nil, fmt.Errorf("public IP response invalid")
		}
		if pip.Properties.IPAddress != "" {
			publicIPs = append(publicIPs, pip.Properties.IPAddress)
		}
	}
	nsgRefs = dedupeSort(nsgRefs)
	for n, nsgID := range nsgRefs {
		key := "security_group:" + nsgID
		c := model.AssetComponent{Status: "not_collected", Reason: "request_budget_exceeded", SourceAPI: "Network SecurityGroups.Get", APIVersion: azureAPIVersion}
		if n >= MaxSecurityGroups {
			networkComponents[key] = c
			references = append(references, reference(a, "security_group", nsgID, "attached_security_group", "network_interface", "/properties/networkSecurityGroup/id"))
			continue
		}
		name := azureNameAfter(nsgID, "networksecuritygroups")
		if name == "" {
			c.Reason = "invalid_source_reference"
			networkComponents[key] = c
			continue
		}
		if err := limiter.Wait(ctx); err != nil {
			c.Status, c.Reason = "failed", "timeout"
			networkComponents[key] = c
			continue
		}
		nsgPayload, err := raw(ctx, "NSG", map[string]string{"resourceGroup": azureResourceGroup(nsgID), "name": name})
		if err != nil {
			c.Status, c.Reason = "failed", errorCode(err, "azure")
			networkComponents[key] = c
			continue
		}
		networkComponents[key] = component(nsgPayload, "Network SecurityGroups.Get", azureAPIVersion, time.Now().UTC())
		references = append(references, reference(a, "security_group", nsgID, "attached_security_group", "network_interface", "/properties/networkSecurityGroup/id"))
	}
	var vpcID, subnetID string
	for _, ref := range references {
		switch ref.ResourceType {
		case "vpc":
			if vpcID == "" {
				vpcID = ref.ResourceID
			}
		case "subnet":
			if subnetID == "" {
				subnetID = ref.ResourceID
			}
		}
	}
	at := time.Now().UTC()
	out := &model.Asset{
		AccountID: a.ID, Provider: "azure", AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: vmID, ResourceType: "vm", Name: vm.Name, OS: vm.Properties.StorageProfile.OSDisk.OSType,
		State: state, InstanceType: vm.Properties.HardwareProfile.VMSize,
		PublicIPs: dedupeSort(publicIPs), PrivateIPs: dedupeSort(privateIPs),
		VPCID: vpcID, SubnetID: subnetID, ObservedAt: at, MapperVersion: azureMapperVersion,
		Components: map[string]model.AssetComponent{"instance": component(vmRaw, "Compute VirtualMachines.Get", azureAPIVersion, at)},
		Provenance: map[string]model.FieldOrigin{},
	}
	if len(vm.Zones) > 0 {
		out.Zone = vm.Zones[0]
	}
	for _, nsgID := range nsgRefs {
		out.SecurityGroupIDs = append(out.SecurityGroupIDs, nsgID)
	}
	if vm.Tags != nil {
		out.Tags = azureTags(vm.Tags)
		out.Provenance["tags"] = model.FieldOrigin{Source: "component:instance", Paths: []string{"/tags"}, Transform: "source_map_projection"}
	}
	out.References = references
	for n, payload := range nicRaw {
		key := fmt.Sprintf("network_interface:%d", n)
		out.Components[key] = component(payload, "Network Interfaces.Get", azureAPIVersion, at)
	}
	for key, c := range networkComponents {
		out.Components[key] = c
	}
	if truncatedNICs {
		out.Components["network_interfaces"] = model.AssetComponent{Status: "not_collected", Reason: "request_budget_exceeded"}
	}
	if truncatedPublicIPs {
		out.Components["public_ips"] = model.AssetComponent{Status: "not_collected", Reason: "request_budget_exceeded"}
	}
	out.Components["software"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["listening_ports"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["reachability"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	for field, path := range map[string]string{"resource_id": "/id", "name": "/name", "os": "/properties/storageProfile/osDisk/osType", "state": "/properties/instanceView/statuses", "instance_type": "/properties/hardwareProfile/vmSize", "zone": "/zones/0", "vpc_id": "/properties/networkProfile/networkInterfaces/0/id", "subnet_id": "/properties/networkProfile/networkInterfaces/0/id", "public_ips": "/properties/networkProfile/networkInterfaces/0/id", "private_ips": "/properties/networkProfile/networkInterfaces/0/id"} {
		if sourceHas(vmRaw, path) {
			out.Provenance[field] = model.FieldOrigin{Source: "component:instance", Paths: []string{path}, Transform: "source_field_projection"}
		}
	}
	for field, path := range map[string]string{"account_uid": "/account_uid", "region": "/region"} {
		out.Provenance[field] = model.FieldOrigin{Source: "configuration", Paths: []string{path}, Transform: "explicit_connection_scope"}
	}
	return out, nil
}

// azureIDBefore returns the parent resource ID for a nested ARM path.
func azureIDBefore(id, key string) string {
	id = azureLower(id)
	index := strings.Index(id, "/"+key+"/")
	if index < 0 {
		return ""
	}
	return id[:index]
}

func readAzureNetworkBatch(ctx context.Context, a model.Account, kind string, ids []string, raw azureRaw, limiter *connector.Limiter) (map[string]*model.Asset, error) {
	if kind == "nic" {
		return readAzureNICBatch(ctx, a, ids, raw, limiter)
	}
	kindSegment, ok := azureProviderKinds[kind]
	if !ok || kind == "vm" || len(ids) == 0 || len(ids) > MaxSecurityGroups {
		return nil, fmt.Errorf("invalid network query scope")
	}
	out := map[string]*model.Asset{}
	seen := map[string]bool{}
	for _, id := range ids {
		resourceID := azureLower(id)
		if !ValidAzureResource(kind, resourceID) || seen[resourceID] {
			return nil, fmt.Errorf("invalid or repeated network ID")
		}
		if subscription := a.Options["subscription_id"]; subscription != "" && !strings.EqualFold(azureSubscription(resourceID), subscription) {
			return nil, ErrNotVisible
		}
		seen[resourceID] = true
		rg := azureResourceGroup(resourceID)
		name := azureNameAfter(resourceID, kindSegment)
		action := map[string]string{"vpc": "VNet", "subnet": "Subnet", "security_group": "NSG"}[kind]
		params := map[string]string{"resourceGroup": rg, "name": name}
		if kind == "subnet" {
			params["vnet"] = azureNameAfter(azureIDBefore(resourceID, "subnets"), "virtualnetworks")
		}
		if err := limiter.Wait(ctx); err != nil {
			return nil, err
		}
		payload, err := raw(ctx, action, params)
		if err != nil {
			return nil, err
		}
		value, err := normalizeAzureNetwork(a, kind, resourceID, payload)
		if err != nil {
			return nil, err
		}
		out[resourceID] = value
	}
	return out, nil
}

// readAzureNICBatch reads exact NIC ARM IDs. The NIC is the Azure resource
// that carries private/public IPs and the NSG attachment.
func readAzureNICBatch(ctx context.Context, a model.Account, ids []string, raw azureRaw, limiter *connector.Limiter) (map[string]*model.Asset, error) {
	if len(ids) == 0 || len(ids) > MaxNICs {
		return nil, fmt.Errorf("invalid network interface query scope")
	}
	out := map[string]*model.Asset{}
	seen := map[string]bool{}
	for _, id := range ids {
		resourceID := azureLower(id)
		if !ValidAzureResource("nic", resourceID) || seen[resourceID] {
			return nil, fmt.Errorf("invalid or repeated network interface ID")
		}
		if subscription := a.Options["subscription_id"]; subscription != "" && !strings.EqualFold(azureSubscription(resourceID), subscription) {
			return nil, ErrNotVisible
		}
		seen[resourceID] = true
		if err := limiter.Wait(ctx); err != nil {
			return nil, err
		}
		payload, err := raw(ctx, "NIC", map[string]string{
			"resourceGroup": azureResourceGroup(resourceID),
			"name":          azureNameAfter(resourceID, "networkinterfaces"),
		})
		if err != nil {
			return nil, err
		}
		value, err := normalizeAzureNIC(a, resourceID, payload)
		if err != nil {
			return nil, err
		}
		out[resourceID] = value
	}
	return out, nil
}

func normalizeAzureNIC(a model.Account, id string, raw json.RawMessage) (*model.Asset, error) {
	var value struct {
		ID         string             `json:"id"`
		Name       string             `json:"name"`
		Tags       map[string]*string `json:"tags"`
		Location   string             `json:"location"`
		Properties struct {
			MACAddress     string `json:"macAddress"`
			VirtualMachine struct {
				ID string `json:"id"`
			} `json:"virtualMachine"`
			NetworkSecurityGroup struct {
				ID string `json:"id"`
			} `json:"networkSecurityGroup"`
			IPConfigurations []struct {
				Properties struct {
					PrivateIPAddress string `json:"privateIPAddress"`
					Primary          *bool  `json:"primary"`
					PublicIPAddress  struct {
						ID string `json:"id"`
					} `json:"publicIPAddress"`
					Subnet struct {
						ID string `json:"id"`
					} `json:"subnet"`
				} `json:"properties"`
			} `json:"ipConfigurations"`
		} `json:"properties"`
	}
	if json.Unmarshal(raw, &value) != nil || !strings.EqualFold(value.ID, id) {
		return nil, fmt.Errorf("network interface identity mismatch")
	}
	primary := false
	var subnetID, nsgID string
	for _, config := range value.Properties.IPConfigurations {
		if config.Properties.Primary != nil && *config.Properties.Primary {
			primary = true
		}
		if config.Properties.PrivateIPAddress != "" {
			// Collected below after normalization.
		}
		if subnet := azureLower(config.Properties.Subnet.ID); subnet != "" && subnetID == "" {
			subnetID = subnet
		}
	}
	if nsg := azureLower(value.Properties.NetworkSecurityGroup.ID); nsg != "" {
		nsgID = nsg
	}
	at := time.Now().UTC()
	out := &model.Asset{
		AccountID: a.ID, Provider: a.Provider, AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: id, ResourceType: "nic", Name: value.Name,
		SubnetID: subnetID, ObservedAt: at, MapperVersion: "azure-nic/v1",
		Components: map[string]model.AssetComponent{"details": component(raw, "Network Interfaces.Get", azureAPIVersion, at)},
		Provenance: map[string]model.FieldOrigin{},
		Network:    &model.AssetNetwork{MACAddress: value.Properties.MACAddress, Primary: &primary},
	}
	for _, config := range value.Properties.IPConfigurations {
		if config.Properties.PrivateIPAddress != "" {
			out.PrivateIPs = append(out.PrivateIPs, config.Properties.PrivateIPAddress)
		}
	}
	if subnetID != "" {
		out.VPCID = azureIDBefore(subnetID, "subnets")
		out.References = append(out.References, reference(a, "vpc", out.VPCID, "belongs_to_vpc", "details", "/properties/ipConfigurations/0/properties/subnet/id"))
		out.References = append(out.References, reference(a, "subnet", subnetID, "in_subnet", "details", "/properties/ipConfigurations/0/properties/subnet/id"))
	}
	if nsgID != "" {
		out.SecurityGroupIDs = []string{nsgID}
		out.References = append(out.References, reference(a, "security_group", nsgID, "attached_security_group", "details", "/properties/networkSecurityGroup/id"))
	}
	if hostID, ok := azureVMID(value.Properties.VirtualMachine.ID); ok {
		out.References = append(out.References, reference(a, "vm", hostID, "attached_to_host", "details", "/properties/virtualMachine/id"))
	}
	out.Tags = azureTags(value.Tags)
	for field, path := range map[string]string{
		"resource_id": "/id", "name": "/name", "vpc_id": "/properties/ipConfigurations/0/properties/subnet/id",
		"subnet_id":          "/properties/ipConfigurations/0/properties/subnet/id",
		"security_group_ids": "/properties/networkSecurityGroup/id", "private_ips": "/properties/ipConfigurations",
		"tags": "/tags", "network.mac_address": "/properties/macAddress",
		"network.primary": "/properties/ipConfigurations/0/properties/primary",
	} {
		if sourceHas(raw, path) {
			out.Provenance[field] = model.FieldOrigin{Source: "component:details", Paths: []string{path}, Transform: "source_field_projection"}
		}
	}
	for field, path := range map[string]string{"account_uid": "/account_uid", "region": "/region"} {
		out.Provenance[field] = model.FieldOrigin{Source: "configuration", Paths: []string{path}, Transform: "explicit_connection_scope"}
	}
	return out, nil
}

func normalizeAzureNetwork(a model.Account, kind, id string, raw json.RawMessage) (*model.Asset, error) {
	var value struct {
		ID         string             `json:"id"`
		Name       string             `json:"name"`
		Tags       map[string]*string `json:"tags"`
		Properties struct {
			AddressSpace struct {
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"addressSpace"`
			AddressPrefix        string `json:"addressPrefix"`
			NetworkSecurityGroup struct {
				ID string `json:"id"`
			} `json:"networkSecurityGroup"`
			SecurityRules []json.RawMessage `json:"securityRules"`
		} `json:"properties"`
	}
	if json.Unmarshal(raw, &value) != nil || !strings.EqualFold(value.ID, id) {
		return nil, fmt.Errorf("network identity mismatch")
	}
	at := time.Now().UTC()
	api := map[string]string{"vpc": "Network VirtualNetworks.Get", "subnet": "Network Subnets.Get", "security_group": "Network SecurityGroups.Get"}[kind]
	out := &model.Asset{
		AccountID: a.ID, Provider: "azure", AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: id, ResourceType: kind, Name: value.Name, ObservedAt: at,
		MapperVersion: "azure-network/v1",
		Components:    map[string]model.AssetComponent{"details": component(raw, api, azureAPIVersion, at)},
		Provenance:    map[string]model.FieldOrigin{},
		Network:       &model.AssetNetwork{},
	}
	paths := map[string]string{"resource_id": "/id", "name": "/name", "tags": "/tags"}
	switch kind {
	case "vpc":
		out.VPCID = id
		paths["vpc_id"] = "/id"
		if len(value.Properties.AddressSpace.AddressPrefixes) > 0 {
			out.Network.CIDRBlock = value.Properties.AddressSpace.AddressPrefixes[0]
			paths["network.cidr_block"] = "/properties/addressSpace/addressPrefixes"
		}
	case "subnet":
		out.SubnetID = id
		if vnet := azureIDBefore(id, "subnets"); vnet != "" {
			out.VPCID = vnet
			paths["vpc_id"] = "/id"
			out.References = []model.AssetReference{reference(a, "vpc", vnet, "belongs_to_vpc", "details", "/id")}
		}
		if value.Properties.AddressPrefix != "" {
			out.Network.CIDRBlock = value.Properties.AddressPrefix
			paths["network.cidr_block"] = "/properties/addressPrefix"
		}
		if nsg := azureLower(value.Properties.NetworkSecurityGroup.ID); nsg != "" {
			out.References = append(out.References, reference(a, "security_group", nsg, "protected_by_security_group", "details", "/properties/networkSecurityGroup/id"))
		}
	case "security_group":
		// ARM NSG resources are subscription/resource-group scoped, not VPC scoped.
		if value.Properties.SecurityRules != nil {
			out.Components["policies"] = component(raw, api, azureAPIVersion, at)
		}
	}
	if value.Tags != nil {
		out.Tags = azureTags(value.Tags)
	}
	for field, path := range paths {
		if sourceHas(raw, path) {
			out.Provenance[field] = model.FieldOrigin{Source: "component:details", Paths: []string{path}, Transform: "source_field_projection"}
		}
	}
	for field, path := range map[string]string{"account_uid": "/account_uid", "region": "/region"} {
		out.Provenance[field] = model.FieldOrigin{Source: "configuration", Paths: []string{path}, Transform: "explicit_connection_scope"}
	}
	return out, nil
}

// azureTags sorts Azure tag maps so revisions stay deterministic.
func azureTags(tags map[string]*string) []model.AssetTag {
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]model.AssetTag, 0, len(keys))
	for _, key := range keys {
		value := ""
		if tags[key] != nil {
			value = *tags[key]
		}
		out = append(out, model.AssetTag{Key: key, Value: value})
	}
	return out
}

// ValidAzureResource validates lowercased ARM resource IDs.
func ValidAzureResource(kind, id string) bool {
	if len(id) > 512 || strings.ToLower(id) != id {
		return false
	}
	switch kind {
	case "vm":
		_, ok := azureVMID(id)
		return ok
	case "vpc":
		return azureHasProvider(id, "microsoft.network", "virtualnetworks")
	case "subnet":
		return azureHasProvider(id, "microsoft.network", "virtualnetworks") &&
			strings.Contains(id, "/subnets/") && azureNameAfter(id, "subnets") != ""
	case "security_group":
		return azureHasProvider(id, "microsoft.network", "networksecuritygroups")
	case "nic":
		return azureHasProvider(id, "microsoft.network", "networkinterfaces")
	}
	return false
}

func init() {
	registerProvider(Provider{
		ID:                "azure",
		Name:              "Microsoft Azure",
		HostType:          "vm",
		APIVersion:        azureAPIVersion,
		HostAPI:           "Compute VirtualMachines.Get",
		PolicyAPI:         "Network SecurityGroups.Get",
		ResourceTypes:     []string{"vm", "security_group", "vpc", "subnet", "nic"},
		MapperVersion:     azureMapperVersion,
		PoliciesInDetails: true,
		RequiresRegion:    true,
		DocsURL:           "https://learn.microsoft.com/rest/api/compute/virtual-machines/get",
		SyntheticHostID:   SyntheticAzureVMID,
		HostID: func(r model.Resource) (string, bool) {
			switch strings.ToLower(r.Type) {
			case "host", "vm", "virtualmachine", "microsoft.compute/virtualmachines":
			default:
				return "", false
			}
			return azureVMID(r.ID)
		},
		Valid:              ValidAzureResource,
		QPS:                2,
		ValidateCredential: requireAKSK,
		ValidateAccount: func(a model.Account) error {
			if a.Options == nil || a.Options["subscription_id"] == "" || a.Options["tenant_id"] == "" {
				return fmt.Errorf("Azure subscription_id and tenant_id options are required")
			}
			return nil
		},
		New: func(cred connector.Credential, a model.Account, limiter *connector.Limiter) (Client, error) {
			raw, err := AzureRaw(cred, a)
			if err != nil {
				return nil, err
			}
			return &azureClient{raw: raw, limiter: limiter}, nil
		},
		Synthetic: func(limiter *connector.Limiter) Client {
			return &azureClient{raw: SyntheticAzureRaw(), limiter: limiter}
		},
	})
}
