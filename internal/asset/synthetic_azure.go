package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Azure synthetic records mirror the ARM JSON representation. They are
// fabricated values, never a captured tenant.
const (
	SyntheticAzureSubscription = "11111111-1111-1111-1111-111111111111"
	SyntheticAzureResourceBase = "/subscriptions/" + SyntheticAzureSubscription + "/resourcegroups/synthetic-rg/providers/"
	SyntheticAzureVMID         = SyntheticAzureResourceBase + "microsoft.compute/virtualmachines/synthetic-web-01"
	SyntheticAzureNICID        = SyntheticAzureResourceBase + "microsoft.network/networkinterfaces/synthetic-nic-1"
	SyntheticAzurePIPID        = SyntheticAzureResourceBase + "microsoft.network/publicipaddresses/synthetic-pip-1"
	SyntheticAzureVNetID       = SyntheticAzureResourceBase + "microsoft.network/virtualnetworks/synthetic-vnet"
	SyntheticAzureSubnetID     = SyntheticAzureVNetID + "/subnets/synthetic-web-subnet"
	SyntheticAzureNSGID        = SyntheticAzureResourceBase + "microsoft.network/networksecuritygroups/synthetic-nsg"
)

const SyntheticAzureVM = `{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Compute/virtualMachines/synthetic-web-01","name":"synthetic-web-01","location":"eastasia","zones":["1"],"tags":{"environment":"demo"},"properties":{"hardwareProfile":{"vmSize":"Standard_D2s_v5"},"storageProfile":{"osDisk":{"osType":"Linux"}},"networkProfile":{"networkInterfaces":[{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Network/networkInterfaces/synthetic-nic-1"}]},"instanceView":{"statuses":[{"code":"ProvisioningState/succeeded"},{"code":"PowerState/running"}]}},"FutureVendorField":9007199254740993}`

const SyntheticAzureNIC = `{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Network/networkInterfaces/synthetic-nic-1","name":"synthetic-nic-1","properties":{"macAddress":"00:0d:3a:00:00:01","virtualMachine":{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Compute/virtualMachines/synthetic-web-01"},"ipConfigurations":[{"name":"ipconfig1","properties":{"privateIPAddress":"10.50.0.4","primary":true,"publicIPAddress":{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Network/publicIPAddresses/synthetic-pip-1"},"subnet":{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Network/virtualNetworks/synthetic-vnet/subnets/synthetic-web-subnet"}}}],"networkSecurityGroup":{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Network/networkSecurityGroups/synthetic-nsg"}},"FutureVendorField":9007199254740993}`

const SyntheticAzurePIP = `{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Network/publicIPAddresses/synthetic-pip-1","name":"synthetic-pip-1","properties":{"ipAddress":"192.0.2.60"}}`

const SyntheticAzureVNet = `{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Network/virtualNetworks/synthetic-vnet","name":"synthetic-vnet","location":"eastasia","tags":{"environment":"demo"},"properties":{"addressSpace":{"addressPrefixes":["10.50.0.0/16"]}},"FutureVendorField":9007199254740993}`

const SyntheticAzureSubnet = `{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Network/virtualNetworks/synthetic-vnet/subnets/synthetic-web-subnet","name":"synthetic-web-subnet","properties":{"addressPrefix":"10.50.0.0/24","networkSecurityGroup":{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Network/networkSecurityGroups/synthetic-nsg"}}}`

const SyntheticAzureNSG = `{"id":"/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/synthetic-rg/providers/Microsoft.Network/networkSecurityGroups/synthetic-nsg","name":"synthetic-nsg","location":"eastasia","properties":{"securityRules":[{"name":"allow-https","properties":{"direction":"Inbound","access":"Allow","protocol":"Tcp","sourceAddressPrefix":"*","destinationPortRange":"443","priority":100}}]},"FutureVendorField":9007199254740993}`

func SyntheticAzureRaw() azureRaw {
	specs := map[string]struct{ id, raw string }{
		"VM":       {SyntheticAzureVMID, SyntheticAzureVM},
		"NIC":      {SyntheticAzureNICID, SyntheticAzureNIC},
		"PublicIP": {SyntheticAzurePIPID, SyntheticAzurePIP},
		"VNet":     {SyntheticAzureVNetID, SyntheticAzureVNet},
		"Subnet":   {SyntheticAzureSubnetID, SyntheticAzureSubnet},
		"NSG":      {SyntheticAzureNSGID, SyntheticAzureNSG},
	}
	return func(_ context.Context, action string, params map[string]string) (json.RawMessage, error) {
		spec, ok := specs[action]
		if !ok {
			return nil, fmt.Errorf("unsupported synthetic action")
		}
		expected := map[string]string{"resourceGroup": "synthetic-rg", "name": azureNameAfter(spec.id, azureActionSegment(action))}
		if action == "Subnet" {
			expected["vnet"] = "synthetic-vnet"
		}
		if azureNameAfter(spec.id, azureActionSegment(action)) != "" && !strings.EqualFold(params["name"], expected["name"]) {
			return nil, ErrNotVisible
		}
		return json.RawMessage(spec.raw), nil
	}
}

func azureActionSegment(action string) string {
	switch action {
	case "VM":
		return "virtualmachines"
	case "NIC":
		return "networkinterfaces"
	case "PublicIP":
		return "publicipaddresses"
	case "VNet":
		return "virtualnetworks"
	case "Subnet":
		return "subnets"
	case "NSG":
		return "networksecuritygroups"
	}
	return ""
}
