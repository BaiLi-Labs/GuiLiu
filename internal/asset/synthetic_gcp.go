package asset

import (
	"context"
	"encoding/json"
	"fmt"
)

// GCP synthetic records mirror the Compute REST JSON representation. They are
// fabricated values, never a captured tenant.
const (
	SyntheticGCPProject    = "synthetic-project"
	SyntheticGCPZone       = "asia-east1-a"
	SyntheticGCPRegion     = "asia-east1"
	SyntheticGCPInstanceID = "projects/synthetic-project/zones/asia-east1-a/instances/synthetic-web-01"
	SyntheticGCPVPCID      = "projects/synthetic-project/global/networks/synthetic-vpc"
	SyntheticGCPSubnetID   = "projects/synthetic-project/regions/asia-east1/subnetworks/synthetic-web-subnet"
	SyntheticGCPFirewallID = "projects/synthetic-project/global/firewalls/synthetic-allow-https"
)

const SyntheticGCPInstance = `{"id":"1234567890123456789","name":"synthetic-web-01","status":"RUNNING","machineType":"https://www.googleapis.com/compute/v1/projects/synthetic-project/zones/asia-east1-a/machineTypes/e2-medium","zone":"https://www.googleapis.com/compute/v1/projects/synthetic-project/zones/asia-east1-a","creationTimestamp":"2026-01-01T09:00:00.000-07:00","labels":{"environment":"demo"},"tags":{"items":["http-server"]},"disks":[{"licenses":["https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-12"]}],"networkInterfaces":[{"network":"https://www.googleapis.com/compute/v1/projects/synthetic-project/global/networks/synthetic-vpc","subnetwork":"https://www.googleapis.com/compute/v1/projects/synthetic-project/regions/asia-east1/subnetworks/synthetic-web-subnet","networkIP":"10.40.0.11","accessConfigs":[{"natIP":"192.0.2.50"}]}],"FutureVendorField":9007199254740993}`

const SyntheticGCPVPC = `{"name":"synthetic-vpc","description":"Synthetic network","IPv4Range":"10.40.0.0/16","creationTimestamp":"2026-01-01T09:00:00.000-07:00","autoCreateSubnetworks":false,"FutureVendorField":9007199254740993}`

const SyntheticGCPSubnet = `{"name":"synthetic-web-subnet","description":"Synthetic subnet","ipCidrRange":"10.40.0.0/24","region":"https://www.googleapis.com/compute/v1/projects/synthetic-project/regions/asia-east1","network":"https://www.googleapis.com/compute/v1/projects/synthetic-project/global/networks/synthetic-vpc","creationTimestamp":"2026-01-01T09:00:00.000-07:00","privateIpGoogleAccess":false}`

const SyntheticGCPFirewall = `{"name":"synthetic-allow-https","description":"Synthetic HTTPS policy","network":"https://www.googleapis.com/compute/v1/projects/synthetic-project/global/networks/synthetic-vpc","direction":"INGRESS","priority":1000,"sourceRanges":["0.0.0.0/0"],"targetTags":["http-server"],"allowed":[{"IPProtocol":"tcp","ports":["443"]}],"creationTimestamp":"2026-01-01T09:00:00.000-07:00","FutureVendorField":9007199254740993}`

func SyntheticGCPRaw() gcpRaw {
	return func(_ context.Context, action string, params map[string]string) (json.RawMessage, error) {
		if params["project"] != SyntheticGCPProject {
			return nil, ErrNotVisible
		}
		switch action {
		case "Instance":
			if params["zone"] != SyntheticGCPZone || params["name"] != "synthetic-web-01" {
				return nil, ErrNotVisible
			}
			return json.RawMessage(SyntheticGCPInstance), nil
		case "Network":
			if params["name"] != "synthetic-vpc" {
				return nil, ErrNotVisible
			}
			return json.RawMessage(SyntheticGCPVPC), nil
		case "Subnetwork":
			if params["region"] != SyntheticGCPRegion || params["name"] != "synthetic-web-subnet" {
				return nil, ErrNotVisible
			}
			return json.RawMessage(SyntheticGCPSubnet), nil
		case "Firewall":
			if params["name"] != "synthetic-allow-https" {
				return nil, ErrNotVisible
			}
			return json.RawMessage(SyntheticGCPFirewall), nil
		}
		return nil, fmt.Errorf("unsupported synthetic action")
	}
}
