package asset

import (
	"context"
	"encoding/json"
	"fmt"
)

// Huawei synthetic records mirror the JSON envelopes returned by ECS ShowServer
// and the VPC Show* APIs. They are fabricated values, never a captured tenant.
const (
	SyntheticHuaweiServerID = "11111111-1111-1111-1111-111111111111"
	SyntheticHuaweiVPCID    = "22222222-2222-2222-2222-222222222222"
	SyntheticHuaweiGroupID  = "33333333-3333-3333-3333-333333333333"
	SyntheticHuaweiSubnetID = "44444444-4444-4444-4444-444444444444"
)

const SyntheticHuaweiInstance = `{"id":"11111111-1111-1111-1111-111111111111","name":"synthetic-web-01","status":"ACTIVE","created":"2026-01-01T09:00:00Z","tenant_id":"00000000-0000-0000-0000-000000000000","flavor":{"id":"c6.large.2"},"metadata":{"image_name":"Huawei Cloud EulerOS 2.0","os_type":"Linux","vpc_id":"22222222-2222-2222-2222-222222222222"},"addresses":{"synthetic-net":[{"addr":"192.0.2.30","version":"4","OS-EXT-IPS:type":"floating"},{"addr":"10.20.0.11","version":"4","OS-EXT-IPS:type":"fixed"}]},"security_groups":[{"id":"33333333-3333-3333-3333-333333333333","name":"synthetic-web-access"}],"OS-EXT-AZ:availability_zone":"cn-north-4a","tags":["environment=demo"],"FutureVendorField":9007199254740993}`

const SyntheticHuaweiVPC = `{"id":"22222222-2222-2222-2222-222222222222","name":"synthetic-production-network","description":"Synthetic network","cidr":"10.20.0.0/16","status":"ACTIVE","created_at":"2026-01-01T09:00:00","tags":[{"key":"environment","value":"demo"}],"FutureVendorField":9007199254740993}`

const SyntheticHuaweiSubnet = `{"id":"44444444-4444-4444-4444-444444444444","name":"synthetic-web-subnet","cidr":"10.20.0.0/24","vpc_id":"22222222-2222-2222-2222-222222222222","availability_zone":"cn-north-4a","status":"ACTIVE","gateway_ip":"10.20.0.1","dhcp_enable":true,"tags":[]}`

const SyntheticHuaweiSecurityGroup = `{"id":"33333333-3333-3333-3333-333333333333","name":"synthetic-web-access","description":"Synthetic HTTPS policy group","vpc_id":"22222222-2222-2222-2222-222222222222","security_group_rules":[{"id":"55555555-5555-5555-5555-555555555555","direction":"ingress","ethertype":"IPv4","protocol":"tcp","port_range_min":443,"port_range_max":443,"remote_ip_prefix":"0.0.0.0/0","security_group_id":"33333333-3333-3333-3333-333333333333"}],"FutureVendorField":9007199254740993}`

func SyntheticHuaweiRaw() huaweiRaw {
	return func(_ context.Context, action string, params map[string]string) (json.RawMessage, error) {
		switch action {
		case "ShowServer":
			if params["ServerId"] != SyntheticHuaweiServerID {
				return nil, ErrNotVisible
			}
			return json.RawMessage(`{"server":` + SyntheticHuaweiInstance + `}`), nil
		case "ShowVpc":
			if params["VpcId"] != SyntheticHuaweiVPCID {
				return nil, ErrNotVisible
			}
			return json.RawMessage(`{"vpc":` + SyntheticHuaweiVPC + `}`), nil
		case "ShowSubnet":
			if params["SubnetId"] != SyntheticHuaweiSubnetID {
				return nil, ErrNotVisible
			}
			return json.RawMessage(`{"subnet":` + SyntheticHuaweiSubnet + `}`), nil
		case "ShowSecurityGroup":
			if params["SecurityGroupId"] != SyntheticHuaweiGroupID {
				return nil, ErrNotVisible
			}
			return json.RawMessage(`{"security_group":` + SyntheticHuaweiSecurityGroup + `}`), nil
		}
		return nil, fmt.Errorf("unsupported synthetic action")
	}
}
