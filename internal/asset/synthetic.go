package asset

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

// SyntheticInstance is a fabricated API-shaped record, not a captured tenant.
const SyntheticInstance = `{"InstanceId":"ins-mock0001","InstanceName":"synthetic-web-01","OsName":"TencentOS Server 3.1","InstanceState":"RUNNING","InstanceType":"S5.MEDIUM4","Placement":{"Zone":"ap-guangzhou-6"},"PublicIpAddresses":["192.0.2.10"],"PrivateIpAddresses":["10.0.0.11"],"VirtualPrivateCloud":{"VpcId":"vpc-synthetic","SubnetId":"subnet-synthetic"},"SecurityGroupIds":["sg-synthetic"],"Tags":[{"TagKey":"environment","TagValue":"demo"}],"FutureVendorField":9007199254740993}`
const SyntheticPolicy = `{"SecurityGroupPolicySet":{"Version":"1","Ingress":[{"Protocol":"TCP","Port":"443","CidrBlock":"0.0.0.0/0","Action":"ACCEPT","PolicyIndex":0}],"Egress":[{"Protocol":"ALL","Port":"all","CidrBlock":"0.0.0.0/0","Action":"ACCEPT"}]}}`
const SyntheticVPC = `{"VpcId":"vpc-synthetic","VpcName":"synthetic-production-network","CidrBlock":"10.0.0.0/16","IsDefault":false,"CreatedTime":"2026-01-01 09:00:00","TagSet":[{"Key":"environment","Value":"demo"}],"FutureVendorField":9007199254740993}`
const SyntheticSubnet = `{"SubnetId":"subnet-synthetic","SubnetName":"synthetic-web-subnet","VpcId":"vpc-synthetic","CidrBlock":"10.0.0.0/24","Zone":"ap-guangzhou-6","IsDefault":false,"RouteTableId":"rtb-synthetic","NetworkAclId":"acl-synthetic","TagSet":[]}`
const SyntheticSecurityGroup = `{"SecurityGroupId":"sg-synthetic","SecurityGroupName":"synthetic-web-access","SecurityGroupDesc":"Synthetic HTTPS policy group","IsDefault":false,"CreatedTime":"2026-01-01 09:00:00","TagSet":[{"Key":"team","Value":"demo"}]}`
const SyntheticTencentENI = `{"NetworkInterfaceId":"eni-mock0001","NetworkInterfaceName":"synthetic-web-eni","VpcId":"vpc-synthetic","SubnetId":"subnet-synthetic","GroupSet":["sg-synthetic"],"Primary":true,"MacAddress":"52:54:00:12:34:56","State":"AVAILABLE","PrivateIpAddressSet":[{"PrivateIpAddress":"10.0.0.11","Primary":true}],"Attachment":{"InstanceId":"ins-mock0001"},"TagSet":[{"Key":"environment","Value":"demo"}],"CreatedTime":"2026-01-01 09:00:00","FutureVendorField":9007199254740993}`

func SyntheticCall() Call {
	return func(_ context.Context, service, action string, params map[string]any) (json.RawMessage, error) {
		if service == "cvm" && action == "DescribeInstances" {
			ids, _ := params["InstanceIds"].([]string)
			if len(ids) != 1 || ids[0] != "ins-mock0001" {
				return json.RawMessage(`{"InstanceSet":[],"TotalCount":0}`), nil
			}
			return json.RawMessage(fmt.Sprintf(`{"InstanceSet":[%s],"TotalCount":1}`, SyntheticInstance)), nil
		}
		if action == "DescribeSecurityGroupPolicies" {
			return json.RawMessage(SyntheticPolicy), nil
		}
		if action == "DescribeNetworkInterfaces" {
			ids, _ := params["NetworkInterfaceIds"].([]string)
			matched := false
			for _, id := range ids {
				if id == "eni-mock0001" {
					matched = true
				}
			}
			if filters, ok := params["Filters"].([]map[string]any); ok {
				for _, filter := range filters {
					if filter["Name"] == "attachment.instance-id" {
						if values, ok := filter["Values"].([]string); ok && len(values) == 1 && values[0] == "ins-mock0001" {
							matched = true
						}
					}
				}
			}
			if !matched {
				return json.RawMessage(`{"NetworkInterfaceSet":[],"TotalCount":0}`), nil
			}
			return json.RawMessage(fmt.Sprintf(`{"NetworkInterfaceSet":[%s],"TotalCount":1}`, SyntheticTencentENI)), nil
		}
		for _, spec := range []struct{ action, key, idKey, id, raw string }{
			{"DescribeVpcs", "VpcSet", "VpcIds", "vpc-synthetic", SyntheticVPC},
			{"DescribeSubnets", "SubnetSet", "SubnetIds", "subnet-synthetic", SyntheticSubnet},
			{"DescribeSecurityGroups", "SecurityGroupSet", "SecurityGroupIds", "sg-synthetic", SyntheticSecurityGroup},
		} {
			if action == spec.action {
				ids, _ := params[spec.idKey].([]string)
				items := []json.RawMessage{}
				for _, id := range ids {
					if id == spec.id {
						items = append(items, json.RawMessage(spec.raw))
					}
				}
				return json.Marshal(map[string]any{spec.key: items, "TotalCount": len(items)})
			}
		}
		return nil, fmt.Errorf("unsupported synthetic action")
	}
}

func SyntheticTencent(ctx context.Context, a model.Account, id string, limiter *connector.Limiter) (*model.Asset, error) {
	value, err := ReadTencent(ctx, a, id, SyntheticCall(), limiter)
	if err == nil {
		value.Synthetic = true
	}
	return value, err
}

// SeedSynthetic stores one fabricated host observation for the connection's
// provider. Providers without a synthetic fixture are skipped.
func SeedSynthetic(ctx context.Context, st store.Store, a model.Account) error {
	p, ok := ProviderFor(a.Provider)
	if !ok || p.SyntheticHostID == "" || p.Synthetic == nil {
		return nil
	}
	s := New(st, nil, true)
	s.limiter = connector.NewLimiter(100000)
	result, err := s.Refresh(ctx, a.ID, p.HostType, p.SyntheticHostID)
	if err != nil {
		return err
	}
	if result.Status != "available" && result.Status != "cached" {
		return fmt.Errorf("synthetic asset seed incomplete: %s", result.Status)
	}
	return nil
}
