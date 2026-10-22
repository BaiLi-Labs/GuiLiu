package asset

import (
	"context"
	"encoding/json"
	"fmt"
)

// Aliyun synthetic records mirror the RPC JSON envelopes returned by the ECS
// and VPC APIs. They are fabricated values, never a captured tenant.
const SyntheticAliyunInstance = `{"InstanceId":"i-mock0001","InstanceName":"synthetic-web-01","OSName":"Alibaba Cloud Linux 3","Status":"Running","InstanceType":"ecs.g7.large","ZoneId":"cn-hangzhou-k","PublicIpAddress":{"IpAddress":["192.0.2.20"]},"EipAddress":{"IpAddress":""},"VpcAttributes":{"VpcId":"vpc-synthetic","VSwitchId":"vsw-synthetic","PrivateIpAddress":{"IpAddress":["10.10.0.11"]}},"SecurityGroupIds":{"SecurityGroupId":["sg-synthetic"]},"NetworkInterfaces":{"NetworkInterface":[{"NetworkInterfaceId":"eni-mock0001"}]},"Tags":{"Tag":[{"TagKey":"environment","TagValue":"demo"}]},"FutureVendorField":9007199254740993}`

const SyntheticAliyunPolicy = `{"SecurityGroupId":"sg-synthetic","Permissions":{"Permission":[{"Direction":"ingress","IpProtocol":"tcp","PortRange":"443/443","SourceCidrIp":"0.0.0.0/0","Policy":"Accept","Priority":1,"Description":"synthetic https"}]},"FutureVendorField":9007199254740993}`

const SyntheticAliyunVPC = `{"VpcId":"vpc-synthetic","VpcName":"synthetic-production-network","CidrBlock":"10.10.0.0/16","IsDefault":false,"CreationTime":"2026-01-01T09:00:00Z","Tags":{"Tag":[{"Key":"environment","Value":"demo"}]},"FutureVendorField":9007199254740993}`

const SyntheticAliyunVSwitch = `{"VSwitchId":"vsw-synthetic","VSwitchName":"synthetic-web-subnet","VpcId":"vpc-synthetic","CidrBlock":"10.10.0.0/24","ZoneId":"cn-hangzhou-k","IsDefault":false,"CreationTime":"2026-01-01T09:00:00Z","Tags":{"Tag":[]}}`

const SyntheticAliyunENI = `{"NetworkInterfaceId":"eni-mock0001","NetworkInterfaceName":"synthetic-web-eni","VpcId":"vpc-synthetic","VSwitchId":"vsw-synthetic","SecurityGroupIds":{"SecurityGroupId":["sg-synthetic"]},"PrivateIpSets":{"PrivateIpSet":[{"PrivateIpAddress":"10.10.0.11","Primary":true}]},"InstanceId":"i-mock0001","Type":"Primary","Status":"Available","MacAddress":"52:54:00:12:34:57","CreatedTime":"2026-01-01T09:00:00Z","Tags":{"Tag":[{"TagKey":"environment","TagValue":"demo"}]},"FutureVendorField":9007199254740993}`

const SyntheticAliyunSecurityGroup = `{"SecurityGroupId":"sg-synthetic","SecurityGroupName":"synthetic-web-access","Description":"Synthetic HTTPS policy group","VpcId":"vpc-synthetic","CreationTime":"2026-01-01T09:00:00Z","Tags":{"Tag":[{"TagKey":"team","TagValue":"demo"}]}}`

func SyntheticAliyunCall() Call {
	return func(_ context.Context, service, action string, params map[string]any) (json.RawMessage, error) {
		if service == "ecs" && action == "DescribeInstances" {
			ids, _ := params["InstanceIds"].([]string)
			if len(ids) != 1 || ids[0] != "i-mock0001" {
				return json.RawMessage(`{"Instances":{"Instance":[]},"TotalCount":0}`), nil
			}
			return json.RawMessage(fmt.Sprintf(`{"Instances":{"Instance":[%s]},"TotalCount":1}`, SyntheticAliyunInstance)), nil
		}
		if service == "ecs" && action == "DescribeNetworkInterfaces" {
			ids, _ := params["NetworkInterfaceId"].([]string)
			if len(ids) != 1 || ids[0] != "eni-mock0001" {
				return json.RawMessage(`{"NetworkInterfaceSets":{"NetworkInterfaceSet":[]},"TotalCount":0}`), nil
			}
			return json.RawMessage(`{"NetworkInterfaceSets":{"NetworkInterfaceSet":[` + SyntheticAliyunENI + `]},"TotalCount":1}`), nil
		}
		if service == "ecs" && action == "DescribeSecurityGroupAttribute" {
			if params["SecurityGroupId"] != "sg-synthetic" {
				return json.RawMessage(`{"Permissions":{"Permission":[]}}`), nil
			}
			return json.RawMessage(SyntheticAliyunPolicy), nil
		}
		for _, spec := range []struct {
			service, action, key, idParam, id, raw string
		}{
			{"vpc", "DescribeVpcs", "Vpcs", "VpcId", "vpc-synthetic", SyntheticAliyunVPC},
			{"vpc", "DescribeVSwitches", "VSwitches", "VSwitchId", "vsw-synthetic", SyntheticAliyunVSwitch},
			{"ecs", "DescribeSecurityGroups", "SecurityGroups", "SecurityGroupIds", "sg-synthetic", SyntheticAliyunSecurityGroup},
		} {
			if service != spec.service || action != spec.action {
				continue
			}
			var ids []string
			switch v := params[spec.idParam].(type) {
			case string:
				ids = []string{v}
			case []string:
				ids = v
			}
			items := []json.RawMessage{}
			for _, id := range ids {
				if id == spec.id {
					items = append(items, json.RawMessage(spec.raw))
				}
			}
			return json.Marshal(map[string]any{spec.key: map[string]any{mapKeyFor(spec.key): items}, "TotalCount": len(items)})
		}
		return nil, fmt.Errorf("unsupported synthetic action")
	}
}

func mapKeyFor(listKey string) string {
	switch listKey {
	case "Vpcs":
		return "Vpc"
	case "VSwitches":
		return "VSwitch"
	case "SecurityGroups":
		return "SecurityGroup"
	}
	return ""
}
