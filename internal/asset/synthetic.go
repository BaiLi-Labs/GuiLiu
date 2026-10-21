package asset

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// SyntheticInstance is a fabricated API-shaped record, not a captured tenant.
const SyntheticInstance = `{"InstanceId":"ins-mock0001","InstanceName":"synthetic-web-01","OsName":"TencentOS Server 3.1","InstanceState":"RUNNING","InstanceType":"S5.MEDIUM4","Placement":{"Zone":"ap-guangzhou-6"},"PublicIpAddresses":["192.0.2.10"],"PrivateIpAddresses":["10.0.0.11"],"VirtualPrivateCloud":{"VpcId":"vpc-synthetic","SubnetId":"subnet-synthetic"},"SecurityGroupIds":["sg-synthetic"],"Tags":[{"TagKey":"environment","TagValue":"demo"}],"FutureVendorField":9007199254740993}`
const SyntheticPolicy = `{"SecurityGroupPolicySet":{"Version":"1","Ingress":[{"Protocol":"TCP","Port":"443","CidrBlock":"0.0.0.0/0","Action":"ACCEPT","PolicyIndex":0}],"Egress":[{"Protocol":"ALL","Port":"all","CidrBlock":"0.0.0.0/0","Action":"ACCEPT"}]}}`

func SyntheticTencent(ctx context.Context, a model.Account, id string, limiter *connector.Limiter) (*model.Asset, error) {
	call := func(_ context.Context, service, action string, _ map[string]any) (json.RawMessage, error) {
		if service == "cvm" && action == "DescribeInstances" {
			if id != "ins-mock0001" {
				return json.RawMessage(`{"InstanceSet":[],"TotalCount":0}`), nil
			}
			return json.RawMessage(fmt.Sprintf(`{"InstanceSet":[%s],"TotalCount":1}`, SyntheticInstance)), nil
		}
		return json.RawMessage(SyntheticPolicy), nil
	}
	value, err := ReadTencent(ctx, a, id, call, limiter)
	if err == nil {
		value.Synthetic = true
	}
	return value, err
}
