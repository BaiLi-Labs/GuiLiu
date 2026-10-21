package asset

import (
	"context"
	"encoding/json"
	"fmt"
)

// AWS synthetic records mirror the EC2 JSON protocol (PascalCase) returned by
// the four declared APIs. They are fabricated values, never a captured tenant.
const (
	SyntheticAWSInstanceID = "i-0123456789abcdef0"
	SyntheticAWSVPCID      = "vpc-0123456789abcdef0"
	SyntheticAWSSubnetID   = "subnet-0123456789abcdef0"
	SyntheticAWSGroupID    = "sg-0123456789abcdef0"
)

const SyntheticAWSInstance = `{"InstanceId":"i-0123456789abcdef0","InstanceType":"m7g.large","PlatformDetails":"Linux/UNIX","ImageId":"ami-0123456789abcdef0","PrivateIpAddress":"10.30.0.11","PublicIpAddress":"192.0.2.40","VpcId":"vpc-0123456789abcdef0","SubnetId":"subnet-0123456789abcdef0","State":{"Name":"running"},"Placement":{"AvailabilityZone":"ap-southeast-1a"},"SecurityGroups":[{"GroupId":"sg-0123456789abcdef0","GroupName":"synthetic-web-access"}],"Tags":[{"Key":"Name","Value":"synthetic-web-01"},{"Key":"environment","Value":"demo"}],"NetworkInterfaces":[{"PrivateIpAddress":"10.30.0.11","Association":{"PublicIp":"192.0.2.40"},"PrivateIpAddresses":[{"PrivateIpAddress":"10.30.0.11"}]}],"FutureVendorField":9007199254740993}`

const SyntheticAWSVPC = `{"VpcId":"vpc-0123456789abcdef0","CidrBlock":"10.30.0.0/16","IsDefault":false,"State":"available","Tags":[{"Key":"Name","Value":"synthetic-production-network"},{"Key":"environment","Value":"demo"}],"FutureVendorField":9007199254740993}`

const SyntheticAWSSubnet = `{"SubnetId":"subnet-0123456789abcdef0","VpcId":"vpc-0123456789abcdef0","CidrBlock":"10.30.0.0/24","AvailabilityZone":"ap-southeast-1a","State":"available","Tags":[{"Key":"Name","Value":"synthetic-web-subnet"}]}`

const SyntheticAWSSecurityGroup = `{"GroupId":"sg-0123456789abcdef0","GroupName":"synthetic-web-access","Description":"Synthetic HTTPS policy group","VpcId":"vpc-0123456789abcdef0","Tags":[{"Key":"team","Value":"demo"}],"IpPermissions":[{"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0"}]}],"IpPermissionsEgress":[],"FutureVendorField":9007199254740993}`

func SyntheticAWSRaw() awsRaw {
	return func(_ context.Context, action string, ids []string) (json.RawMessage, error) {
		if len(ids) != 1 {
			return nil, fmt.Errorf("invalid synthetic request")
		}
		switch action {
		case "DescribeInstances":
			if ids[0] != SyntheticAWSInstanceID {
				return json.RawMessage(`{"Reservations":[]}`), nil
			}
			return json.RawMessage(`{"Reservations":[{"Instances":[` + SyntheticAWSInstance + `]}]}`), nil
		case "DescribeVpcs":
			if ids[0] != SyntheticAWSVPCID {
				return json.RawMessage(`{"Vpcs":[]}`), nil
			}
			return json.RawMessage(`{"Vpcs":[` + SyntheticAWSVPC + `]}`), nil
		case "DescribeSubnets":
			if ids[0] != SyntheticAWSSubnetID {
				return json.RawMessage(`{"Subnets":[]}`), nil
			}
			return json.RawMessage(`{"Subnets":[` + SyntheticAWSSubnet + `]}`), nil
		case "DescribeSecurityGroups":
			if ids[0] != SyntheticAWSGroupID {
				return json.RawMessage(`{"SecurityGroups":[]}`), nil
			}
			return json.RawMessage(`{"SecurityGroups":[` + SyntheticAWSSecurityGroup + `]}`), nil
		}
		return nil, fmt.Errorf("unsupported synthetic action")
	}
}
