// AWS control-plane assets.
//
// Source APIs (read-only, exact native IDs only):
//
//	EC2 DescribeInstances, DescribeVpcs, DescribeSubnets, DescribeSecurityGroups
//
// EC2 answers the Query protocol with XML, so the SDK's typed response is
// re-encoded as JSON component evidence and marked raw_form=api_projection.
// Unknown vendor fields are therefore not preserved for AWS; the declared
// fields and their provenance still come from the source response.
// DescribeSecurityGroups returns inline ingress/egress rules, so no second
// request is made for a policy set.
package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

const awsAPIVersion = "2016-11-15"
const awsMapperVersion = "aws-ec2/v1"

var (
	awsInstanceID = regexp.MustCompile(`^i-[0-9a-f]+$`)
	awsVPCID      = regexp.MustCompile(`^vpc-[0-9a-f]+$`)
	awsSubnetID   = regexp.MustCompile(`^subnet-[0-9a-f]+$`)
	awsGroupID    = regexp.MustCompile(`^sg-[0-9a-f]+$`)
)

// awsRaw performs one exact-ID read. Actions are limited to the four declared
// EC2 calls.
type awsRaw func(ctx context.Context, action string, ids []string) (json.RawMessage, error)

// AwsRaw builds a typed EC2 caller. Responses are re-encoded as JSON.
func AwsRaw(ctx context.Context, cred connector.Credential, a model.Account) (awsRaw, error) {
	if a.Region == "" {
		return nil, fmt.Errorf("AWS region is required")
	}
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(a.Region)}
	options = append(options, awsconfig.WithCredentialsProvider(
		credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.AccessKeySecret, cred.SessionToken)))
	cfg, err := awsconfig.LoadDefaultConfig(ctx, options...)
	if err != nil {
		return nil, err
	}
	client := ec2.NewFromConfig(cfg)
	return func(ctx context.Context, action string, ids []string) (json.RawMessage, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch action {
		case "DescribeInstances":
			out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{InstanceIds: ids})
			if err != nil {
				return nil, err
			}
			return marshalAWS(out)
		case "DescribeVpcs":
			out, err := client.DescribeVpcs(ctx, &ec2.DescribeVpcsInput{VpcIds: ids})
			if err != nil {
				return nil, err
			}
			return marshalAWS(out)
		case "DescribeSubnets":
			out, err := client.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{SubnetIds: ids})
			if err != nil {
				return nil, err
			}
			return marshalAWS(out)
		case "DescribeSecurityGroups":
			out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: ids})
			if err != nil {
				return nil, err
			}
			return marshalAWS(out)
		}
		return nil, fmt.Errorf("unsupported asset action")
	}, nil
}

func marshalAWS(value any) (json.RawMessage, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode AWS response: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return nil, fmt.Errorf("asset response exceeds size limit")
	}
	return raw, nil
}

type awsClient struct {
	raw     awsRaw
	limiter *connector.Limiter
}

func (c *awsClient) ReadInstance(ctx context.Context, a model.Account, id string) (*model.Asset, error) {
	return ReadAWS(ctx, a, id, c.raw, c.limiter)
}

func (c *awsClient) ReadNetwork(ctx context.Context, a model.Account, kind string, ids []string) (map[string]*model.Asset, error) {
	return readAWSNetworkBatch(ctx, a, kind, ids, c.raw, c.limiter)
}

func (c *awsClient) ReadPolicies(ctx context.Context, a model.Account, id string) (model.AssetComponent, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return model.AssetComponent{}, err
	}
	raw, err := c.raw(ctx, "DescribeSecurityGroups", []string{id})
	return awsPolicyComponent(raw, err, id)
}

func awsPolicyComponent(raw json.RawMessage, err error, id string) (model.AssetComponent, error) {
	api := "EC2 DescribeSecurityGroups"
	c := model.AssetComponent{Status: "failed", SourceAPI: api, APIVersion: awsAPIVersion}
	if err != nil {
		c.Reason = errorCode(err, "aws")
		return c, nil
	}
	group, findErr := awsSecurityGroup(raw, id)
	if findErr != nil {
		c.Reason = "invalid_source_response"
		return c, nil
	}
	c = component(group, api, awsAPIVersion, time.Now().UTC())
	c.RawForm = "api_projection"
	return c, nil
}

func awsSecurityGroup(raw json.RawMessage, id string) (json.RawMessage, error) {
	var envelope struct{ SecurityGroups []json.RawMessage }
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, fmt.Errorf("invalid security group response")
	}
	for _, item := range envelope.SecurityGroups {
		var fields struct{ GroupId string }
		if json.Unmarshal(item, &fields) == nil && fields.GroupId == id {
			return item, nil
		}
	}
	return nil, fmt.Errorf("security group identity mismatch")
}

// ReadAWS requests exactly one EC2 instance and at most five attached
// security-group rule sets.
func ReadAWS(ctx context.Context, a model.Account, id string, raw awsRaw, limiter *connector.Limiter) (*model.Asset, error) {
	if !awsInstanceID.MatchString(id) {
		return nil, fmt.Errorf("invalid EC2 instance ID")
	}
	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}
	payload, err := raw(ctx, "DescribeInstances", []string{id})
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Reservations []struct{ Instances []json.RawMessage }
	}
	if json.Unmarshal(payload, &envelope) != nil {
		return nil, fmt.Errorf("invalid instance response")
	}
	var instances []json.RawMessage
	for _, reservation := range envelope.Reservations {
		instances = append(instances, reservation.Instances...)
	}
	if len(instances) == 0 {
		return nil, ErrNotVisible
	}
	if len(instances) != 1 {
		return nil, fmt.Errorf("unexpected instance response")
	}
	var i struct {
		InstanceId        string
		InstanceType      string
		PlatformDetails   string
		ImageId           string
		PrivateIpAddress  string
		PublicIpAddress   *string
		VpcId             string
		SubnetId          string
		State             struct{ Name string }
		Placement         struct{ AvailabilityZone string }
		SecurityGroups    []struct{ GroupId, GroupName string }
		Tags              []struct{ Key, Value string }
		NetworkInterfaces []struct {
			PrivateIpAddress   string
			Association        *struct{ PublicIp string }
			PrivateIpAddresses []struct{ PrivateIpAddress string }
		}
	}
	instance := instances[0]
	if json.Unmarshal(instance, &i) != nil || i.InstanceId != id {
		return nil, fmt.Errorf("instance identity mismatch")
	}
	privateIPs := []string{}
	if i.PrivateIpAddress != "" {
		privateIPs = append(privateIPs, i.PrivateIpAddress)
	}
	publicIPs := []string{}
	if i.PublicIpAddress != nil && *i.PublicIpAddress != "" {
		publicIPs = append(publicIPs, *i.PublicIpAddress)
	}
	for _, nic := range i.NetworkInterfaces {
		if nic.PrivateIpAddress != "" {
			privateIPs = append(privateIPs, nic.PrivateIpAddress)
		}
		for _, address := range nic.PrivateIpAddresses {
			if address.PrivateIpAddress != "" {
				privateIPs = append(privateIPs, address.PrivateIpAddress)
			}
		}
		if nic.Association != nil && nic.Association.PublicIp != "" {
			publicIPs = append(publicIPs, nic.Association.PublicIp)
		}
	}
	privateIPs, publicIPs = dedupeSort(privateIPs), dedupeSort(publicIPs)
	name := ""
	for _, tag := range i.Tags {
		if tag.Key == "Name" {
			name = tag.Value
		}
	}
	at := time.Now().UTC()
	osName := i.PlatformDetails
	if osName == "" {
		osName = i.ImageId
	}
	out := &model.Asset{
		AccountID: a.ID, Provider: "aws", AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: i.InstanceId, ResourceType: "ec2", Name: name, OS: osName,
		State: i.State.Name, InstanceType: i.InstanceType, Zone: i.Placement.AvailabilityZone,
		PublicIPs: publicIPs, PrivateIPs: privateIPs, VPCID: i.VpcId, SubnetID: i.SubnetId,
		MapperVersion: awsMapperVersion, ObservedAt: at,
		Components: map[string]model.AssetComponent{"instance": awsComponent(instance, "EC2 DescribeInstances", at)},
		Provenance: map[string]model.FieldOrigin{},
	}
	for _, group := range i.SecurityGroups {
		if group.GroupId != "" {
			out.SecurityGroupIDs = append(out.SecurityGroupIDs, group.GroupId)
		}
	}
	for _, tag := range i.Tags {
		out.Tags = append(out.Tags, model.AssetTag{Key: tag.Key, Value: tag.Value})
	}
	if sourceHas(instance, "/Tags") && out.Tags == nil {
		out.Tags = []model.AssetTag{}
	}
	if i.VpcId != "" {
		out.References = append(out.References, reference(a, "vpc", i.VpcId, "belongs_to_vpc", "instance", "/VpcId"))
	}
	if i.SubnetId != "" {
		out.References = append(out.References, reference(a, "subnet", i.SubnetId, "in_subnet", "instance", "/SubnetId"))
	}
	for n, group := range i.SecurityGroups {
		if group.GroupId != "" {
			out.References = append(out.References, reference(a, "security_group", group.GroupId, "attached_security_group", "instance", fmt.Sprintf("/SecurityGroups/%d/GroupId", n)))
		}
	}
	for field, path := range map[string]string{"resource_id": "/InstanceId", "os": "/PlatformDetails", "state": "/State/Name", "instance_type": "/InstanceType", "zone": "/Placement/AvailabilityZone", "vpc_id": "/VpcId", "subnet_id": "/SubnetId", "security_group_ids": "/SecurityGroups", "tags": "/Tags", "private_ips": "/NetworkInterfaces", "public_ips": "/NetworkInterfaces"} {
		if sourceHas(instance, path) {
			out.Provenance[field] = model.FieldOrigin{Source: "component:instance", Paths: []string{path}, Transform: "source_field_projection"}
		}
	}
	if name != "" {
		out.Provenance["name"] = model.FieldOrigin{Source: "component:instance", Paths: []string{"/Tags"}, Transform: "source_tag_name_projection"}
	}
	for field, path := range map[string]string{"account_uid": "/account_uid", "region": "/region"} {
		out.Provenance[field] = model.FieldOrigin{Source: "configuration", Paths: []string{path}, Transform: "explicit_connection_scope"}
	}
	out.Components["software"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["listening_ports"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["reachability"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	for n, group := range i.SecurityGroups {
		key := "security_group:" + group.GroupId
		c := model.AssetComponent{Status: "not_collected", Reason: "request_budget_exceeded", SourceAPI: "EC2 DescribeSecurityGroups", APIVersion: awsAPIVersion}
		if n >= MaxSecurityGroups || !awsGroupID.MatchString(group.GroupId) {
			out.Components[key] = c
			continue
		}
		if err := limiter.Wait(ctx); err != nil {
			c.Status, c.Reason = "failed", "timeout"
			out.Components[key] = c
			continue
		}
		policyRaw, err := raw(ctx, "DescribeSecurityGroups", []string{group.GroupId})
		policy, _ := awsPolicyComponent(policyRaw, err, group.GroupId)
		out.Components[key] = policy
	}
	return out, nil
}

func awsComponent(raw json.RawMessage, api string, at time.Time) model.AssetComponent {
	c := component(raw, api, awsAPIVersion, at)
	c.RawForm = "api_projection"
	return c
}

func dedupeSort(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func readAWSNetworkBatch(ctx context.Context, a model.Account, kind string, ids []string, raw awsRaw, limiter *connector.Limiter) (map[string]*model.Asset, error) {
	var action, listKey, idPath string
	switch kind {
	case "vpc":
		action, listKey, idPath = "DescribeVpcs", "Vpcs", "/VpcId"
	case "subnet":
		action, listKey, idPath = "DescribeSubnets", "Subnets", "/SubnetId"
	case "security_group":
		action, listKey, idPath = "DescribeSecurityGroups", "SecurityGroups", "/GroupId"
	default:
		return nil, fmt.Errorf("invalid network query scope")
	}
	if len(ids) == 0 || len(ids) > MaxSecurityGroups {
		return nil, fmt.Errorf("invalid network query scope")
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		if !ValidAWSResource(kind, id) || wanted[id] {
			return nil, fmt.Errorf("invalid or repeated network ID")
		}
		wanted[id] = true
	}
	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}
	payload, err := raw(ctx, action, ids)
	if err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(payload, &envelope) != nil {
		return nil, fmt.Errorf("invalid network response")
	}
	var items []json.RawMessage
	if data, ok := envelope[listKey]; !ok || string(data) == "null" || json.Unmarshal(data, &items) != nil {
		return nil, fmt.Errorf("missing network result set")
	}
	out := map[string]*model.Asset{}
	for _, item := range items {
		var fields map[string]json.RawMessage
		if json.Unmarshal(item, &fields) != nil {
			return nil, fmt.Errorf("invalid network record")
		}
		var id string
		key := strings.TrimPrefix(idPath, "/")
		if json.Unmarshal(fields[key], &id) != nil || !wanted[id] || out[id] != nil {
			return nil, fmt.Errorf("network identity mismatch")
		}
		value, err := normalizeAWSNetwork(a, kind, id, item)
		if err != nil {
			return nil, err
		}
		out[id] = value
	}
	return out, nil
}

func normalizeAWSNetwork(a model.Account, kind, id string, raw json.RawMessage) (*model.Asset, error) {
	var value struct {
		VpcId            string
		SubnetId         string
		GroupId          string
		CidrBlock        string
		AvailabilityZone string
		State            string
		VpcState         string
		GroupName        string
		Description      string
		IsDefault        *bool
		Tags             []struct{ Key, Value string }
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("invalid network fields")
	}
	at := time.Now().UTC()
	out := &model.Asset{
		AccountID: a.ID, Provider: "aws", AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: id, ResourceType: kind, ObservedAt: at, MapperVersion: "aws-vpc/v1",
		Components: map[string]model.AssetComponent{"details": awsComponent(raw, "EC2 "+awsAction(kind), at)},
		Provenance: map[string]model.FieldOrigin{},
		Network:    &model.AssetNetwork{CIDRBlock: value.CidrBlock, IsDefault: value.IsDefault, Description: value.Description},
	}
	paths := map[string]string{"resource_id": idPathFor(kind), "network.cidr_block": "/CidrBlock", "network.is_default": "/IsDefault", "tags": "/Tags"}
	name := ""
	for _, tag := range value.Tags {
		if tag.Key == "Name" {
			name = tag.Value
		}
	}
	switch kind {
	case "vpc":
		out.VPCID = id
		out.State = value.VpcState
		paths["vpc_id"] = "/VpcId"
	case "subnet":
		out.VPCID = value.VpcId
		out.SubnetID = id
		out.Zone = value.AvailabilityZone
		out.State = value.State
		paths["subnet_id"] = "/SubnetId"
		paths["vpc_id"] = "/VpcId"
		paths["zone"] = "/AvailabilityZone"
		if value.VpcId != "" {
			out.References = []model.AssetReference{reference(a, "vpc", value.VpcId, "belongs_to_vpc", "details", "/VpcId")}
		}
	case "security_group":
		out.VPCID = value.VpcId
		paths["network.description"] = "/Description"
		paths["vpc_id"] = "/VpcId"
		if _, err := awsSecurityGroupFromItem(raw, id); err == nil {
			out.Components["policies"] = awsComponent(raw, "EC2 DescribeSecurityGroups", at)
		}
	}
	if name != "" {
		out.Name = name
		paths["name"] = "/Tags"
	} else if value.GroupName != "" {
		out.Name = value.GroupName
		paths["name"] = "/GroupName"
	}
	if sourceHas(raw, "/Tags") {
		out.Tags = []model.AssetTag{}
		for _, tag := range value.Tags {
			out.Tags = append(out.Tags, model.AssetTag{Key: tag.Key, Value: tag.Value})
		}
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

func awsSecurityGroupFromItem(raw json.RawMessage, id string) (json.RawMessage, error) {
	var fields struct{ GroupId string }
	if json.Unmarshal(raw, &fields) != nil || fields.GroupId != id {
		return nil, fmt.Errorf("security group identity mismatch")
	}
	return raw, nil
}

func awsAction(kind string) string {
	switch kind {
	case "vpc":
		return "DescribeVpcs"
	case "subnet":
		return "DescribeSubnets"
	case "security_group":
		return "DescribeSecurityGroups"
	}
	return ""
}

func idPathFor(kind string) string {
	switch kind {
	case "vpc":
		return "/VpcId"
	case "subnet":
		return "/SubnetId"
	case "security_group":
		return "/GroupId"
	}
	return ""
}

// ValidAWSResource validates native EC2 resource IDs.
func ValidAWSResource(kind, id string) bool {
	if len(id) > 128 {
		return false
	}
	switch kind {
	case "ec2":
		return awsInstanceID.MatchString(id)
	case "vpc":
		return awsVPCID.MatchString(id)
	case "subnet":
		return awsSubnetID.MatchString(id)
	case "security_group":
		return awsGroupID.MatchString(id)
	}
	return false
}

// awsInstanceFromARN accepts either the native ID or an EC2 ARN and returns the
// native ID. No other resource type is interpreted as a host.
func awsInstanceFromARN(value string) (string, bool) {
	if awsInstanceID.MatchString(value) {
		return value, true
	}
	if index := strings.Index(value, ":instance/"); index >= 0 {
		id := value[index+len(":instance/"):]
		if awsInstanceID.MatchString(id) {
			return id, true
		}
	}
	return "", false
}

func init() {
	registerProvider(Provider{
		ID:                "aws",
		Name:              "Amazon Web Services",
		HostType:          "ec2",
		APIVersion:        awsAPIVersion,
		HostAPI:           "EC2 DescribeInstances",
		PolicyAPI:         "EC2 DescribeSecurityGroups",
		ResourceTypes:     []string{"ec2", "security_group", "vpc", "subnet"},
		MapperVersion:     awsMapperVersion,
		PoliciesInDetails: true,
		DocsURL:           "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html",
		SyntheticHostID:   SyntheticAWSInstanceID,
		HostID: func(r model.Resource) (string, bool) {
			switch strings.ToLower(r.Type) {
			case "host", "instance", "awsec2instance", "ec2 instance", "ec2":
			default:
				return "", false
			}
			return awsInstanceFromARN(r.ID)
		},
		AlertResourceIDs: func(a model.Account, native string) []string {
			ids := []string{native}
			if a.Region != "" && a.AccountUID != "" {
				ids = append(ids, "arn:aws:ec2:"+a.Region+":"+a.AccountUID+":instance/"+native)
			}
			return ids
		},
		Valid:              ValidAWSResource,
		QPS:                2,
		RequiresRegion:     true,
		ValidateCredential: requireAKSK,
		New: func(cred connector.Credential, a model.Account, limiter *connector.Limiter) (Client, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			raw, err := AwsRaw(ctx, cred, a)
			if err != nil {
				return nil, err
			}
			return &awsClient{raw: raw, limiter: limiter}, nil
		},
		Synthetic: func(limiter *connector.Limiter) Client {
			return &awsClient{raw: SyntheticAWSRaw(), limiter: limiter}
		},
	})
}
