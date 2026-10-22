// Alibaba Cloud control-plane assets.
//
// Source APIs (all read-only, exact native IDs only):
//
//	ECS  DescribeInstances, DescribeSecurityGroups, DescribeSecurityGroupAttribute
//	VPC  DescribeVpcs, DescribeVSwitches
//
// Requests use the generic OpenAPI RPC client so the saved component evidence
// is the exact JSON bytes returned by the vendor, not a typed projection.
package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
)

const aliyunECSAV = "2014-05-26"
const aliyunVPCAV = "2016-04-28"
const aliyunMapperVersion = "aliyun-ecs/v1"

var (
	aliyunInstanceID = regexp.MustCompile(`^i-[a-zA-Z0-9]+$`)
	aliyunVPCID      = regexp.MustCompile(`^vpc-[a-zA-Z0-9]+$`)
	aliyunVSwitchID  = regexp.MustCompile(`^vsw-[a-zA-Z0-9]+$`)
	aliyunGroupID    = regexp.MustCompile(`^sg-[a-zA-Z0-9]+$`)
	aliyunENIID      = regexp.MustCompile(`^eni-[a-zA-Z0-9]+$`)
)

var aliyunServices = map[string]struct{ endpoint, version string }{
	"ecs": {endpoint: "ecs.aliyuncs.com", version: aliyunECSAV},
	"vpc": {endpoint: "vpc.aliyuncs.com", version: aliyunVPCAV},
}

// AliyunCall builds a signed RPC caller for the ECS and VPC endpoints. The
// region is injected into every request because both APIs require RegionId.
func AliyunCall(cred connector.Credential, region string) (Call, error) {
	if region == "" {
		return nil, fmt.Errorf("aliyun region is required")
	}
	clients := map[string]*openapi.Client{}
	for name, spec := range aliyunServices {
		conf := &openapi.Config{
			AccessKeyId:     tea.String(cred.AccessKeyID),
			AccessKeySecret: tea.String(cred.AccessKeySecret),
			Endpoint:        tea.String(spec.endpoint),
			Protocol:        tea.String("HTTPS"),
			RegionId:        tea.String(region),
		}
		if cred.SessionToken != "" {
			conf.SecurityToken = tea.String(cred.SessionToken)
		}
		c, err := openapi.NewClient(conf)
		if err != nil {
			return nil, err
		}
		clients[name] = c
	}
	return func(ctx context.Context, svc, action string, params map[string]any) (result json.RawMessage, callErr error) {
		defer func() { callErr = connector.WithSourceAPI("aliyun", strings.ToUpper(svc)+" "+action, callErr) }()
		client, ok := clients[svc]
		if !ok {
			return nil, fmt.Errorf("unsupported asset service")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		spec := aliyunServices[svc]
		p := &openapi.Params{
			Action:      tea.String(action),
			Version:     tea.String(spec.version),
			Protocol:    tea.String("HTTPS"),
			Pathname:    tea.String("/"),
			Method:      tea.String("POST"),
			AuthType:    tea.String("AK"),
			Style:       tea.String("RPC"),
			ReqBodyType: tea.String("formData"),
			BodyType:    tea.String("binary"),
		}
		runtime := &service.RuntimeOptions{ConnectTimeout: tea.Int(10000), ReadTimeout: tea.Int(15000)}
		response, err := client.CallApi(p, &openapi.OpenApiRequest{Query: aliyunQuery(region, params)}, runtime)
		if err != nil {
			return nil, err
		}
		body, ok := response["body"].(io.ReadCloser)
		if !ok {
			return nil, fmt.Errorf("Alibaba API returned no response stream")
		}
		defer body.Close()
		return readAssetBody(body)
	}, nil
}

func aliyunQuery(region string, params map[string]any) map[string]*string {
	q := map[string]*string{"RegionId": tea.String(region)}
	for key, value := range params {
		switch v := value.(type) {
		case string:
			q[key] = tea.String(v)
		case int:
			q[key] = tea.String(strconv.Itoa(v))
		case int32:
			q[key] = tea.String(strconv.FormatInt(int64(v), 10))
		case int64:
			q[key] = tea.String(strconv.FormatInt(v, 10))
		case bool:
			q[key] = tea.String(strconv.FormatBool(v))
		case []string:
			b, _ := json.Marshal(v)
			q[key] = tea.String(string(b))
		}
	}
	return q
}

type aliyunClient struct {
	call    Call
	limiter *connector.Limiter
}

func (c *aliyunClient) ReadInstance(ctx context.Context, a model.Account, id string) (*model.Asset, error) {
	return ReadAliyun(ctx, a, id, c.call, c.limiter)
}

func (c *aliyunClient) ReadNetwork(ctx context.Context, a model.Account, kind string, ids []string) (map[string]*model.Asset, error) {
	if kind == "nic" {
		return readAliyunNICBatch(ctx, a, ids, c.call, c.limiter)
	}
	return readAliyunNetworkBatch(ctx, a, kind, ids, c.call, c.limiter)
}

func (c *aliyunClient) ReadPolicies(ctx context.Context, a model.Account, id string) (model.AssetComponent, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return model.AssetComponent{}, err
	}
	raw, err := c.call(ctx, "ecs", "DescribeSecurityGroupAttribute", map[string]any{"SecurityGroupId": id})
	return aliyunPolicyComponent(raw, err), nil
}

func aliyunPolicyComponent(raw json.RawMessage, err error) model.AssetComponent {
	api := "ECS DescribeSecurityGroupAttribute"
	c := model.AssetComponent{Status: "failed", SourceAPI: api, APIVersion: aliyunECSAV}
	if err != nil {
		c.Reason = errorCode(err, "aliyun")
		c.SourceError = connector.SourceError(connector.WithSourceAPI("aliyun", c.SourceAPI, err))
		return c
	}
	var response struct{ Permissions json.RawMessage }
	if json.Unmarshal(raw, &response) != nil || len(response.Permissions) == 0 || string(response.Permissions) == "null" {
		c.Reason = "invalid_source_response"
		return c
	}
	return component(response.Permissions, api, aliyunECSAV, time.Now().UTC())
}

// ReadAliyun requests exactly one ECS instance and at most five attached
// security-group rule sets.
func ReadAliyun(ctx context.Context, a model.Account, id string, call Call, limiter *connector.Limiter) (*model.Asset, error) {
	if !aliyunInstanceID.MatchString(id) {
		return nil, fmt.Errorf("invalid ECS instance ID")
	}
	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := call(ctx, "ecs", "DescribeInstances", map[string]any{"InstanceIds": []string{id}, "PageSize": 1})
	if err != nil {
		return nil, err
	}
	var page struct {
		Instances  struct{ Instance []json.RawMessage }
		TotalCount int
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		return nil, fmt.Errorf("invalid instance response")
	}
	if len(page.Instances.Instance) == 0 {
		return nil, ErrNotVisible
	}
	if len(page.Instances.Instance) != 1 {
		return nil, fmt.Errorf("unexpected instance response")
	}
	var i struct {
		InstanceId, InstanceName, OSName, Status, InstanceType, ZoneId string
		PublicIpAddress                                                struct{ IpAddress []string }
		EipAddress                                                     struct{ IpAddress string }
		VpcAttributes                                                  struct {
			VpcId, VSwitchId string
			PrivateIpAddress struct{ IpAddress []string }
		}
		SecurityGroupIds  struct{ SecurityGroupId []string }
		NetworkInterfaces struct {
			NetworkInterface []struct{ NetworkInterfaceId string }
		}
		Tags struct {
			Tag []struct{ TagKey, TagValue string }
		}
	}
	instance := page.Instances.Instance[0]
	if err := json.Unmarshal(instance, &i); err != nil || i.InstanceId != id {
		return nil, fmt.Errorf("instance identity mismatch")
	}
	publicIPs := append([]string(nil), i.PublicIpAddress.IpAddress...)
	if i.EipAddress.IpAddress != "" {
		publicIPs = append(publicIPs, i.EipAddress.IpAddress)
	}
	at := time.Now().UTC()
	out := &model.Asset{
		AccountID: a.ID, Provider: "aliyun", AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: i.InstanceId, ResourceType: "ecs", Name: i.InstanceName, OS: i.OSName,
		State: i.Status, InstanceType: i.InstanceType, Zone: i.ZoneId,
		PublicIPs: publicIPs, PrivateIPs: i.VpcAttributes.PrivateIpAddress.IpAddress,
		VPCID: i.VpcAttributes.VpcId, SubnetID: i.VpcAttributes.VSwitchId,
		SecurityGroupIDs: i.SecurityGroupIds.SecurityGroupId,
		MapperVersion:    aliyunMapperVersion, ObservedAt: at,
		Components: map[string]model.AssetComponent{"instance": component(instance, "ECS DescribeInstances", aliyunECSAV, at)},
		Provenance: map[string]model.FieldOrigin{},
	}
	for _, t := range i.Tags.Tag {
		out.Tags = append(out.Tags, model.AssetTag{Key: t.TagKey, Value: t.TagValue})
	}
	if sourceHas(instance, "/Tags") && out.Tags == nil {
		out.Tags = []model.AssetTag{}
	}
	if i.VpcAttributes.VpcId != "" {
		out.References = append(out.References, reference(a, "vpc", i.VpcAttributes.VpcId, "belongs_to_vpc", "instance", "/VpcAttributes/VpcId"))
	}
	if i.VpcAttributes.VSwitchId != "" {
		out.References = append(out.References, reference(a, "subnet", i.VpcAttributes.VSwitchId, "in_subnet", "instance", "/VpcAttributes/VSwitchId"))
	}
	for n, g := range i.SecurityGroupIds.SecurityGroupId {
		out.References = append(out.References, reference(a, "security_group", g, "attached_security_group", "instance", fmt.Sprintf("/SecurityGroupIds/SecurityGroupId/%d", n)))
	}
	for n, nic := range i.NetworkInterfaces.NetworkInterface {
		if aliyunENIID.MatchString(nic.NetworkInterfaceId) {
			out.References = append(out.References, reference(a, "nic", nic.NetworkInterfaceId, "attached_network_interface", "instance", fmt.Sprintf("/NetworkInterfaces/NetworkInterface/%d/NetworkInterfaceId", n)))
		}
	}
	for field, path := range map[string]string{"resource_id": "/InstanceId", "name": "/InstanceName", "os": "/OSName", "state": "/Status", "instance_type": "/InstanceType", "zone": "/ZoneId", "private_ips": "/VpcAttributes/PrivateIpAddress/IpAddress", "vpc_id": "/VpcAttributes/VpcId", "subnet_id": "/VpcAttributes/VSwitchId", "security_group_ids": "/SecurityGroupIds/SecurityGroupId", "tags": "/Tags"} {
		if sourceHas(instance, path) {
			out.Provenance[field] = model.FieldOrigin{Source: "component:instance", Paths: []string{path}, Transform: "source_field_projection"}
		}
	}
	var publicPaths []string
	for _, path := range []string{"/PublicIpAddress/IpAddress", "/EipAddress/IpAddress"} {
		if sourceHas(instance, path) {
			publicPaths = append(publicPaths, path)
		}
	}
	if len(publicPaths) > 0 {
		out.Provenance["public_ips"] = model.FieldOrigin{Source: "component:instance", Paths: publicPaths, Transform: "source_field_merge"}
	}
	for field, path := range map[string]string{"account_uid": "/account_uid", "region": "/region"} {
		out.Provenance[field] = model.FieldOrigin{Source: "configuration", Paths: []string{path}, Transform: "explicit_connection_scope"}
	}
	out.Components["software"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["listening_ports"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["reachability"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	for n, g := range i.SecurityGroupIds.SecurityGroupId {
		key := "security_group:" + g
		c := model.AssetComponent{Status: "not_collected", Reason: "request_budget_exceeded", SourceAPI: "ECS DescribeSecurityGroupAttribute", APIVersion: aliyunECSAV}
		if n >= MaxSecurityGroups || !aliyunGroupID.MatchString(g) {
			out.Components[key] = c
			continue
		}
		if err := limiter.Wait(ctx); err != nil {
			c.Status, c.Reason = "failed", "timeout"
			out.Components[key] = c
			continue
		}
		if err := ctx.Err(); err != nil {
			c.Status, c.Reason = "failed", "timeout"
			out.Components[key] = c
			continue
		}
		policy, err := call(ctx, "ecs", "DescribeSecurityGroupAttribute", map[string]any{"SecurityGroupId": g})
		out.Components[key] = aliyunPolicyComponent(policy, err)
	}
	return out, nil
}

func aliyunNetworkAPI(kind string) (service, action, idParam, listPath, idPath, api string) {
	switch kind {
	case "vpc":
		return "vpc", "DescribeVpcs", "VpcId", "/Vpcs/Vpc", "/VpcId", "VPC DescribeVpcs"
	case "subnet":
		return "vpc", "DescribeVSwitches", "VSwitchId", "/VSwitches/VSwitch", "/VSwitchId", "VPC DescribeVSwitches"
	case "security_group":
		return "ecs", "DescribeSecurityGroups", "SecurityGroupIds", "/SecurityGroups/SecurityGroup", "/SecurityGroupId", "ECS DescribeSecurityGroups"
	}
	return "", "", "", "", "", ""
}

func readAliyunNetworkBatch(ctx context.Context, a model.Account, kind string, ids []string, call Call, limiter *connector.Limiter) (map[string]*model.Asset, error) {
	service, action, idParam, listPath, idPath, api := aliyunNetworkAPI(kind)
	if action == "" || len(ids) == 0 || len(ids) > MaxSecurityGroups {
		return nil, fmt.Errorf("invalid network query scope")
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		if !ValidAliyunResource(kind, id) || wanted[id] {
			return nil, fmt.Errorf("invalid or repeated network ID")
		}
		wanted[id] = true
	}
	out := map[string]*model.Asset{}
	for _, id := range ids {
		if err := limiter.Wait(ctx); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var param any = id
		if idParam == "SecurityGroupIds" {
			param = []string{id}
		}
		raw, err := call(ctx, service, action, map[string]any{idParam: param, "PageSize": 1})
		if err != nil {
			return nil, err
		}
		items, err := aliyunList(raw, listPath)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			continue
		}
		if len(items) != 1 {
			return nil, fmt.Errorf("unexpected network response")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(items[0], &fields) != nil {
			return nil, fmt.Errorf("invalid network record")
		}
		var got string
		if json.Unmarshal(fields[pathKey(idPath)], &got) != nil || got != id || !wanted[id] {
			return nil, fmt.Errorf("network identity mismatch")
		}
		value, err := normalizeAliyunNetwork(a, kind, id, action, api, items[0])
		if err != nil {
			return nil, err
		}
		out[id] = value
	}
	return out, nil
}

func aliyunList(raw json.RawMessage, path string) ([]json.RawMessage, error) {
	parts := splitPath(path)
	var current json.RawMessage = raw
	for _, key := range parts {
		var object map[string]json.RawMessage
		if json.Unmarshal(current, &object) != nil {
			return nil, fmt.Errorf("missing network result set")
		}
		value, ok := object[key]
		if !ok || string(value) == "null" {
			return nil, fmt.Errorf("missing network result set")
		}
		current = value
	}
	var items []json.RawMessage
	if json.Unmarshal(current, &items) != nil || items == nil {
		return nil, fmt.Errorf("missing network result set")
	}
	return items, nil
}

func splitPath(path string) []string {
	out := []string{}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func pathKey(path string) string {
	parts := splitPath(path)
	if len(parts) == 0 {
		return path
	}
	return parts[len(parts)-1]
}

func normalizeAliyunNetwork(a model.Account, kind, id, action, api string, raw json.RawMessage) (*model.Asset, error) {
	var value struct {
		VpcId, VpcName, VSwitchId, VSwitchName, SecurityGroupId, SecurityGroupName, Description string
		CidrBlock, Ipv6CidrBlock, CreationTime, ZoneId                                          string
		IsDefault                                                                               *bool
		Tags                                                                                    struct {
			Tag []struct{ Key, Value, TagKey, TagValue string }
		}
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("invalid network fields")
	}
	at := time.Now().UTC()
	out := &model.Asset{
		AccountID: a.ID, Provider: "aliyun", AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: id, ResourceType: kind, ObservedAt: at, MapperVersion: "aliyun-vpc/v1",
		Components: map[string]model.AssetComponent{"details": component(raw, api, aliyunVPCAV, at)},
		Provenance: map[string]model.FieldOrigin{},
		Network:    &model.AssetNetwork{Description: value.Description, CIDRBlock: value.CidrBlock, IPv6CIDRBlock: value.Ipv6CidrBlock, IsDefault: value.IsDefault, SourceCreatedTime: value.CreationTime},
	}
	paths := map[string]string{"network.cidr_block": "/CidrBlock", "network.ipv6_cidr_block": "/Ipv6CidrBlock", "network.is_default": "/IsDefault", "network.source_created_time": "/CreationTime", "tags": "/Tags/Tag"}
	switch kind {
	case "vpc":
		out.Name = value.VpcName
		out.VPCID = id
		paths["resource_id"] = "/VpcId"
		paths["vpc_id"] = "/VpcId"
		paths["name"] = "/VpcName"
	case "subnet":
		out.Name = value.VSwitchName
		out.VPCID = value.VpcId
		out.SubnetID = id
		out.Zone = value.ZoneId
		paths["resource_id"] = "/VSwitchId"
		paths["subnet_id"] = "/VSwitchId"
		paths["name"] = "/VSwitchName"
		paths["zone"] = "/ZoneId"
		paths["vpc_id"] = "/VpcId"
		if value.VpcId != "" {
			out.References = []model.AssetReference{reference(a, "vpc", value.VpcId, "belongs_to_vpc", "details", "/VpcId")}
		}
	case "security_group":
		out.Name = value.SecurityGroupName
		out.VPCID = value.VpcId
		paths["resource_id"] = "/SecurityGroupId"
		paths["name"] = "/SecurityGroupName"
		paths["network.description"] = "/Description"
		paths["vpc_id"] = "/VpcId"
	}
	if sourceHas(raw, "/Tags/Tag") {
		out.Tags = []model.AssetTag{}
		for _, tag := range value.Tags.Tag {
			key, val := tag.Key, tag.Value
			if tag.TagKey != "" {
				key, val = tag.TagKey, tag.TagValue
			}
			out.Tags = append(out.Tags, model.AssetTag{Key: key, Value: val})
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

// readAliyunNICBatch requests exact ENI IDs from the ECS API.
func readAliyunNICBatch(ctx context.Context, a model.Account, ids []string, call Call, limiter *connector.Limiter) (map[string]*model.Asset, error) {
	if len(ids) == 0 || len(ids) > MaxNICs {
		return nil, fmt.Errorf("invalid network interface query scope")
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		if !aliyunENIID.MatchString(id) || wanted[id] {
			return nil, fmt.Errorf("invalid or repeated network interface ID")
		}
		wanted[id] = true
	}
	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}
	raw, err := call(ctx, "ecs", "DescribeNetworkInterfaces", map[string]any{
		"NetworkInterfaceId": ids,
		"MaxResults":         len(ids),
	})
	if err != nil {
		return nil, err
	}
	var envelope struct {
		NetworkInterfaceSets struct{ NetworkInterfaceSet []json.RawMessage }
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, fmt.Errorf("invalid network interface response")
	}
	out := map[string]*model.Asset{}
	for _, item := range envelope.NetworkInterfaceSets.NetworkInterfaceSet {
		var identity struct{ NetworkInterfaceId string }
		if json.Unmarshal(item, &identity) != nil || !wanted[identity.NetworkInterfaceId] || out[identity.NetworkInterfaceId] != nil {
			return nil, fmt.Errorf("network interface identity mismatch")
		}
		value, err := normalizeAliyunNIC(a, identity.NetworkInterfaceId, item)
		if err != nil {
			return nil, err
		}
		out[identity.NetworkInterfaceId] = value
	}
	return out, nil
}

func normalizeAliyunNIC(a model.Account, id string, raw json.RawMessage) (*model.Asset, error) {
	var value struct {
		NetworkInterfaceId, NetworkInterfaceName, VpcId, VSwitchId string
		MacAddress, Type, Status, CreationTime, InstanceId         string
		SecurityGroupIds                                           struct{ SecurityGroupId []string }
		PrivateIpSets                                              struct {
			PrivateIpSet []struct {
				PrivateIpAddress string
				Primary          bool
			}
		}
		Tags struct {
			Tag []struct{ Key, Value, TagKey, TagValue string }
		}
	}
	if json.Unmarshal(raw, &value) != nil || value.NetworkInterfaceId != id {
		return nil, fmt.Errorf("network interface identity mismatch")
	}
	primary := strings.EqualFold(value.Type, "Primary")
	at := time.Now().UTC()
	out := &model.Asset{
		AccountID: a.ID, Provider: a.Provider, AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: id, ResourceType: "nic", Name: value.NetworkInterfaceName,
		VPCID: value.VpcId, SubnetID: value.VSwitchId, SecurityGroupIDs: value.SecurityGroupIds.SecurityGroupId,
		State: value.Status, ObservedAt: at, MapperVersion: "aliyun-eni/v1",
		Components: map[string]model.AssetComponent{"details": component(raw, "ECS DescribeNetworkInterfaces", aliyunECSAV, at)},
		Provenance: map[string]model.FieldOrigin{},
		Network:    &model.AssetNetwork{MACAddress: value.MacAddress, Primary: &primary, SourceCreatedTime: value.CreationTime},
	}
	for _, address := range value.PrivateIpSets.PrivateIpSet {
		if address.PrivateIpAddress != "" {
			out.PrivateIPs = append(out.PrivateIPs, address.PrivateIpAddress)
		}
	}
	if sourceHas(raw, "/Tags/Tag") {
		out.Tags = []model.AssetTag{}
		for _, tag := range value.Tags.Tag {
			key, val := tag.Key, tag.Value
			if tag.TagKey != "" {
				key, val = tag.TagKey, tag.TagValue
			}
			out.Tags = append(out.Tags, model.AssetTag{Key: key, Value: val})
		}
	}
	if value.VpcId != "" {
		out.References = append(out.References, reference(a, "vpc", value.VpcId, "belongs_to_vpc", "details", "/VpcId"))
	}
	if value.VSwitchId != "" {
		out.References = append(out.References, reference(a, "subnet", value.VSwitchId, "in_subnet", "details", "/VSwitchId"))
	}
	for n, group := range value.SecurityGroupIds.SecurityGroupId {
		if aliyunGroupID.MatchString(group) {
			out.References = append(out.References, reference(a, "security_group", group, "attached_security_group", "details", fmt.Sprintf("/SecurityGroupIds/SecurityGroupId/%d", n)))
		}
	}
	if aliyunInstanceID.MatchString(value.InstanceId) {
		out.References = append(out.References, reference(a, "ecs", value.InstanceId, "attached_to_host", "details", "/InstanceId"))
	}
	for field, path := range map[string]string{
		"resource_id": "/NetworkInterfaceId", "name": "/NetworkInterfaceName", "state": "/Status",
		"vpc_id": "/VpcId", "subnet_id": "/VSwitchId", "security_group_ids": "/SecurityGroupIds/SecurityGroupId",
		"private_ips": "/PrivateIpSets/PrivateIpSet", "tags": "/Tags/Tag",
		"network.mac_address": "/MacAddress", "network.primary": "/Type",
		"network.source_created_time": "/CreationTime",
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

// ValidAliyunResource validates native IDs without guessing resource identity.
func ValidAliyunResource(kind, id string) bool {
	if len(id) > 128 {
		return false
	}
	switch kind {
	case "ecs":
		return aliyunInstanceID.MatchString(id)
	case "vpc":
		return aliyunVPCID.MatchString(id)
	case "subnet":
		return aliyunVSwitchID.MatchString(id)
	case "security_group":
		return aliyunGroupID.MatchString(id)
	case "nic":
		return aliyunENIID.MatchString(id)
	}
	return false
}

func init() {
	registerProvider(Provider{
		ID:              "aliyun",
		Name:            "Alibaba Cloud",
		HostType:        "ecs",
		APIVersion:      aliyunECSAV,
		HostAPI:         "ECS DescribeInstances",
		PolicyAPI:       "ECS DescribeSecurityGroupAttribute",
		ResourceTypes:   []string{"ecs", "security_group", "vpc", "subnet", "nic"},
		MapperVersion:   aliyunMapperVersion,
		DocsURL:         "https://help.aliyun.com/zh/ecs/developer-reference/api-ecs-2014-05-26-describeinstances",
		SyntheticHostID: "i-mock0001",
		AlertHostType:   "host",
		HostID: func(r model.Resource) (string, bool) {
			if r.Type == "host" && aliyunInstanceID.MatchString(r.ID) {
				return r.ID, true
			}
			return "", false
		},
		Valid:              ValidAliyunResource,
		QPS:                2,
		RequiresRegion:     true,
		ValidateCredential: requireAKSK,
		New: func(cred connector.Credential, a model.Account, limiter *connector.Limiter) (Client, error) {
			call, err := AliyunCall(cred, a.Region)
			if err != nil {
				return nil, err
			}
			return &aliyunClient{call: call, limiter: limiter}, nil
		},
		Synthetic: func(limiter *connector.Limiter) Client {
			return &aliyunClient{call: SyntheticAliyunCall(), limiter: limiter}
		},
	})
}
