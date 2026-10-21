// Huawei Cloud control-plane assets.
//
// Source APIs (read-only, exact native IDs only):
//
//	ECS v2  ShowServer
//	VPC v2  ShowVpc, ShowSubnet, ShowSecurityGroup
//
// The SDK request definitions are reused with a raw-body response type, so the
// saved component evidence is the exact JSON bytes returned by the vendor.
// ShowServer does not report a subnet ID, so Huawei hosts carry only the
// source-declared VPC reference; the subnet stays unknown instead of inferred.
package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/def"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/region"
	ecs "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2"
	ecsmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/ecs/v2/model"
	vpc "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2"
	vpcmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/vpc/v2/model"
)

const huaweiAPIVersion = "v2"
const huaweiMapperVersion = "huawei-ecs/v1"

var huaweiID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// huaweiRaw performs one exact-ID read. Actions are limited to the four
// control-plane calls declared by this adapter.
type huaweiRaw func(ctx context.Context, action string, params map[string]string) (json.RawMessage, error)

func HuaweiRaw(cred connector.Credential, a model.Account, timeout time.Duration) (huaweiRaw, error) {
	projectID := ""
	if a.Options != nil {
		projectID = a.Options["project_id"]
	}
	if projectID == "" {
		return nil, fmt.Errorf("Huawei project_id option is required")
	}
	if a.Region == "" {
		return nil, fmt.Errorf("Huawei region is required")
	}
	credentials, err := auth.NewBasicCredentialsBuilder().
		WithAk(cred.AccessKeyID).
		WithSk(cred.AccessKeySecret).
		WithSecurityToken(cred.SessionToken).
		WithProjectId(projectID).
		SafeBuild()
	if err != nil {
		return nil, err
	}
	endpoint := func(service string) string {
		if a.Options != nil {
			if custom := a.Options[service+"_endpoint"]; custom != "" {
				return custom
			}
		}
		return fmt.Sprintf("https://%s.%s.myhuaweicloud.com", service, a.Region)
	}
	build := func(service string) *core.HcHttpClient {
		httpConfig := config.DefaultHttpConfig()
		httpConfig.Timeout = timeout
		ep := endpoint(service)
		return core.NewHcHttpClientBuilder().
			WithCredential(credentials).
			WithRegion(region.NewRegion(a.Region, ep)).
			WithEndpoint(ep).
			WithHttpConfig(httpConfig).
			Build()
	}
	ecsHTTP, vpcHTTP := build("ecs"), build("vpc")

	return func(ctx context.Context, action string, params map[string]string) (json.RawMessage, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch action {
		case "ShowServer":
			return huaweiSync(ecsHTTP, &ecsmodel.ShowServerRequest{ServerId: params["ServerId"]}, ecs.GenReqDefForShowServer())
		case "ShowVpc":
			return huaweiSync(vpcHTTP, &vpcmodel.ShowVpcRequest{VpcId: params["VpcId"]}, vpc.GenReqDefForShowVpc())
		case "ShowSubnet":
			return huaweiSync(vpcHTTP, &vpcmodel.ShowSubnetRequest{SubnetId: params["SubnetId"]}, vpc.GenReqDefForShowSubnet())
		case "ShowSecurityGroup":
			return huaweiSync(vpcHTTP, &vpcmodel.ShowSecurityGroupRequest{SecurityGroupId: params["SecurityGroupId"]}, vpc.GenReqDefForShowSecurityGroup())
		}
		return nil, fmt.Errorf("unsupported asset action")
	}, nil
}

// huaweiStream intercepts the response body before the SDK deserializes it.
type huaweiStream struct {
	Body           io.ReadCloser
	HttpStatusCode int
}

func huaweiSync(client *core.HcHttpClient, request interface{}, requestDef *def.HttpRequestDef) (json.RawMessage, error) {
	stream := &huaweiStream{}
	requestDef.Response = stream
	if _, err := client.Sync(request, requestDef); err != nil {
		return nil, err
	}
	if stream.Body == nil {
		return nil, fmt.Errorf("Huawei API returned no response stream")
	}
	defer stream.Body.Close()
	return readAssetBody(stream.Body)
}

type huaweiClient struct {
	raw     huaweiRaw
	limiter *connector.Limiter
}

func (c *huaweiClient) ReadInstance(ctx context.Context, a model.Account, id string) (*model.Asset, error) {
	return ReadHuawei(ctx, a, id, c.raw, c.limiter)
}

func (c *huaweiClient) ReadNetwork(ctx context.Context, a model.Account, kind string, ids []string) (map[string]*model.Asset, error) {
	return readHuaweiNetworkBatch(ctx, a, kind, ids, c.raw, c.limiter)
}

func (c *huaweiClient) ReadPolicies(ctx context.Context, a model.Account, id string) (model.AssetComponent, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return model.AssetComponent{}, err
	}
	raw, err := c.raw(ctx, "ShowSecurityGroup", map[string]string{"SecurityGroupId": id})
	return huaweiPolicyComponent(raw, err)
}

func huaweiEnvelope(raw json.RawMessage, key string) (json.RawMessage, error) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, fmt.Errorf("invalid %s response", key)
	}
	value, ok := envelope[key]
	if !ok || len(value) == 0 || string(value) == "null" {
		return nil, fmt.Errorf("missing %s response", key)
	}
	return value, nil
}

func huaweiPolicyComponent(raw json.RawMessage, err error) (model.AssetComponent, error) {
	api := "VPC ShowSecurityGroup"
	c := model.AssetComponent{Status: "failed", SourceAPI: api, APIVersion: huaweiAPIVersion}
	if err != nil {
		c.Reason = errorCode(err, "huawei")
		return c, nil
	}
	group, envelopeErr := huaweiEnvelope(raw, "security_group")
	if envelopeErr != nil {
		c.Reason = "invalid_source_response"
		return c, nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(group, &fields) != nil {
		c.Reason = "invalid_source_response"
		return c, nil
	}
	rules, ok := fields["security_group_rules"]
	if !ok || len(rules) == 0 || string(rules) == "null" {
		c.Reason = "invalid_source_response"
		return c, nil
	}
	return component(rules, api, huaweiAPIVersion, time.Now().UTC()), nil
}

// ReadHuawei requests exactly one ECS server and at most five attached
// security-group rule sets.
func ReadHuawei(ctx context.Context, a model.Account, id string, raw huaweiRaw, limiter *connector.Limiter) (*model.Asset, error) {
	if !huaweiID.MatchString(id) {
		return nil, fmt.Errorf("invalid ECS server ID")
	}
	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}
	payload, err := raw(ctx, "ShowServer", map[string]string{"ServerId": id})
	if err != nil {
		return nil, err
	}
	server, err := huaweiEnvelope(payload, "server")
	if err != nil {
		return nil, err
	}
	var s struct {
		ID        string              `json:"id"`
		Name      string              `json:"name"`
		Status    string              `json:"status"`
		Created   string              `json:"created"`
		TenantID  string              `json:"tenant_id"`
		Flavor    struct{ ID string } `json:"flavor"`
		Metadata  map[string]string   `json:"metadata"`
		Addresses map[string][]struct {
			Addr    string `json:"addr"`
			Version string `json:"version"`
			Type    string `json:"OS-EXT-IPS:type"`
		} `json:"addresses"`
		SecurityGroups []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"security_groups"`
		Zone string   `json:"OS-EXT-AZ:availability_zone"`
		Tags []string `json:"tags"`
	}
	if json.Unmarshal(server, &s) != nil || s.ID != id {
		return nil, fmt.Errorf("server identity mismatch")
	}
	var publicIPs, privateIPs []string
	networks := make([]string, 0, len(s.Addresses))
	for name := range s.Addresses {
		networks = append(networks, name)
	}
	sort.Strings(networks)
	for _, name := range networks {
		for _, address := range s.Addresses[name] {
			if address.Addr == "" {
				continue
			}
			if strings.EqualFold(address.Type, "floating") {
				publicIPs = append(publicIPs, address.Addr)
			} else {
				privateIPs = append(privateIPs, address.Addr)
			}
		}
	}
	sort.Strings(publicIPs)
	sort.Strings(privateIPs)
	osName := s.Metadata["image_name"]
	if osName == "" {
		osName = s.Metadata["os_type"]
	}
	at := time.Now().UTC()
	out := &model.Asset{
		AccountID: a.ID, Provider: "huawei", AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: s.ID, ResourceType: "ecs", Name: s.Name, OS: osName, State: s.Status,
		InstanceType: s.Flavor.ID, Zone: s.Zone, PublicIPs: publicIPs, PrivateIPs: privateIPs,
		VPCID: s.Metadata["vpc_id"], MapperVersion: huaweiMapperVersion, ObservedAt: at,
		Components: map[string]model.AssetComponent{"instance": component(server, "ECS ShowServer", huaweiAPIVersion, at)},
		Provenance: map[string]model.FieldOrigin{},
	}
	for _, tag := range s.Tags {
		key, value, _ := strings.Cut(tag, "=")
		out.Tags = append(out.Tags, model.AssetTag{Key: key, Value: value})
	}
	if sourceHas(server, "/tags") && out.Tags == nil {
		out.Tags = []model.AssetTag{}
	}
	if out.VPCID != "" {
		out.References = append(out.References, reference(a, "vpc", out.VPCID, "belongs_to_vpc", "instance", "/metadata/vpc_id"))
	}
	for n, group := range s.SecurityGroups {
		if group.ID == "" {
			continue
		}
		out.References = append(out.References, reference(a, "security_group", group.ID, "attached_security_group", "instance", fmt.Sprintf("/security_groups/%d/id", n)))
	}
	for field, path := range map[string]string{"resource_id": "/id", "name": "/name", "state": "/status", "instance_type": "/flavor/id", "zone": "/OS-EXT-AZ:availability_zone", "private_ips": "/addresses", "public_ips": "/addresses", "vpc_id": "/metadata/vpc_id", "security_group_ids": "/security_groups", "tags": "/tags"} {
		if sourceHas(server, path) {
			transform := "source_field_projection"
			if path == "/addresses" {
				transform = "source_field_filter_by_ip_type"
			}
			out.Provenance[field] = model.FieldOrigin{Source: "component:instance", Paths: []string{path}, Transform: transform}
		}
	}
	if sourceHas(server, "/metadata/image_name") {
		out.Provenance["os"] = model.FieldOrigin{Source: "component:instance", Paths: []string{"/metadata/image_name"}, Transform: "source_field_projection"}
	} else if sourceHas(server, "/metadata/os_type") {
		out.Provenance["os"] = model.FieldOrigin{Source: "component:instance", Paths: []string{"/metadata/os_type"}, Transform: "source_field_projection"}
	}
	for field, path := range map[string]string{"account_uid": "/account_uid", "region": "/region"} {
		out.Provenance[field] = model.FieldOrigin{Source: "configuration", Paths: []string{path}, Transform: "explicit_connection_scope"}
	}
	out.Components["software"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["listening_ports"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["reachability"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	for n, group := range s.SecurityGroups {
		key := "security_group:" + group.ID
		c := model.AssetComponent{Status: "not_collected", Reason: "request_budget_exceeded", SourceAPI: "VPC ShowSecurityGroup", APIVersion: huaweiAPIVersion}
		if n >= MaxSecurityGroups || !huaweiID.MatchString(group.ID) {
			out.Components[key] = c
			continue
		}
		if err := limiter.Wait(ctx); err != nil {
			c.Status, c.Reason = "failed", "timeout"
			out.Components[key] = c
			continue
		}
		policyRaw, err := raw(ctx, "ShowSecurityGroup", map[string]string{"SecurityGroupId": group.ID})
		policy, _ := huaweiPolicyComponent(policyRaw, err)
		out.Components[key] = policy
	}
	return out, nil
}

func huaweiNetworkAction(kind string) (action, key, idParam, api string) {
	switch kind {
	case "vpc":
		return "ShowVpc", "vpc", "VpcId", "VPC ShowVpc"
	case "subnet":
		return "ShowSubnet", "subnet", "SubnetId", "VPC ShowSubnet"
	case "security_group":
		return "ShowSecurityGroup", "security_group", "SecurityGroupId", "VPC ShowSecurityGroup"
	}
	return "", "", "", ""
}

func readHuaweiNetworkBatch(ctx context.Context, a model.Account, kind string, ids []string, raw huaweiRaw, limiter *connector.Limiter) (map[string]*model.Asset, error) {
	action, key, idParam, api := huaweiNetworkAction(kind)
	if action == "" || len(ids) == 0 || len(ids) > MaxSecurityGroups {
		return nil, fmt.Errorf("invalid network query scope")
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		if !ValidHuaweiResource(kind, id) || wanted[id] {
			return nil, fmt.Errorf("invalid or repeated network ID")
		}
		wanted[id] = true
	}
	out := map[string]*model.Asset{}
	for _, id := range ids {
		if err := limiter.Wait(ctx); err != nil {
			return nil, err
		}
		payload, err := raw(ctx, action, map[string]string{idParam: id})
		if err != nil {
			return nil, err
		}
		item, err := huaweiEnvelope(payload, key)
		if err != nil {
			return nil, err
		}
		value, err := normalizeHuaweiNetwork(a, kind, id, api, item)
		if err != nil {
			return nil, err
		}
		out[id] = value
	}
	return out, nil
}

func normalizeHuaweiNetwork(a model.Account, kind, id, api string, raw json.RawMessage) (*model.Asset, error) {
	var value struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		CIDR        string `json:"cidr"`
		VpcID       string `json:"vpc_id"`
		Zone        string `json:"availability_zone"`
		Status      string `json:"status"`
		CreatedAt   string `json:"created_at"`
		Tags        []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"tags"`
	}
	if err := json.Unmarshal(raw, &value); err != nil || value.ID != id {
		return nil, fmt.Errorf("network identity mismatch")
	}
	at := time.Now().UTC()
	out := &model.Asset{
		AccountID: a.ID, Provider: "huawei", AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: id, ResourceType: kind, Name: value.Name, ObservedAt: at,
		MapperVersion: "huawei-vpc/v1",
		Components:    map[string]model.AssetComponent{"details": component(raw, api, huaweiAPIVersion, at)},
		Provenance:    map[string]model.FieldOrigin{},
		Network:       &model.AssetNetwork{Description: value.Description, CIDRBlock: value.CIDR, SourceCreatedTime: value.CreatedAt},
	}
	paths := map[string]string{"resource_id": "/id", "name": "/name", "network.cidr_block": "/cidr", "network.source_created_time": "/created_at", "tags": "/tags"}
	switch kind {
	case "vpc":
		out.VPCID = id
		paths["vpc_id"] = "/id"
	case "subnet":
		out.VPCID = value.VpcID
		out.SubnetID = id
		out.Zone = value.Zone
		paths["subnet_id"] = "/id"
		paths["vpc_id"] = "/vpc_id"
		paths["zone"] = "/availability_zone"
		if value.VpcID != "" {
			out.References = []model.AssetReference{reference(a, "vpc", value.VpcID, "belongs_to_vpc", "details", "/vpc_id")}
		}
	case "security_group":
		out.VPCID = value.VpcID
		paths["network.description"] = "/description"
		paths["vpc_id"] = "/vpc_id"
		if rules, ok := huaweiRules(raw); ok {
			out.Components["policies"] = component(rules, "VPC ShowSecurityGroup", huaweiAPIVersion, at)
		}
	}
	if sourceHas(raw, "/tags") {
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

func huaweiRules(raw json.RawMessage) (json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, false
	}
	rules, ok := fields["security_group_rules"]
	if !ok || len(rules) == 0 || string(rules) == "null" {
		return nil, false
	}
	return rules, true
}

// ValidHuaweiResource validates Huawei native UUIDs.
func ValidHuaweiResource(kind, id string) bool {
	if len(id) > 128 {
		return false
	}
	switch kind {
	case "ecs", "vpc", "subnet", "security_group":
		return huaweiID.MatchString(id)
	}
	return false
}

func init() {
	registerProvider(Provider{
		ID:                "huawei",
		Name:              "Huawei Cloud",
		HostType:          "ecs",
		APIVersion:        huaweiAPIVersion,
		HostAPI:           "ECS ShowServer",
		PolicyAPI:         "VPC ShowSecurityGroup",
		ResourceTypes:     []string{"ecs", "security_group", "vpc", "subnet"},
		MapperVersion:     huaweiMapperVersion,
		PoliciesInDetails: true,
		DocsURL:           "https://support.huaweicloud.com/api-ecs/ecs_02_0201.html",
		SyntheticHostID:   SyntheticHuaweiServerID,
		HostID: func(r model.Resource) (string, bool) {
			switch strings.ToLower(r.Type) {
			case "host", "server", "vm", "ecs":
			default:
				return "", false
			}
			if huaweiID.MatchString(r.ID) {
				return r.ID, true
			}
			return "", false
		},
		ValidateAccount: func(a model.Account) error {
			if a.Options == nil || a.Options["project_id"] == "" {
				return fmt.Errorf("Huawei project_id option is required")
			}
			return nil
		},
		Valid:              ValidHuaweiResource,
		QPS:                2,
		RequiresRegion:     true,
		ValidateCredential: requireAKSK,
		New: func(cred connector.Credential, a model.Account, limiter *connector.Limiter) (Client, error) {
			raw, err := HuaweiRaw(cred, a, 15*time.Second)
			if err != nil {
				return nil, err
			}
			return &huaweiClient{raw: raw, limiter: limiter}, nil
		},
		Synthetic: func(limiter *connector.Limiter) Client {
			return &huaweiClient{raw: SyntheticHuaweiRaw(), limiter: limiter}
		},
	})
}
