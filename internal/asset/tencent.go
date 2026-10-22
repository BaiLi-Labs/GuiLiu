// Package asset implements the first bounded control-plane asset adapter.
// It does not scan hosts, infer services, or run during ordinary reads.
package asset

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

const MapperVersion = "tencent-cvm/v2"
const tencentAPIVersion = "2017-03-12"
const MaxSecurityGroups = 5
const MaxNICs = 5

var instanceID = regexp.MustCompile(`^ins-[a-zA-Z0-9]+$`)
var groupID = regexp.MustCompile(`^sg-[a-zA-Z0-9]+$`)

// Call is injected by synthetic tests; production uses the SDK signer and raw
// response decoder, avoiding typed SDK projection of unknown vendor fields.
type Call func(context.Context, string, string, map[string]any) (json.RawMessage, error)

func TencentCall(cred connector.Credential, region string) Call {
	var c common.CredentialIface = common.NewCredential(cred.AccessKeyID, cred.AccessKeySecret)
	if cred.SessionToken != "" {
		c = common.NewTokenCredential(cred.AccessKeyID, cred.AccessKeySecret, cred.SessionToken)
	}
	clients := map[string]*common.Client{}
	for _, service := range []string{"cvm", "vpc"} {
		p := profile.NewClientProfile()
		p.HttpProfile.Endpoint = service + ".tencentcloudapi.com"
		p.HttpProfile.ReqTimeout = 10
		// No automatic retries: explicit refreshes have a fixed request budget.
		p.NetworkFailureMaxRetries = 0
		p.RateLimitExceededMaxRetries = 0
		clients[service] = common.NewCommonClient(c, region, p).WithHttpTransport(boundedTransport{http.DefaultTransport})
	}
	return func(ctx context.Context, service, action string, params map[string]any) (json.RawMessage, error) {
		client, ok := clients[service]
		if !ok {
			return nil, fmt.Errorf("unsupported asset service")
		}
		req := tchttp.NewCommonRequest(service, "2017-03-12", action)
		req.SetContext(ctx)
		if err := req.SetActionParameters(params); err != nil {
			return nil, err
		}
		resp := &rawResponse{}
		if err := client.Send(req, resp); err != nil {
			return nil, err
		}
		return resp.Response, nil
	}
}

type rawResponse struct {
	tchttp.BaseResponse
	Response json.RawMessage `json:"Response"`
}

const maxResponseBytes = 2 << 20

type boundedTransport struct{ base http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > maxResponseBytes {
		response.Body.Close()
		return nil, fmt.Errorf("asset response exceeds size limit")
	}
	response.Body = &boundedBody{ReadCloser: response.Body, remaining: maxResponseBytes}
	return response, nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
		return n, fmt.Errorf("asset response exceeds size limit")
	}
	return n, err
}

func sourceHas(raw json.RawMessage, path string) bool {
	for _, key := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return false
		}
		value, ok := object[key]
		if !ok || string(value) == "null" {
			return false
		}
		raw = value
	}
	return true
}

func component(raw json.RawMessage, api, apiVersion string, at time.Time) model.AssetComponent {
	return model.AssetComponent{Status: "available", SourceAPI: api, APIVersion: apiVersion, ObservedAt: &at, RawForm: "exact_bytes", Raw: append(json.RawMessage(nil), raw...), RawHash: fmt.Sprintf("%x", sha256.Sum256(raw))}
}

// ReadTencent requests exactly one instance, its ENIs and at most five
// referenced policy sets. Raw policies retain templates and object references
// without expansion.
func ReadTencent(ctx context.Context, a model.Account, id string, call Call, limiter *connector.Limiter) (*model.Asset, error) {
	return readTencent(ctx, a, id, call, limiter, nil)
}

func readTencent(ctx context.Context, a model.Account, id string, call Call, limiter *connector.Limiter, nics *nicCache) (*model.Asset, error) {
	if !instanceID.MatchString(id) {
		return nil, fmt.Errorf("invalid CVM instance ID")
	}
	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := call(ctx, "cvm", "DescribeInstances", map[string]any{"InstanceIds": []string{id}, "Limit": 1})
	if err != nil {
		return nil, err
	}
	var page struct {
		InstanceSet []json.RawMessage
		TotalCount  int
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		return nil, fmt.Errorf("invalid instance response")
	}
	if len(page.InstanceSet) == 0 {
		return nil, ErrNotVisible
	}
	if len(page.InstanceSet) != 1 {
		return nil, fmt.Errorf("unexpected instance response")
	}
	var i struct {
		InstanceId, InstanceName, OsName, InstanceState, InstanceType string
		PublicIpAddresses, PrivateIpAddresses, SecurityGroupIds       []string
		Placement                                                     struct{ Zone string }
		VirtualPrivateCloud                                           struct{ VpcId, SubnetId string }
		Tags                                                          []struct{ TagKey, TagValue string }
	}
	if err := json.Unmarshal(page.InstanceSet[0], &i); err != nil || i.InstanceId != id {
		return nil, fmt.Errorf("instance identity mismatch")
	}
	at := time.Now().UTC()
	out := &model.Asset{AccountID: a.ID, Provider: "tencent", AccountUID: a.AccountUID, Region: a.Region, ResourceID: i.InstanceId, ResourceType: "cvm", Name: i.InstanceName, OS: i.OsName, State: i.InstanceState, InstanceType: i.InstanceType, Zone: i.Placement.Zone, PublicIPs: i.PublicIpAddresses, PrivateIPs: i.PrivateIpAddresses, VPCID: i.VirtualPrivateCloud.VpcId, SubnetID: i.VirtualPrivateCloud.SubnetId, SecurityGroupIDs: i.SecurityGroupIds, MapperVersion: MapperVersion, ObservedAt: at, Components: map[string]model.AssetComponent{"instance": component(page.InstanceSet[0], "CVM DescribeInstances", tencentAPIVersion, at)}, Provenance: map[string]model.FieldOrigin{}}
	for _, t := range i.Tags {
		out.Tags = append(out.Tags, model.AssetTag{Key: t.TagKey, Value: t.TagValue})
	}
	if sourceHas(page.InstanceSet[0], "/Tags") && out.Tags == nil {
		out.Tags = []model.AssetTag{}
	}
	if i.VirtualPrivateCloud.VpcId != "" {
		out.References = append(out.References, reference(a, "vpc", i.VirtualPrivateCloud.VpcId, "belongs_to_vpc", "instance", "/VirtualPrivateCloud/VpcId"))
	}
	if i.VirtualPrivateCloud.SubnetId != "" {
		out.References = append(out.References, reference(a, "subnet", i.VirtualPrivateCloud.SubnetId, "in_subnet", "instance", "/VirtualPrivateCloud/SubnetId"))
	}
	for n, id := range i.SecurityGroupIds {
		out.References = append(out.References, reference(a, "security_group", id, "attached_security_group", "instance", fmt.Sprintf("/SecurityGroupIds/%d", n)))
	}
	for field, path := range map[string]string{"resource_id": "/InstanceId", "name": "/InstanceName", "os": "/OsName", "state": "/InstanceState", "instance_type": "/InstanceType", "zone": "/Placement/Zone", "public_ips": "/PublicIpAddresses", "private_ips": "/PrivateIpAddresses", "vpc_id": "/VirtualPrivateCloud/VpcId", "subnet_id": "/VirtualPrivateCloud/SubnetId", "security_group_ids": "/SecurityGroupIds", "tags": "/Tags"} {
		// Paths are relative to the exact instance component, not the list envelope.
		if sourceHas(page.InstanceSet[0], path) {
			out.Provenance[field] = model.FieldOrigin{Source: "component:instance", Paths: []string{path}, Transform: "source_field_projection"}
		}
	}
	for field, path := range map[string]string{"account_uid": "/account_uid", "region": "/region"} {
		out.Provenance[field] = model.FieldOrigin{Source: "configuration", Paths: []string{path}, Transform: "explicit_connection_scope"}
	}
	out.Components["software"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["listening_ports"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["reachability"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	for n, g := range i.SecurityGroupIds {
		key := "security_group:" + g
		c := model.AssetComponent{Status: "not_collected", Reason: "request_budget_exceeded", SourceAPI: "VPC DescribeSecurityGroupPolicies", APIVersion: "2017-03-12"}
		if n >= MaxSecurityGroups || !groupID.MatchString(g) {
			out.Components[key] = c
			continue
		}
		if err := limiter.Wait(ctx); err != nil {
			c.Status = "failed"
			c.Reason = "timeout"
			out.Components[key] = c
			continue
		}
		if err := ctx.Err(); err != nil {
			c.Status = "failed"
			c.Reason = "timeout"
			out.Components[key] = c
			continue
		}
		policy, err := call(ctx, "vpc", "DescribeSecurityGroupPolicies", map[string]any{"SecurityGroupId": g})
		if err != nil {
			c.Status = "failed"
			c.Reason = errorCode(err, "tencent")
			out.Components[key] = c
			continue
		}
		var envelope struct{ SecurityGroupPolicySet json.RawMessage }
		if json.Unmarshal(policy, &envelope) != nil || len(envelope.SecurityGroupPolicySet) == 0 || string(envelope.SecurityGroupPolicySet) == "null" {
			c.Status = "failed"
			c.Reason = "invalid_source_response"
			out.Components[key] = c
			continue
		}
		out.Components[key] = component(envelope.SecurityGroupPolicySet, c.SourceAPI, tencentAPIVersion, time.Now().UTC())
	}
	if err := limiter.Wait(ctx); err != nil {
		out.Components["network_interfaces"] = model.AssetComponent{Status: "failed", Reason: "timeout", SourceAPI: "VPC DescribeNetworkInterfaces", APIVersion: tencentAPIVersion}
		return out, nil
	}
	nicPayload, nicErr := call(ctx, "vpc", "DescribeNetworkInterfaces", map[string]any{
		"Filters": []map[string]any{{"Name": "attachment.instance-id", "Values": []string{id}}},
		"Limit":   MaxNICs,
	})
	if nicErr != nil {
		out.Components["network_interfaces"] = model.AssetComponent{Status: "failed", Reason: errorCode(nicErr, "tencent"), SourceAPI: "VPC DescribeNetworkInterfaces", APIVersion: tencentAPIVersion}
		return out, nil
	}
	var nicEnvelope struct {
		NetworkInterfaceSet json.RawMessage
		TotalCount          int
	}
	if json.Unmarshal(nicPayload, &nicEnvelope) != nil || len(nicEnvelope.NetworkInterfaceSet) == 0 || string(nicEnvelope.NetworkInterfaceSet) == "null" {
		out.Components["network_interfaces"] = model.AssetComponent{Status: "failed", Reason: "invalid_source_response", SourceAPI: "VPC DescribeNetworkInterfaces", APIVersion: tencentAPIVersion}
		return out, nil
	}
	var nicItems []json.RawMessage
	if json.Unmarshal(nicEnvelope.NetworkInterfaceSet, &nicItems) != nil {
		out.Components["network_interfaces"] = model.AssetComponent{Status: "failed", Reason: "invalid_source_response", SourceAPI: "VPC DescribeNetworkInterfaces", APIVersion: tencentAPIVersion}
		return out, nil
	}
	nicComponent := component(nicPayload, "VPC DescribeNetworkInterfaces", tencentAPIVersion, time.Now().UTC())
	if nicEnvelope.TotalCount > len(nicItems) {
		nicComponent.Status = "partial"
		nicComponent.Reason = "request_budget_exceeded"
	}
	out.Components["network_interfaces"] = nicComponent
	for n, item := range nicItems {
		var identity struct{ NetworkInterfaceId string }
		if json.Unmarshal(item, &identity) != nil || !eniID.MatchString(identity.NetworkInterfaceId) {
			continue
		}
		if nics != nil {
			nics.put(identity.NetworkInterfaceId, item)
		}
		out.References = append(out.References, reference(a, "nic", identity.NetworkInterfaceId, "attached_network_interface", "network_interfaces", fmt.Sprintf("/NetworkInterfaceSet/%d/NetworkInterfaceId", n)))
	}
	return out, nil
}

// nicCache shares ENI payloads between a host refresh and the following
// reference enrichment so one host read never fetches the same ENI twice.
type nicCache struct {
	mu    sync.Mutex
	items map[string]json.RawMessage
}

func (c *nicCache) put(id string, raw json.RawMessage) {
	if c == nil || id == "" || len(raw) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.items == nil {
		c.items = map[string]json.RawMessage{}
	}
	c.items[id] = append(json.RawMessage(nil), raw...)
}

func (c *nicCache) get(id string) (json.RawMessage, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, ok := c.items[id]
	return raw, ok
}

// tencentClient adapts the generic signed Call into the asset Client contract.
type tencentClient struct {
	call     Call
	limiter  *connector.Limiter
	nicCache *nicCache
}

func (c *tencentClient) ReadInstance(ctx context.Context, a model.Account, id string) (*model.Asset, error) {
	return readTencent(ctx, a, id, c.call, c.limiter, c.nicCache)
}

func (c *tencentClient) ReadNetwork(ctx context.Context, a model.Account, kind string, ids []string) (map[string]*model.Asset, error) {
	if kind == "nic" {
		return readTencentNICBatch(ctx, a, ids, c.call, c.limiter, c.nicCache)
	}
	return readNetworkBatch(ctx, a, kind, ids, c.call, c.limiter)
}

// readTencentNICBatch requests exact ENI IDs, reusing payloads already read
// during the host refresh.
func readTencentNICBatch(ctx context.Context, a model.Account, ids []string, call Call, limiter *connector.Limiter, cache *nicCache) (map[string]*model.Asset, error) {
	if len(ids) == 0 || len(ids) > MaxNICs {
		return nil, fmt.Errorf("invalid network interface query scope")
	}
	wanted := map[string]bool{}
	raws := map[string]json.RawMessage{}
	missing := []string{}
	for _, id := range ids {
		if !eniID.MatchString(id) || wanted[id] {
			return nil, fmt.Errorf("invalid or repeated network interface ID")
		}
		wanted[id] = true
		if raw, ok := cache.get(id); ok {
			raws[id] = raw
		} else {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		if err := limiter.Wait(ctx); err != nil {
			return nil, err
		}
		payload, err := call(ctx, "vpc", "DescribeNetworkInterfaces", map[string]any{
			"NetworkInterfaceIds": missing,
			"Limit":               len(missing),
		})
		if err != nil {
			return nil, err
		}
		var envelope struct{ NetworkInterfaceSet json.RawMessage }
		if json.Unmarshal(payload, &envelope) != nil || len(envelope.NetworkInterfaceSet) == 0 || string(envelope.NetworkInterfaceSet) == "null" {
			return nil, fmt.Errorf("invalid network interface response")
		}
		var items []json.RawMessage
		if json.Unmarshal(envelope.NetworkInterfaceSet, &items) != nil {
			return nil, fmt.Errorf("invalid network interface response")
		}
		for _, item := range items {
			var identity struct{ NetworkInterfaceId string }
			if json.Unmarshal(item, &identity) != nil || !wanted[identity.NetworkInterfaceId] {
				return nil, fmt.Errorf("network interface identity mismatch")
			}
			if raws[identity.NetworkInterfaceId] != nil {
				return nil, fmt.Errorf("duplicated network interface record")
			}
			raws[identity.NetworkInterfaceId] = item
			cache.put(identity.NetworkInterfaceId, item)
		}
	}
	out := map[string]*model.Asset{}
	for _, id := range ids {
		raw, ok := raws[id]
		if !ok {
			continue
		}
		value, err := normalizeTencentNIC(a, id, raw)
		if err != nil {
			return nil, err
		}
		out[id] = value
	}
	return out, nil
}

func normalizeTencentNIC(a model.Account, id string, raw json.RawMessage) (*model.Asset, error) {
	var value struct {
		NetworkInterfaceId, NetworkInterfaceName, VpcId, SubnetId string
		MacAddress, State, CreatedTime                            string
		GroupSet                                                  []string
		Primary                                                   *bool
		PrivateIpAddressSet                                       []struct {
			PrivateIpAddress string
			Primary          bool
		}
		Attachment struct{ InstanceId string }
		TagSet     []struct{ Key, Value string }
	}
	if json.Unmarshal(raw, &value) != nil || value.NetworkInterfaceId != id {
		return nil, fmt.Errorf("network interface identity mismatch")
	}
	at := time.Now().UTC()
	out := &model.Asset{
		AccountID: a.ID, Provider: a.Provider, AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: id, ResourceType: "nic", Name: value.NetworkInterfaceName,
		VPCID: value.VpcId, SubnetID: value.SubnetId, SecurityGroupIDs: value.GroupSet,
		State: value.State, MapperVersion: "tencent-eni/v1", ObservedAt: at,
		Components: map[string]model.AssetComponent{"details": component(raw, "VPC DescribeNetworkInterfaces", tencentAPIVersion, at)},
		Provenance: map[string]model.FieldOrigin{},
		Network:    &model.AssetNetwork{MACAddress: value.MacAddress, Primary: value.Primary, SourceCreatedTime: value.CreatedTime},
	}
	for _, address := range value.PrivateIpAddressSet {
		if address.PrivateIpAddress != "" {
			out.PrivateIPs = append(out.PrivateIPs, address.PrivateIpAddress)
		}
	}
	if sourceHas(raw, "/TagSet") {
		out.Tags = []model.AssetTag{}
		for _, tag := range value.TagSet {
			out.Tags = append(out.Tags, model.AssetTag{Key: tag.Key, Value: tag.Value})
		}
	}
	if value.VpcId != "" {
		out.References = append(out.References, reference(a, "vpc", value.VpcId, "belongs_to_vpc", "details", "/VpcId"))
	}
	if value.SubnetId != "" {
		out.References = append(out.References, reference(a, "subnet", value.SubnetId, "in_subnet", "details", "/SubnetId"))
	}
	for n, group := range value.GroupSet {
		if groupID.MatchString(group) {
			out.References = append(out.References, reference(a, "security_group", group, "attached_security_group", "details", fmt.Sprintf("/GroupSet/%d", n)))
		}
	}
	if instanceID.MatchString(value.Attachment.InstanceId) {
		out.References = append(out.References, reference(a, "cvm", value.Attachment.InstanceId, "attached_to_host", "details", "/Attachment/InstanceId"))
	}
	for field, path := range map[string]string{
		"resource_id": "/NetworkInterfaceId", "name": "/NetworkInterfaceName", "state": "/State",
		"vpc_id": "/VpcId", "subnet_id": "/SubnetId", "security_group_ids": "/GroupSet",
		"private_ips": "/PrivateIpAddressSet", "tags": "/TagSet",
		"network.mac_address": "/MacAddress", "network.primary": "/Primary",
		"network.source_created_time": "/CreatedTime",
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

func (c *tencentClient) ReadPolicies(ctx context.Context, a model.Account, id string) (model.AssetComponent, error) {
	raw, err := c.call(ctx, "vpc", "DescribeSecurityGroupPolicies", map[string]any{"SecurityGroupId": id})
	return policyComponent(raw, err, "VPC DescribeSecurityGroupPolicies", tencentAPIVersion, "tencent"), nil
}

func init() {
	registerProvider(Provider{
		ID:              "tencent",
		Name:            "Tencent Cloud",
		HostType:        "cvm",
		APIVersion:      tencentAPIVersion,
		HostAPI:         "CVM DescribeInstances",
		PolicyAPI:       "VPC DescribeSecurityGroupPolicies",
		ResourceTypes:   []string{"cvm", "security_group", "vpc", "subnet", "nic"},
		MapperVersion:   MapperVersion,
		DocsURL:         "https://cloud.tencent.com/document/api/213/15728",
		SyntheticHostID: "ins-mock0001",
		AlertHostType:   "host",
		HostID: func(r model.Resource) (string, bool) {
			if r.Type == "host" && instanceID.MatchString(r.ID) {
				return r.ID, true
			}
			return "", false
		},
		Valid:              ValidResource,
		QPS:                2,
		RequiresRegion:     true,
		ValidateCredential: requireAKSK,
		New: func(cred connector.Credential, a model.Account, limiter *connector.Limiter) (Client, error) {
			return &tencentClient{call: TencentCall(cred, a.Region), limiter: limiter, nicCache: &nicCache{}}, nil
		},
		Synthetic: func(limiter *connector.Limiter) Client {
			return &tencentClient{call: SyntheticCall(), limiter: limiter, nicCache: &nicCache{}}
		},
	})
}
