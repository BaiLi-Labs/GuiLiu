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
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tchttp "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/http"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
)

const MapperVersion = "tencent-cvm/v2"
const MaxSecurityGroups = 5

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

func component(raw json.RawMessage, api string, at time.Time) model.AssetComponent {
	return model.AssetComponent{Status: "available", SourceAPI: api, APIVersion: "2017-03-12", ObservedAt: &at, Raw: append(json.RawMessage(nil), raw...), RawHash: fmt.Sprintf("%x", sha256.Sum256(raw))}
}

// ReadTencent requests exactly one instance and at most five referenced policy
// sets. Raw policies retain templates and object references without expansion.
func ReadTencent(ctx context.Context, a model.Account, id string, call Call, limiter *connector.Limiter) (*model.Asset, error) {
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
	out := &model.Asset{AccountID: a.ID, Provider: "tencent", AccountUID: a.AccountUID, Region: a.Region, ResourceID: i.InstanceId, ResourceType: "cvm", Name: i.InstanceName, OS: i.OsName, State: i.InstanceState, InstanceType: i.InstanceType, Zone: i.Placement.Zone, PublicIPs: i.PublicIpAddresses, PrivateIPs: i.PrivateIpAddresses, VPCID: i.VirtualPrivateCloud.VpcId, SubnetID: i.VirtualPrivateCloud.SubnetId, SecurityGroupIDs: i.SecurityGroupIds, MapperVersion: MapperVersion, ObservedAt: at, Components: map[string]model.AssetComponent{"instance": component(page.InstanceSet[0], "CVM DescribeInstances", at)}, Provenance: map[string]model.FieldOrigin{}}
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
			c.Reason = errorCode(err)
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
		out.Components[key] = component(envelope.SecurityGroupPolicySet, c.SourceAPI, time.Now().UTC())
	}
	return out, nil
}
