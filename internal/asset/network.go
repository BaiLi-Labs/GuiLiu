package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const MaxRefreshRequests = 9

var vpcID = regexp.MustCompile(`^vpc-[a-zA-Z0-9]+$`)
var subnetID = regexp.MustCompile(`^subnet-[a-zA-Z0-9]+$`)

func ValidResource(kind, id string) bool {
	if len(id) > 128 {
		return false
	}
	switch kind {
	case "cvm":
		return instanceID.MatchString(id)
	case "vpc":
		return vpcID.MatchString(id)
	case "subnet":
		return subnetID.MatchString(id)
	case "security_group":
		return groupID.MatchString(id)
	}
	return false
}
func reference(a model.Account, kind, id, relation, component, path string) model.AssetReference {
	return model.AssetReference{Provider: a.Provider, AccountID: a.ID, AccountUID: a.AccountUID, Region: a.Region, ResourceType: kind, ResourceID: id, Relation: relation, SourceComponent: component, SourcePath: path}
}
func networkAPI(kind string) (action, list, idField string) {
	switch kind {
	case "vpc":
		return "DescribeVpcs", "VpcSet", "VpcId"
	case "subnet":
		return "DescribeSubnets", "SubnetSet", "SubnetId"
	case "security_group":
		return "DescribeSecurityGroups", "SecurityGroupSet", "SecurityGroupId"
	}
	return "", "", ""
}

// readNetworkBatch only requests exact IDs, never scans a VPC or expands
// routes, peers, templates, or nested security group references.
func readNetworkBatch(ctx context.Context, a model.Account, kind string, ids []string, call Call, limiter *connector.Limiter) (map[string]*model.Asset, error) {
	action, list, idField := networkAPI(kind)
	if action == "" || len(ids) == 0 || len(ids) > MaxSecurityGroups {
		return nil, fmt.Errorf("invalid network query scope")
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		if !ValidResource(kind, id) || wanted[id] {
			return nil, fmt.Errorf("invalid or repeated network ID")
		}
		wanted[id] = true
	}
	if err := limiter.Wait(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := call(ctx, "vpc", action, map[string]any{idField + "s": ids, "Limit": strconv.Itoa(len(ids))})
	if err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, fmt.Errorf("invalid network response")
	}
	var items []json.RawMessage
	if data, ok := envelope[list]; !ok || string(data) == "null" || json.Unmarshal(data, &items) != nil || items == nil {
		return nil, fmt.Errorf("missing network result set")
	}
	out := map[string]*model.Asset{}
	for _, item := range items {
		var fields map[string]json.RawMessage
		if json.Unmarshal(item, &fields) != nil {
			return nil, fmt.Errorf("invalid network record")
		}
		var id string
		if json.Unmarshal(fields[idField], &id) != nil || !wanted[id] || out[id] != nil {
			return nil, fmt.Errorf("network identity mismatch")
		}
		value, err := normalizeNetwork(a, kind, id, action, item)
		if err != nil {
			return nil, err
		}
		out[id] = value
	}
	return out, nil
}

func normalizeNetwork(a model.Account, kind, id, action string, raw json.RawMessage) (*model.Asset, error) {
	var value struct {
		VpcId, SubnetId, SecurityGroupId, VpcName, SubnetName, SecurityGroupName, SecurityGroupDesc string
		CidrBlock, Ipv6CidrBlock, Zone, CreatedTime                                                 string
		IsDefault                                                                                   *bool
		TagSet                                                                                      []struct{ Key, Value string }
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("invalid network fields")
	}
	at := time.Now().UTC()
	out := &model.Asset{AccountID: a.ID, Provider: a.Provider, AccountUID: a.AccountUID, Region: a.Region, ResourceID: id, ResourceType: kind, ObservedAt: at, MapperVersion: "tencent-vpc/v1", Components: map[string]model.AssetComponent{"details": component(raw, "VPC "+action, tencentAPIVersion, at)}, Provenance: map[string]model.FieldOrigin{}, Network: &model.AssetNetwork{Description: value.SecurityGroupDesc, CIDRBlock: value.CidrBlock, IPv6CIDRBlock: value.Ipv6CidrBlock, IsDefault: value.IsDefault, SourceCreatedTime: value.CreatedTime}}
	paths := map[string]string{"network.cidr_block": "/CidrBlock", "network.ipv6_cidr_block": "/Ipv6CidrBlock", "network.is_default": "/IsDefault", "network.source_created_time": "/CreatedTime", "tags": "/TagSet"}
	switch kind {
	case "vpc":
		out.Name = value.VpcName
		out.VPCID = id
		paths["resource_id"] = "/VpcId"
		paths["vpc_id"] = "/VpcId"
		paths["name"] = "/VpcName"
	case "subnet":
		out.Name = value.SubnetName
		out.VPCID = value.VpcId
		out.SubnetID = id
		out.Zone = value.Zone
		paths["resource_id"] = "/SubnetId"
		paths["subnet_id"] = "/SubnetId"
		paths["name"] = "/SubnetName"
		paths["zone"] = "/Zone"
		paths["vpc_id"] = "/VpcId"
		if value.VpcId != "" {
			out.References = []model.AssetReference{reference(a, "vpc", value.VpcId, "belongs_to_vpc", "details", "/VpcId")}
		}
	case "security_group":
		out.Name = value.SecurityGroupName
		paths["resource_id"] = "/SecurityGroupId"
		paths["name"] = "/SecurityGroupName"
		paths["network.description"] = "/SecurityGroupDesc"
	}
	if sourceHas(raw, "/TagSet") {
		out.Tags = []model.AssetTag{}
		for _, tag := range value.TagSet {
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

func readNetwork(ctx context.Context, a model.Account, kind, id string, call Call, limiter *connector.Limiter) (*model.Asset, error) {
	items, err := readNetworkBatch(ctx, a, kind, []string{id}, call, limiter)
	if err != nil {
		return nil, err
	}
	out := items[id]
	if out == nil {
		return nil, ErrNotVisible
	}
	if kind == "security_group" {
		c := model.AssetComponent{Status: "failed", Reason: "timeout", SourceAPI: "VPC DescribeSecurityGroupPolicies", APIVersion: tencentAPIVersion}
		if err := limiter.Wait(ctx); err == nil && ctx.Err() == nil {
			raw, callErr := call(ctx, "vpc", "DescribeSecurityGroupPolicies", map[string]any{"SecurityGroupId": id})
			c = policyComponent(raw, callErr, c.SourceAPI, c.APIVersion, a.Provider)
		}
		out.Components["policies"] = c
	}
	return out, nil
}

// policyComponent turns one security-group policy response into a component.
// A source failure keeps only its classified reason; payloads never leak.
func policyComponent(raw json.RawMessage, err error, api, apiVersion, provider string) model.AssetComponent {
	c := model.AssetComponent{Status: "failed", SourceAPI: api, APIVersion: apiVersion}
	if err != nil {
		c.Reason = errorCode(err, provider)
		return c
	}
	var response struct{ SecurityGroupPolicySet json.RawMessage }
	if json.Unmarshal(raw, &response) != nil || len(response.SecurityGroupPolicySet) == 0 || string(response.SecurityGroupPolicySet) == "null" {
		c.Reason = "invalid_source_response"
		return c
	}
	return component(response.SecurityGroupPolicySet, api, apiVersion, time.Now().UTC())
}
