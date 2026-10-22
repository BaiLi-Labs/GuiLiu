package mcp

import (
	"context"
	"fmt"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
)

func (s *Server) registerAssetTools() {
	s.register(Tool{Name: "get_asset_by_reference", Description: "Follow an explicit scoped resource reference to a saved host, network interface, security group, VPC or subnet. Copy the identity fields from references. Reports missing/stale data and recent refresh failures. Does not call cloud APIs.", InputSchema: obj(map[string]any{"provider": strProp("Provider"), "account_id": strProp("Optional source connection ID, for refresh status"), "account_uid": strProp("Native cloud account UID"), "region": strProp("Cloud region (may be empty only for providers without a region scope)"), "resource_type": strProp("Provider host type (cvm/ecs/ec2/gce/vm), nic, security_group, vpc or subnet"), "resource_id": strProp("Exact native resource ID")}, "provider", "account_uid", "region", "resource_type", "resource_id"), Handler: s.toolAssetLookup})
	s.register(Tool{Name: "list_assets", Description: "Read locally saved control-plane assets. No cloud API calls, no complete-inventory guarantee. Only explicit filters are supported; page with next_cursor as after_id.", InputSchema: obj(map[string]any{"provider": strProp("Provider"), "account_id": strProp("Connection ID"), "account_uid": strProp("Native cloud account UID"), "region": strProp("Region"), "resource_id": strProp("Exact native resource ID"), "resource_type": strProp("Provider host type, nic, security_group, vpc or subnet"), "after_id": strProp("Previous next_cursor"), "limit": intProp("Maximum assets", query.AssetDefaultLimit, 1, query.AssetMaxLimit)}), Handler: s.toolListAssets})
	s.register(Tool{Name: "get_asset", Description: "Read an independent local asset observation, optionally at an exact asset revision. This is not the asset state at a Finding's event time.", InputSchema: obj(map[string]any{"asset_id": strProp("Required GuiLiu asset_id returned by list_assets, get_asset_by_reference or asset context; not the native resource_id"), "revision": map[string]any{"type": "integer", "minimum": 1, "description": "Optional positive exact asset revision; omit for the latest saved asset observation. Invalid revisions fail."}}, "asset_id"), Handler: s.toolGetAsset})
	s.register(Tool{Name: "get_alert_asset_context", Description: "Read current local host context for an explicit host reference with matching provider, account UID, region and native resource ID. Missing or stale data is explicit. Never refreshes cloud data.", InputSchema: obj(map[string]any{"alert_id": strProp("Finding ID"), "revision": map[string]any{"type": "integer", "minimum": 1}, "snapshot_sequence": map[string]any{"type": "integer", "minimum": 0}}, "alert_id"), Handler: s.toolAssetContext})
	s.register(Tool{Name: "list_asset_findings", Description: "Query all stored history of Findings with the same scoped native host identity; no implicit 7d window. IP and name are not identity links. Reuse snapshot_sequence and next_cursor for paging.", InputSchema: obj(map[string]any{"asset_id": strProp("Required GuiLiu asset_id returned by list_assets, get_asset_by_reference or asset context; not the native resource_id"), "after_id": strProp("Previous next_cursor"), "limit": intProp("Maximum Findings", query.AssetDefaultLimit, 1, query.AssetMaxLimit), "snapshot_sequence": map[string]any{"type": "integer", "minimum": 0}}, "asset_id"), Handler: s.toolAssetFindings})
	s.register(Tool{Name: "get_asset_component", Description: "Read exact source JSON text and hash from a saved asset revision. Security group policies are configuration, not observed listening or reachable ports.", InputSchema: obj(map[string]any{"asset_id": strProp("Required GuiLiu asset_id returned by list_assets, get_asset_by_reference or asset context; not the native resource_id"), "revision": map[string]any{"type": "integer", "minimum": 1, "maximum": 2147483647, "description": "Required exact asset revision copied from get_asset; no default. Invalid or missing revisions fail."}, "component": strProp("Component key returned by get_asset")}, "asset_id", "revision", "component"), Handler: s.toolAssetComponent})
}
func strictAssetArgs(args map[string]any, keys ...string) error {
	for key := range args {
		if key != "limit" && key != "revision" && key != "snapshot_sequence" {
			if _, ok := args[key].(string); !ok {
				return fmt.Errorf("%s must be a string", key)
			}
		}
		found := false
		for _, k := range keys {
			if k == key {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("unsupported argument: %s", key)
		}
	}
	return nil
}
func assetArgInt(args map[string]any, key string, def, min, max int64) (int64, error) {
	raw, ok := args[key]
	if !ok {
		return def, nil
	}
	n, e := parseInteger(raw)
	if e != nil || n < min || n > max {
		return 0, fmt.Errorf("invalid %s", key)
	}
	return n, nil
}
func assetSequence(args map[string]any) (*int64, error) {
	if _, ok := args["snapshot_sequence"]; !ok {
		return nil, nil
	}
	n, e := assetArgInt(args, "snapshot_sequence", 0, 0, 9223372036854775807)
	return &n, e
}
func requiredAssetString(args map[string]any, key string) (string, error) {
	v := argString(args, key)
	if v == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return v, nil
}

func (s *Server) toolListAssets(ctx context.Context, args map[string]any) (any, error) {
	if e := strictAssetArgs(args, "provider", "account_id", "account_uid", "region", "resource_id", "resource_type", "after_id", "limit"); e != nil {
		return nil, e
	}
	n, e := assetArgInt(args, "limit", 20, 1, 100)
	if e != nil {
		return nil, e
	}
	return query.AssetList(ctx, s.store, model.AssetFilter{Provider: argString(args, "provider"), AccountID: argString(args, "account_id"), AccountUID: argString(args, "account_uid"), Region: argString(args, "region"), ResourceID: argString(args, "resource_id"), ResourceType: argString(args, "resource_type"), AfterID: argString(args, "after_id"), Limit: int(n)})
}

func (s *Server) toolAssetLookup(ctx context.Context, args map[string]any) (any, error) {
	if e := strictAssetArgs(args, "provider", "account_id", "account_uid", "region", "resource_type", "resource_id"); e != nil {
		return nil, e
	}
	return query.LookupAsset(ctx, s.store, model.AssetFilter{Provider: argString(args, "provider"), AccountID: argString(args, "account_id"), AccountUID: argString(args, "account_uid"), Region: argString(args, "region"), ResourceType: argString(args, "resource_type"), ResourceID: argString(args, "resource_id")})
}
func (s *Server) toolGetAsset(ctx context.Context, args map[string]any) (any, error) {
	if e := strictAssetArgs(args, "asset_id", "revision"); e != nil {
		return nil, e
	}
	id, e := requiredAssetString(args, "asset_id")
	if e != nil {
		return nil, e
	}
	n, e := assetArgInt(args, "revision", 0, 1, 2147483647)
	if e != nil {
		return nil, e
	}
	a, e := s.store.GetAsset(ctx, id, int(n))
	if e != nil {
		return nil, e
	}
	return query.AssetView(*a), nil
}
func (s *Server) toolAssetContext(ctx context.Context, args map[string]any) (any, error) {
	a, e := s.readFindingArgs(ctx, args)
	if e != nil {
		return nil, e
	}
	return query.ContextForAlert(ctx, s.store, a)
}
func (s *Server) toolAssetFindings(ctx context.Context, args map[string]any) (any, error) {
	if e := strictAssetArgs(args, "asset_id", "after_id", "limit", "snapshot_sequence"); e != nil {
		return nil, e
	}
	id, e := requiredAssetString(args, "asset_id")
	if e != nil {
		return nil, e
	}
	n, e := assetArgInt(args, "limit", 20, 1, 100)
	if e != nil {
		return nil, e
	}
	seq, e := assetSequence(args)
	if e != nil {
		return nil, e
	}
	return query.AssetFindings(ctx, s.store, id, argString(args, "after_id"), int(n), seq)
}
func (s *Server) toolAssetComponent(ctx context.Context, args map[string]any) (any, error) {
	if e := strictAssetArgs(args, "asset_id", "revision", "component"); e != nil {
		return nil, e
	}
	id, e := requiredAssetString(args, "asset_id")
	if e != nil {
		return nil, e
	}
	key, e := requiredAssetString(args, "component")
	if e != nil {
		return nil, e
	}
	n, e := assetArgInt(args, "revision", 0, 1, 2147483647)
	if e != nil || n == 0 {
		return nil, fmt.Errorf("positive revision is required")
	}
	a, e := s.store.GetAsset(ctx, id, int(n))
	if e != nil {
		return nil, e
	}
	c, ok := a.Components[key]
	if !ok || len(c.Raw) == 0 {
		return nil, fmt.Errorf("component evidence not available")
	}
	return map[string]any{"asset_id": id, "revision": n, "component": key, "raw_text": string(c.Raw), "raw_hash": c.RawHash, "source_api": c.SourceAPI, "observed_at": c.ObservedAt}, nil
}

func (s *Server) readFindingArgs(ctx context.Context, args map[string]any) (*model.AlertRecord, error) {
	if e := strictAssetArgs(args, "alert_id", "revision", "snapshot_sequence"); e != nil {
		return nil, e
	}
	id, e := requiredAssetString(args, "alert_id")
	if e != nil {
		return nil, e
	}
	n, e := assetArgInt(args, "revision", 0, 1, 2147483647)
	if e != nil {
		return nil, e
	}
	seq, e := assetSequence(args)
	if e != nil {
		return nil, e
	}
	return query.ReadFinding(ctx, s.store, id, int(n), seq)
}
