package query

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/asset"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

var ErrInvalidFindingSelection = errors.New("invalid Finding selection")

func ReadFinding(ctx context.Context, st store.Store, id string, revision int, seq *int64) (*model.AlertRecord, error) {
	if revision > 0 && seq != nil {
		return nil, fmt.Errorf("%w: revision and snapshot_sequence cannot be combined", ErrInvalidFindingSelection)
	}
	if revision > 0 {
		return st.GetAlertRevision(ctx, id, revision)
	}
	if seq != nil {
		f := model.AlertFilter{SnapshotSequence: seq}
		if err := PinSnapshot(ctx, st, &f); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidFindingSelection, err)
		}
		return st.GetAlertAtSnapshot(ctx, id, *seq)
	}
	return st.GetAlert(ctx, id)
}

// AssetView omits large source payloads; immutable component URLs retain access
// to exact bytes. Used unchanged by REST, MCP and the Web's REST consumer.
func AssetView(a model.Asset) model.Asset {
	components := make(map[string]model.AssetComponent, len(a.Components))
	for key, c := range a.Components {
		c.Raw = nil
		if c.RawHash != "" {
			c.RawURL = fmt.Sprintf("/api/v1/assets/%s/revisions/%d/components/%s/raw", a.ID, a.Revision, url.PathEscape(key))
		}
		components[key] = c
	}
	a.Components = components
	a.References = append([]model.AssetReference(nil), a.References...)
	for i := range a.References {
		ref := &a.References[i]
		params := url.Values{"provider": {ref.Provider}, "account_id": {ref.AccountID}, "account_uid": {ref.AccountUID}, "region": {ref.Region}, "resource_type": {ref.ResourceType}, "resource_id": {ref.ResourceID}}
		ref.LookupURL = "/api/v1/assets/lookup?" + params.Encode()
	}
	return a
}

var ErrInvalidAssetReference = errors.New("invalid asset reference")

type AssetLookup struct {
	Status      string              `json:"status"`
	Asset       *model.Asset        `json:"asset,omitempty"`
	Refresh     *model.AssetRefresh `json:"refresh,omitempty"`
	Limitations []string            `json:"limitations"`
}

func LookupAsset(ctx context.Context, st store.Store, f model.AssetFilter) (*AssetLookup, error) {
	p, ok := asset.ProviderFor(f.Provider)
	if !ok || f.AccountUID == "" || f.ResourceID == "" || f.ResourceType == "" || (p.RequiresRegion && f.Region == "") {
		return nil, fmt.Errorf("%w: known provider, account_uid, required region scope, resource_type and resource_id are required", ErrInvalidAssetReference)
	}
	if !p.Supports(f.ResourceType) {
		return nil, fmt.Errorf("%w: unsupported resource_type for provider", ErrInvalidAssetReference)
	}
	out := &AssetLookup{Status: "not_collected", Limitations: []string{"local_observations_only", "not_event_time_state", "no_network_reachability_inference"}}
	if f.AccountID != "" {
		connection, err := st.GetAccount(ctx, f.AccountID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if connection != nil {
			if connection.Provider != f.Provider || connection.AccountUID != f.AccountUID || connection.Region != f.Region {
				return nil, fmt.Errorf("%w: connection does not match resource scope", ErrInvalidAssetReference)
			}
			attempt, err := st.GetAssetRefresh(ctx, f.AccountID, f.Region, f.ResourceID)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			out.Refresh = attempt
		}
	}
	f.AccountID = ""
	f.Limit = 2
	f.AfterID = ""
	items, err := st.ListAssets(ctx, f)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return out, nil
	}
	if len(items) != 1 {
		return nil, fmt.Errorf("%w: ambiguous resource identity", ErrInvalidAssetReference)
	}
	value := AssetView(items[0])
	out.Asset = &value
	out.Status = "available"
	if time.Since(value.LastObservedAt) > 5*time.Minute {
		out.Status = "stale"
	}
	return out, nil
}

type AssetContext struct {
	AlertID          string              `json:"alert_id"`
	AlertRevision    int                 `json:"alert_revision"`
	Status           string              `json:"status"`
	Reason           string              `json:"reason,omitempty"`
	Asset            *model.Asset        `json:"asset,omitempty"`
	RefreshAccountID string              `json:"refresh_account_id,omitempty"`
	ResourceID       string              `json:"resource_id,omitempty"`
	Refresh          *model.AssetRefresh `json:"refresh,omitempty"`
	MatchedOn        []string            `json:"matched_on,omitempty"`
	Limitations      []string            `json:"limitations"`
}

func ContextForAlert(ctx context.Context, st store.Store, a *model.AlertRecord) (*AssetContext, error) {
	out := &AssetContext{AlertID: a.ID, AlertRevision: a.Revision, Status: "unavailable", Limitations: []string{"current_asset_observation_not_event_time_state", "on_demand_inventory_not_complete_asset_coverage", "software_listeners_and_reachability_not_collected"}}
	p, ok := asset.ProviderFor(a.Provider)
	if !ok {
		out.Reason = "provider_not_supported"
		return out, nil
	}
	hostID, ok := asset.NativeHostID(p, a.Resource)
	if !ok {
		out.Reason = "no_explicit_primary_host_reference"
		return out, nil
	}
	out.ResourceID = hostID
	out.RefreshAccountID = a.AccountID
	if a.AccountUID == "" || (p.RequiresRegion && a.Region == "") {
		out.Reason = "resource_scope_incomplete"
		return out, nil
	}
	items, err := st.ListAssets(ctx, model.AssetFilter{Provider: a.Provider, AccountUID: a.AccountUID, Region: a.Region, ResourceID: hostID, Limit: 2})
	if err != nil {
		return nil, err
	}
	attempt, err := st.GetAssetRefresh(ctx, a.AccountID, a.Region, hostID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	out.Refresh = attempt
	if len(items) == 0 {
		out.Reason = "not_collected"
		return out, nil
	}
	if len(items) != 1 || items[0].ResourceType != p.HostType {
		out.Reason = "resource_identity_ambiguous"
		return out, nil
	}
	asset := AssetView(items[0])
	out.Asset = &asset
	out.Status = "available"
	if time.Since(asset.LastObservedAt) > 5*time.Minute {
		out.Status = "stale"
	}
	out.MatchedOn = []string{"provider", "account_uid", "region", "native_resource_id", "host_resource_type"}
	return out, nil
}

func AssetList(ctx context.Context, st store.Store, f model.AssetFilter) (map[string]any, error) {
	if f.Limit < 1 || f.Limit > 100 {
		return nil, fmt.Errorf("limit must be between 1 and 100")
	}
	limit := f.Limit
	f.Limit++
	items, err := st.ListAssets(ctx, f)
	if err != nil {
		return nil, err
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	views := make([]model.Asset, 0, len(items))
	next := ""
	for _, a := range items {
		views = append(views, AssetView(a))
	}
	if more {
		next = items[len(items)-1].ID
	}
	return map[string]any{"assets": views, "has_more": more, "next_cursor": next, "limit": limit, "limitations": []string{"live_local_inventory_without_snapshot", "only_explicitly_collected_resources"}}, nil
}

func AssetFindings(ctx context.Context, st store.Store, id, after string, limit int, seq *int64) (map[string]any, error) {
	if limit < 1 || limit > 100 {
		return nil, fmt.Errorf("limit must be between 1 and 100")
	}
	a, err := st.GetAsset(ctx, id, 0)
	if err != nil {
		return nil, err
	}
	p, ok := asset.ProviderFor(a.Provider)
	if !ok || a.ResourceType != p.HostType || a.AccountUID == "" || (p.RequiresRegion && a.Region == "") {
		return nil, fmt.Errorf("%w: related Findings require a complete native host identity", ErrInvalidAssetReference)
	}
	resourceIDs := []string{a.ResourceID}
	if p.AlertResourceIDs != nil {
		scope := model.Account{Provider: a.Provider, AccountUID: a.AccountUID, Region: a.Region}
		resourceIDs = append(resourceIDs, p.AlertResourceIDs(scope, a.ResourceID)...)
	}
	resourceIDs = uniqueStrings(resourceIDs)
	f := model.AlertFilter{Provider: a.Provider, AccountUID: a.AccountUID, Region: a.Region, ExactResourceIDs: resourceIDs, ResourceType: p.AlertHostType, Sort: "id", AfterID: after, Limit: limit + 1, SnapshotSequence: seq}
	if err := PinSnapshot(ctx, st, &f); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFindingSelection, err)
	}
	items, total, err := st.ListAlerts(ctx, f)
	if err != nil {
		return nil, err
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	alerts := make([]view.Alert, 0, len(items))
	next := ""
	for i := range items {
		alerts = append(alerts, view.AlertFromRecord(&items[i], false))
	}
	if more {
		next = items[len(items)-1].ID
	}
	matched := []string{"provider", "account_uid", "region", "native_resource_id", "host_resource_type"}
	if len(resourceIDs) > 1 {
		matched = append(matched, "vendor_resource_id_alias")
	}
	return map[string]any{"asset_id": id, "alerts": alerts, "total": total, "snapshot_sequence": *f.SnapshotSequence, "has_more": more, "next_cursor": next, "limit": limit, "matched_on": matched, "limitations": []string{"only_stored_findings", "resource_scope_may_be_explicit_connection_configuration"}}, nil
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
