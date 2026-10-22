package query

import (
	"context"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

// GroupPage is shared by REST and MCP; CLI and Web consume the same REST page.
func GroupPage(ctx context.Context, st store.Store, f model.AlertFilter) (map[string]any, error) {
	groups, total, err := st.ListAlertGroups(ctx, f)
	if err != nil {
		return nil, err
	}
	summary, err := st.GroupingSummary(ctx, f)
	if err != nil {
		return nil, err
	}
	limitations := []string{}
	if f.GroupBy.UsesAssetContext() {
		limitations = []string{"current_asset_observations_not_event_time_state", "only_explicitly_collected_primary_host_references", "asset_title_and_relation_samples_limited_to_5"}
		if f.GroupBy.IsNetwork() {
			limitations = append(limitations, "network_memberships_can_overlap")
		}
	}
	return map[string]any{"groups": groups, "total": total, "group_by": f.GroupBy, "limit": f.Limit, "offset": f.Offset, "window": view.WindowFromFilter(f), "snapshot_sequence": f.SnapshotSequence, "asset_snapshot_sequence": f.AssetSnapshotSequence, "summary": summary, "limitations": limitations}, nil
}
