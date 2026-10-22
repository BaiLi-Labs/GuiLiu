package query

import (
	"context"
	"fmt"
	"github.com/BaiLi-Labs/GuiLiu/internal/audit"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func PinSnapshot(ctx context.Context, st store.Store, f *model.AlertFilter) error {
	high, err := st.SnapshotSequence(ctx)
	if err != nil {
		return err
	}
	if f.SnapshotSequence == nil {
		f.SnapshotSequence = &high
	}
	if *f.SnapshotSequence < 0 || *f.SnapshotSequence > high {
		return fmt.Errorf("snapshot_sequence is outside the available change log")
	}
	if f.GroupBy.UsesAssetContext() {
		assetHigh, err := st.AssetSnapshotSequence(ctx)
		if err != nil {
			return err
		}
		if f.AssetSnapshotSequence == nil {
			if f.GroupBy.UsesAssetContext() && len(f.GroupKey) > 0 {
				return fmt.Errorf("asset_snapshot_sequence is required to expand an asset or network group")
			}
			f.AssetSnapshotSequence = &assetHigh
		}
		if *f.AssetSnapshotSequence < 0 || *f.AssetSnapshotSequence > assetHigh {
			return fmt.Errorf("asset_snapshot_sequence is outside the available asset revisions")
		}
	}
	audit.FindingQuery(ctx, *f)
	return nil
}
