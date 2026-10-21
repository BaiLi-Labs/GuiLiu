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
	audit.FindingQuery(ctx, *f)
	return nil
}
