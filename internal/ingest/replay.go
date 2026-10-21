package ingest

import (
	"bytes"
	"context"
	"fmt"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

type ReplayResult struct {
	Scanned int  `json:"scanned"`
	Changed int  `json:"changed"`
	Failed  int  `json:"failed"`
	Applied bool `json:"applied"`
}

// Replay rebuilds normalized data from stored payloads without Fetch/Check.
// The CLI is an offline maintenance command: stop the serving process first.
func (e *Engine) Replay(ctx context.Context, acct model.Account, f model.AlertFilter, mapperVersion string, apply bool) (*ReplayResult, error) {
	if !e.acquire(acct.ID) {
		return nil, ErrAlreadyRunning
	}
	defer e.release(acct.ID)
	conn, err := e.newConnector(ctx, acct)
	if err != nil {
		return nil, err
	}
	defer connector.Close(conn)
	f.AccountID = acct.ID
	result := &ReplayResult{Applied: apply}
	afterID := ""
	for {
		items, err := e.store.ListReplayAlerts(ctx, f, mapperVersion, afterID)
		if err != nil {
			return result, err
		}
		if len(items) == 0 {
			return result, nil
		}
		for _, old := range items {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			afterID = old.ID
			result.Scanned++
			alert, err := conn.Normalize(old.Raw)
			if err == nil && alert.ExternalID != old.ExternalID {
				err = fmt.Errorf("external id changed from %q to %q", old.ExternalID, alert.ExternalID)
			}
			var rec *model.AlertRecord
			if err == nil {
				alert.Raw = old.Raw
				rec, err = e.buildRecord(acct, conn.Info(), alert, old.IngestedAt)
			}
			if err != nil {
				result.Failed++
				e.log.Warn("replay mapping failed", "alert_id", old.ID, "error", err)
				continue
			}
			if bytes.Equal(old.OCSF, rec.OCSF) && old.MapperVersion == rec.MapperVersion &&
				old.Actor == rec.Actor &&
				old.EventTime.Equal(rec.EventTime) && old.FirstSeenAt.Equal(rec.FirstSeenAt) && old.LastSeenAt.Equal(rec.LastSeenAt) {
				continue
			}
			rec.LastIngestedAt = old.LastIngestedAt
			result.Changed++
			if apply {
				if _, err := e.store.UpsertAlert(ctx, rec); err != nil {
					return result, err
				}
			}
		}
	}
}
