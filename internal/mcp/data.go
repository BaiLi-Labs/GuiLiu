package mcp

import (
	"context"
	"fmt"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

func (s *Server) registerDataTools() {
	s.register(Tool{Name: "list_alert_changes", Description: "Read the persistent change log in sequence order. Save next_cursor only after processing. Reuse the same provider/account scope when resuming. Fetch an exact revision with get_alert. projection_updated=false means a late older observation was retained in history without replacing the current projection. Repeated ingestion does not create changes.", InputSchema: obj(map[string]any{"cursor": strProp("Last consumed sequence; empty starts at the beginning"), "limit": intProp("Maximum changes", query.ChangeDefaultLimit, 1, query.ChangeMaxLimit), "provider": strProp("Optional provider scope"), "account_id": strProp("Optional account scope")}), Handler: func(ctx context.Context, args map[string]any) (any, error) {
		return s.store.ListAlertChanges(ctx, argString(args, "cursor"), argInt(args, "limit", query.ChangeDefaultLimit, 1, query.ChangeMaxLimit), argString(args, "provider"), argString(args, "account_id"))
	}})
	s.register(Tool{Name: "get_data_coverage", Description: "Read completed source query bounds, matching stored event bounds, pending windows and failure reasons. coverage_start is not the oldest event time. Outside-window durations are not missing-event counts or ratios. complete is a mechanical collection check, not a usability verdict. Sync metadata is current; Finding observations use snapshot_sequence.", InputSchema: obj(mergeProps(timeProps(), map[string]any{"provider": strProp("Provider scope"), "account_id": strProp("Account scope")})), Handler: func(ctx context.Context, args map[string]any) (any, error) {
		f, err := s.filterFromArgs(args, 0)
		if err != nil {
			return nil, err
		}
		return s.coverage(ctx, f)
	}})
	s.register(Tool{Name: "get_alert_revisions", Description: "Page immutable source and canonical revisions. Continue with next_before_revision until has_more is false.", InputSchema: obj(map[string]any{"alert_id": strProp("Alert ID"), "before_revision": intProp("Exclusive revision boundary", 0, 0, 2147483647), "limit": intProp("Revisions per page", 20, 1, 200)}, "alert_id"), Handler: func(ctx context.Context, args map[string]any) (any, error) {
		id := argString(args, "alert_id")
		if id == "" {
			return nil, fmt.Errorf("alert_id is required")
		}
		limit := argInt(args, "limit", 20, 1, 200)
		items, err := s.store.AlertRevisionPage(ctx, id, argInt(args, "before_revision", 0, 0, 2147483647), limit+1)
		if err != nil {
			return nil, err
		}
		more := len(items) > limit
		if more {
			items = items[:limit]
		}
		next := 0
		if more {
			next = items[len(items)-1].Revision
		}
		records := []view.Revision{}
		for _, r := range items {
			records = append(records, view.RevisionFromModel(r))
		}
		return map[string]any{"alert_id": id, "revisions": records, "has_more": more, "next_before_revision": next}, nil
	}})
	s.register(Tool{Name: "get_provider_mapping", Description: "Read the versioned source field pointers and deterministic mapping rules for a connector.", InputSchema: obj(map[string]any{"provider": strProp("Provider ID")}, "provider"), Handler: func(_ context.Context, args map[string]any) (any, error) {
		d, ok := s.registry.Descriptor(argString(args, "provider"))
		if !ok {
			return nil, fmt.Errorf("unknown provider")
		}
		return map[string]any{"provider": d.ID, "mapper_version": d.MapperVersion, "fields": connector.MappingFor(d.ID)}, nil
	}})
}
