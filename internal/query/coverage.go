// Package query holds the data access semantics shared by REST, MCP and the
// read-only query CLI.
package query

import (
	"context"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func Coverage(ctx context.Context, st store.Store, registry *connector.Registry, f model.AlertFilter, maxAge time.Duration) (*model.Coverage, error) {
	if err := PinSnapshot(ctx, st, &f); err != nil {
		return nil, err
	}
	observed, err := st.ObservedEventRanges(ctx, f)
	if err != nil {
		return nil, err
	}
	accounts, err := st.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	unconfigured, err := st.ListUnconfiguredSources(ctx, f.Provider, f.AccountID)
	if err != nil {
		return nil, err
	}
	accounts = append(accounts, unconfigured...)
	result := &model.Coverage{Complete: true, Accounts: []model.AccountCoverage{}, Boundary: "Only records visible through the declared source API, configured scope and granted permissions are covered. Vendor retention, delivery delays and products not aggregated into that API are outside this guarantee."}
	result.SnapshotSequence = f.SnapshotSequence
	result.QueryWindow = model.CoverageQueryWindow{Start: f.Start, End: f.End, TimeField: f.TimeField}
	if result.QueryWindow.TimeField == "" {
		result.QueryWindow.TimeField = "event_time"
	}
	apis := map[string]string{"tencent": "CSIP DescribeAlertList", "aliyun": "SAS DescribeSuspEvents", "huawei": "SecMaster ListAlerts", "aws": "Security Hub GetFindingsV2", "gcp": "SCC ListFindings REST", "azure": "Defender for Cloud ARM Alerts - List"}
	basis := map[string]string{"tencent": "vendor alert query window", "aliyun": "last occurrence time", "huawei": "vendor search time range", "aws": "created OR last_seen OR modified", "gcp": "event_time", "azure": "full list; local event/processing time window"}
	for _, a := range accounts {
		if f.Provider != "" && f.Provider != a.Provider || f.AccountID != "" && f.AccountID != a.ID {
			continue
		}
		state, err := st.GetSyncState(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		c := model.AccountCoverage{AccountID: a.ID, Provider: a.Provider, Name: a.Name, Enabled: a.Enabled, Scope: map[string]string{}, API: apis[a.Provider], TimeBasis: basis[a.Provider], Status: state.Health(time.Now().UTC(), maxAge), LastSuccessAt: state.LastSuccessAt, FailedRecords: state.FailedRecords, LastError: state.LastError, Limitations: []string{"upstream_permissions_and_retention", "not_all_vendor_products", "no_historical_state_reconciliation"}}
		c.LastSourceError = state.LastSourceError
		c.LastAttemptAt = state.LastAttemptAt
		c.ObservedEvents = observed[a.ID]
		c.Reasons = []string{}
		c.OutsideCompletedWindows = outsideCollection(f.Start, f.End, state.CoverageStart, state.CursorEnd)
		c.Limitations = append(c.Limitations, "collection_window_bounds_are_not_event_time_coverage", "sync_metadata_is_current_not_snapshot_versioned")
		if !state.PendingEnd.IsZero() {
			c.PendingWindow = &model.CollectionWindow{Start: state.PendingStart, End: state.PendingEnd}
		}
		if d, ok := registry.Descriptor(a.Provider); ok {
			c.APIVersion = d.APIVersion
			if d.SourceAPI != "" {
				c.API = d.SourceAPI
			}
		}
		if a.Region != "" {
			c.Scope["region"] = a.Region
		}
		if a.AccountUID != "" {
			c.Scope["account_uid"] = a.AccountUID
		}
		for _, key := range []string{"project_id", "workspace_id", "parent", "location", "subscription_id", "status", "api_version"} {
			if v := a.Options[key]; v != "" {
				c.Scope[key] = v
			}
		}
		if a.Provider == "gcp" {
			if c.Scope["location"] == "" {
				c.Scope["location"] = "global"
			}
			if a.Options["api_version"] != "" {
				c.APIVersion = a.Options["api_version"]
			}
		}
		if !state.CoverageStart.IsZero() {
			v := state.CoverageStart
			c.CoverageStart = &v
		}
		if !state.CursorEnd.IsZero() {
			v := state.CursorEnd
			c.Watermark = &v
		}
		c.Complete = a.Enabled && c.Status == "healthy" && f.Start != nil && f.End != nil && c.CoverageStart != nil && c.Watermark != nil && !f.Start.Before(*c.CoverageStart) && !f.End.After(*c.Watermark)
		if !a.Enabled {
			c.Status = "disabled"
		}
		if c.Status != "healthy" {
			c.Reasons = append(c.Reasons, "sync_"+c.Status)
		}
		if state.FailedRecords > 0 {
			c.Reasons = append(c.Reasons, "unresolved_ingest_failures")
		}
		for _, interval := range c.OutsideCompletedWindows {
			c.Reasons = append(c.Reasons, interval.Reason)
		}
		if f.Start == nil || f.End == nil {
			c.Limitations = append(c.Limitations, "query_range_not_bounded")
			c.Reasons = append(c.Reasons, "query_range_not_bounded")
		}
		// A time watermark describes collection progress, not proof that an old
		// finding's every subsequent state change is observable through this API.
		if a.Provider != "aws" {
			c.Limitations = append(c.Limitations, "old_finding_state_changes_may_be_outside_collection_window")
		}
		if f.TimeField != "" && f.TimeField != "event_time" {
			c.Complete = false
			c.Limitations = append(c.Limitations, "query_time_basis_differs_from_source_collection_basis")
			c.Reasons = append(c.Reasons, "query_time_basis_differs_from_source_collection_basis")
		}
		if !c.Complete {
			result.Complete = false
		}
		result.Accounts = append(result.Accounts, c)
	}
	if len(result.Accounts) == 0 {
		result.Complete = false
	}
	return result, nil
}

// Compare timestamp bounds only. An event may precede these source query
// windows (e.g. a finding returned by its update time). No missing-event ratio
// or source delivery guarantee can be inferred from these durations.
func outsideCollection(start, end *time.Time, collectedStart, collectedEnd time.Time) []model.CollectionInterval {
	out := []model.CollectionInterval{}
	if start == nil || end == nil || !end.After(*start) {
		return out
	}
	add := func(a, b time.Time, reason string) {
		if b.After(a) {
			out = append(out, model.CollectionInterval{CollectionWindow: model.CollectionWindow{Start: a, End: b}, DurationSeconds: b.Sub(a).Seconds(), Reason: reason})
		}
	}
	if collectedStart.IsZero() || collectedEnd.IsZero() || collectedEnd.Before(collectedStart) {
		add(*start, *end, "no_completed_collection_window")
		return out
	}
	if start.Before(collectedStart) {
		to := collectedStart
		if end.Before(to) {
			to = *end
		}
		add(*start, to, "before_completed_collection")
	}
	if end.After(collectedEnd) {
		from := collectedEnd
		if start.After(from) {
			from = *start
		}
		add(from, *end, "after_completed_collection")
	}
	return out
}
