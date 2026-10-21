package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/BaiLi-Labs/GuiLiu/internal/timeutil"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

func (s *Server) registerTools() {
	s.registerDataTools()
	s.registerAssetTools()
	s.register(Tool{
		Name:        "list_cloud_accounts",
		Description: "List configured cloud accounts with ingestion health. Credentials are never returned.",
		InputSchema: obj(map[string]any{}),
		Handler:     s.toolListAccounts,
	})
	s.register(Tool{
		Name:        "list_alerts",
		Description: "List normalized cloud security alerts. Use this for cross-cloud fact retrieval and filtering by provider, severity, status, asset or keyword.",
		InputSchema: obj(mergeProps(map[string]any{
			"provider":   strProp("Provider id, e.g. tencent or aliyun"),
			"account_id": strProp("Configured account id"),
			"severity":   severityProp(),
			"status":     statusProp(),
			"keyword":    strProp("Full-text search across title, description, alert type and asset name"),
			"ip":         strProp("Exact match on source, destination or observable IP"),
			"resource":   strProp("Asset id (exact) or asset name (substring)"),
			"sort":       strProp("event_time (default), severity, last_seen, first_seen"),
		}, mergeProps(timeProps(), map[string]any{
			"limit":  intProp("Maximum alerts to return", 20, 1, query.AgentMaxPageSize),
			"offset": intProp("Pagination offset", 0, 0, 10000),
		}))),
		Handler: s.toolListAlerts,
	})
	s.register(Tool{
		Name:        "list_alert_groups",
		Description: "Group findings by exact fields: native rule/account/region/asset/source signature, type and asset, asset, or source. Counts are stored alert records, not attack occurrences. max_severity is the maximum vendor-mapped severity among members. No verdicts or filtering are inferred. Reuse the returned snapshot_sequence and window.start/end when expanding or paging.",
		InputSchema: obj(mergeProps(map[string]any{
			"group_by":   groupByProp(),
			"provider":   strProp("Provider id"),
			"account_id": strProp("Configured account id"),
			"severity":   severityProp(),
			"status":     statusProp(),
			"keyword":    strProp("Full-text search across title, description, alert type and asset name"),
			"ip":         strProp("Exact match on source or destination IP"),
			"resource":   strProp("Asset id (exact) or asset name (substring)"),
		}, mergeProps(timeProps(), map[string]any{
			"limit":  intProp("Maximum groups to return", 20, 1, query.AgentMaxPageSize),
			"offset": intProp("Pagination offset", 0, 0, 10000),
		}))),
		Handler: s.toolListAlertGroups,
	})
	s.register(Tool{
		Name:        "get_alert_group",
		Description: "Get original alerts in a group. Copy group_by, group_key and window.start/end from list_alert_groups to keep membership within the same time range.",
		InputSchema: obj(mergeProps(map[string]any{
			"group_by":   groupByProp(),
			"group_key":  groupKeyProp(),
			"provider":   strProp("Provider id"),
			"account_id": strProp("Configured account id"),
			"severity":   severityProp(),
			"status":     statusProp(),
			"keyword":    strProp("Full-text search"),
			"ip":         strProp("Exact match on source or destination IP"),
			"resource":   strProp("Asset id (exact) or asset name (substring)"),
		}, mergeProps(timeProps(), map[string]any{
			"limit":  intProp("Maximum member alerts to return", 50, 1, query.AgentMaxPageSize),
			"offset": intProp("Pagination offset", 0, 0, 10000),
		})), "group_by", "group_key"),
		Handler: s.toolGetAlertGroup,
	})
	s.register(Tool{
		Name:        "get_alert",
		Description: "Get one alert with its source-appropriate OCSF payload (when available) and the original vendor JSON.",
		InputSchema: obj(map[string]any{"alert_id": strProp("Alert id returned by list_alerts")}, "alert_id"),
		Handler:     s.toolGetAlert,
	})
	s.register(Tool{
		Name:        "get_alert_evidence",
		Description: "Get the evidence artifacts, observables and raw vendor payload for one alert. Use this before drawing conclusions.",
		InputSchema: obj(map[string]any{"alert_id": strProp("Alert id returned by list_alerts")}, "alert_id"),
		Handler:     s.toolGetAlertEvidence,
	})
	s.register(Tool{
		Name:        "search_alerts_by_ip",
		Description: "Find alerts matching a source, destination or observable IP. Defaults to the last 7 days.",
		InputSchema: obj(mergeProps(map[string]any{
			"ip": strProp("IPv4 or IPv6 address"),
		}, mergeProps(timeProps(), map[string]any{
			"limit": intProp("Maximum alerts to return", 50, 1, query.AgentMaxPageSize),
		})), "ip"),
		Handler: s.toolSearchByIP,
	})
	s.register(Tool{
		Name:        "search_alerts_by_asset",
		Description: "Find alerts for an asset id or name. Defaults to the last 7 days.",
		InputSchema: obj(mergeProps(map[string]any{
			"asset": strProp("Asset id (exact) or asset name (substring)"),
		}, mergeProps(timeProps(), map[string]any{
			"limit": intProp("Maximum alerts to return", 50, 1, query.AgentMaxPageSize),
		})), "asset"),
		Handler: s.toolSearchByAsset,
	})
	s.register(Tool{
		Name:        "get_alert_statistics",
		Description: "Aggregate alert counts by severity, provider, status, day and top assets. Defaults to the last 7 days.",
		InputSchema: obj(mergeProps(map[string]any{
			"provider":   strProp("Provider id"),
			"account_id": strProp("Configured account id"),
			"severity":   severityProp(),
			"status":     statusProp(),
		}, timeProps())),
		Handler: s.toolStatistics,
	})
	s.register(Tool{
		Name:        "get_connector_health",
		Description: "Show ingestion health for every account: cursor, last success, last error, consecutive failures and recent runs.",
		InputSchema: obj(map[string]any{
			"account_id": strProp("Optional account id; omit for all accounts"),
		}),
		Handler: s.toolHealth,
	})
}

func (s *Server) toolListAlerts(ctx context.Context, args map[string]any) (any, error) {
	f, err := s.filterFromArgs(args, 7*24*time.Hour)
	if err != nil {
		return nil, err
	}
	return s.listAlerts(ctx, f)
}

func (s *Server) toolListAlertGroups(ctx context.Context, args map[string]any) (any, error) {
	f, err := s.filterFromArgs(args, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	if f.GroupBy == "" {
		f.GroupBy = model.GroupByTypeAsset
	}
	if err := query.PinSnapshot(ctx, s.store, &f); err != nil {
		return nil, err
	}
	groups, total, err := s.store.ListAlertGroups(ctx, f)
	if err != nil {
		return nil, err
	}
	coverage, err := s.coverage(ctx, f)
	if err != nil {
		return nil, err
	}
	return map[string]any{"snapshot_sequence": f.SnapshotSequence,
		"coverage": coverage,
		"window":   view.WindowFromFilter(f),
		"total":    total,
		"group_by": f.GroupBy,
		"limit":    f.Limit,
		"offset":   f.Offset,
		"groups":   groups,
	}, nil
}

func (s *Server) toolGetAlertGroup(ctx context.Context, args map[string]any) (any, error) {
	f, err := s.filterFromArgs(args, 24*time.Hour)
	if err != nil {
		return nil, err
	}
	if f.GroupBy == "" {
		return nil, errors.New("group_by is required")
	}
	if len(f.GroupKey) == 0 {
		return nil, errors.New("group_key is required")
	}
	result, err := s.listAlerts(ctx, f)
	if err != nil {
		return nil, err
	}
	payload, _ := result.(map[string]any)
	payload["group_by"] = f.GroupBy
	payload["group_key"] = f.GroupKey
	return payload, nil
}

func (s *Server) toolGetAlert(ctx context.Context, args map[string]any) (any, error) {
	rec, err := s.readFindingArgs(ctx, args)
	id := argString(args, "alert_id")
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("alert %s not found", id)
		}
		return nil, err
	}
	return map[string]any{
		"alert": view.AlertFromRecord(rec, true),
	}, nil
}

func (s *Server) toolGetAlertEvidence(ctx context.Context, args map[string]any) (any, error) {
	rec, err := s.readFindingArgs(ctx, args)
	id := argString(args, "alert_id")
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("alert %s not found", id)
		}
		return nil, err
	}
	a := view.AlertFromRecord(rec, true)
	return map[string]any{
		"alert_id": rec.ID,
		"revision": rec.Revision, "raw_hash": a.RawHash, "raw_url": a.RawURL, "provenance": a.Provenance,
		"title":       rec.Title,
		"severity":    rec.Severity.String(),
		"event_time":  a.EventTime,
		"observables": a.Observables,
		"evidences":   a.Evidences,
		"ocsf":        a.OCSF,
		"raw":         a.Raw,
	}, nil
}

func (s *Server) toolSearchByIP(ctx context.Context, args map[string]any) (any, error) {
	ip := argString(args, "ip")
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("ip %q is not a valid IP address", ip)
	}
	f, err := s.filterFromArgs(args, 7*24*time.Hour)
	if err != nil {
		return nil, err
	}
	if _, ok := args["limit"]; !ok {
		f.Limit = 50
	}
	f.IP = ip
	return s.listAlerts(ctx, f)
}

func (s *Server) toolSearchByAsset(ctx context.Context, args map[string]any) (any, error) {
	asset := argString(args, "asset")
	if asset == "" {
		return nil, errors.New("asset is required")
	}
	f, err := s.filterFromArgs(args, 7*24*time.Hour)
	if err != nil {
		return nil, err
	}
	if _, ok := args["limit"]; !ok {
		f.Limit = 50
	}
	f.Resource = asset
	return s.listAlerts(ctx, f)
}

func (s *Server) toolStatistics(ctx context.Context, args map[string]any) (any, error) {
	f, err := s.filterFromArgs(args, 7*24*time.Hour)
	if err != nil {
		return nil, err
	}
	f.Limit = 1
	if err := query.PinSnapshot(ctx, s.store, &f); err != nil {
		return nil, err
	}
	stats, err := s.store.AlertStats(ctx, f)
	if err != nil {
		return nil, err
	}
	coverage, err := s.coverage(ctx, f)
	if err != nil {
		return nil, err
	}
	return map[string]any{"snapshot_sequence": f.SnapshotSequence,
		"coverage": coverage,
		"window": map[string]any{
			"start": timeutil.Format(derefTime(f.Start)),
			"end":   timeutil.Format(derefTime(f.End)),
		},
		"statistics": view.Summarize(*stats),
	}, nil
}

func (s *Server) toolListAccounts(ctx context.Context, _ map[string]any) (any, error) {
	accounts, err := s.accountsWithState(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"accounts": accounts}, nil
}

func (s *Server) toolHealth(ctx context.Context, args map[string]any) (any, error) {
	accounts, err := s.store.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	accountID := argString(args, "account_id")
	items := make([]map[string]any, 0, len(accounts))
	status := "ok"
	for i := range accounts {
		a := &accounts[i]
		if accountID != "" && a.ID != accountID {
			continue
		}
		state, err := s.store.GetSyncState(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		runs, err := s.store.ListSyncRuns(ctx, a.ID, 5)
		if err != nil {
			return nil, err
		}
		sv := view.SyncStateFromModel(state, s.maxAge)
		if a.Enabled && !sv.Healthy {
			status = "degraded"
		}
		runViews := make([]view.SyncRun, 0, len(runs))
		for i := range runs {
			runViews = append(runViews, view.SyncRunFromModel(&runs[i]))
		}
		items = append(items, map[string]any{
			"account":     view.AccountFromModel(a),
			"sync_state":  sv,
			"recent_runs": runViews,
		})
	}
	if accountID != "" && len(items) == 0 {
		return nil, fmt.Errorf("account %s not found", accountID)
	}
	providers := []any{}
	if s.registry != nil {
		descriptors := s.registry.List()
		sort.Slice(descriptors, func(i, j int) bool { return descriptors[i].ID < descriptors[j].ID })
		for _, d := range descriptors {
			providers = append(providers, d)
		}
	}
	return map[string]any{
		"status":    status,
		"accounts":  items,
		"providers": providers,
	}, nil
}

func (s *Server) accountsWithState(ctx context.Context) ([]view.Account, error) {
	accounts, err := s.store.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]view.Account, 0, len(accounts))
	for i := range accounts {
		a := &accounts[i]
		v := view.AccountFromModel(a)
		if s.registry != nil {
			if d, ok := s.registry.Descriptor(a.Provider); ok {
				v.ProviderName = d.Name
			}
		}
		state, err := s.store.GetSyncState(ctx, a.ID)
		if err != nil {
			return nil, err
		}
		sv := view.SyncStateFromModel(state, s.maxAge)
		v.SyncState = &sv
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) listAlerts(ctx context.Context, f model.AlertFilter) (any, error) {
	if err := query.PinSnapshot(ctx, s.store, &f); err != nil {
		return nil, err
	}
	items, total, err := s.store.ListAlerts(ctx, f)
	if err != nil {
		return nil, err
	}
	alerts := make([]view.Alert, 0, len(items))
	for i := range items {
		alerts = append(alerts, view.AlertFromRecord(&items[i], false))
	}
	coverage, err := s.coverage(ctx, f)
	if err != nil {
		return nil, err
	}
	next := ""
	hasMore := f.Offset+len(items) < total
	if f.Sort == "id" && len(items) > 0 && hasMore {
		next = items[len(items)-1].ID
	}
	return map[string]any{"snapshot_sequence": f.SnapshotSequence, "next_cursor": next, "has_more": hasMore,
		"coverage": coverage,
		"window":   view.WindowFromFilter(f),
		"total":    total,
		"limit":    f.Limit,
		"offset":   f.Offset,
		"alerts":   alerts,
	}, nil
}

// Freshness is advisory, not a claim that a historical query is fully covered.
func (s *Server) coverage(ctx context.Context, f model.AlertFilter) (any, error) {
	return query.Coverage(ctx, s.store, s.registry, f, s.maxAge)
}

func (s *Server) filterFromArgs(args map[string]any, defaultWindow time.Duration) (model.AlertFilter, error) {
	f := model.AlertFilter{
		TimeField: argString(args, "time_field"), Provider: argString(args, "provider"),
		AccountID: argString(args, "account_id"),
		Keyword:   argString(args, "keyword"),
		IP:        argString(args, "ip"),
		Resource:  argString(args, "resource"),
		Sort:      argString(args, "sort"),
		Limit:     argInt(args, "limit", 20, 1, query.AgentMaxPageSize),
		Offset:    argInt(args, "offset", 0, 0, int(^uint(0)>>1)),
		RuleID:    argString(args, "rule_id"), FindingKind: argString(args, "finding_kind"), VendorStatus: argString(args, "vendor_status"), ObservableValue: argString(args, "observable_value"), AfterID: argString(args, "after_id"),
	}
	if _, ok := args["observable_type"]; ok {
		v, e := parseInteger(args["observable_type"])
		if e != nil || v < 0 || v > 999 {
			return f, fmt.Errorf("invalid observable_type")
		}
		n := int(v)
		f.ObservableType = &n
	}
	if raw, ok := args["snapshot_sequence"]; ok {
		n, err := parseInteger(raw)
		if err != nil || n < 0 {
			return f, fmt.Errorf("invalid snapshot_sequence")
		}
		f.SnapshotSequence = &n
	}
	if f.AfterID != "" {
		f.Sort = "id"
	}
	if raw := argString(args, "group_by"); raw != "" {
		groupBy, ok := model.ParseAlertGroupBy(raw)
		if !ok {
			return f, fmt.Errorf("unknown group_by %q", raw)
		}
		f.GroupBy = groupBy
	}
	if key := argStringMap(args, "group_key"); len(key) > 0 {
		f.GroupKey = key
	}
	for _, raw := range argList(args, "severity") {
		sev, ok := model.ParseSeverity(raw)
		if !ok {
			return f, fmt.Errorf("unknown severity %q", raw)
		}
		f.Severities = append(f.Severities, sev)
	}
	for _, raw := range argList(args, "status") {
		st, ok := model.ParseAlertStatus(raw)
		if !ok {
			return f, fmt.Errorf("unknown status %q", raw)
		}
		f.Statuses = append(f.Statuses, st)
	}
	start, end, err := parseRange(args, defaultWindow)
	if err != nil {
		return f, err
	}
	f.Start = start
	f.End = end
	if f.IP != "" && net.ParseIP(f.IP) == nil {
		return f, fmt.Errorf("ip %q is not a valid IP address", f.IP)
	}
	return f, query.ValidateFilter(f)
}

func parseRange(args map[string]any, defaultWindow time.Duration) (*time.Time, *time.Time, error) {
	return query.ResolveWindow(argString(args, "start"), argString(args, "end"), argString(args, "since"), defaultWindow, time.Now().UTC())
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func argStringMap(args map[string]any, key string) map[string]string {
	v, ok := args[key]
	if !ok || v == nil {
		return nil
	}
	raw, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, item := range raw {
		if s, ok := item.(string); ok {
			out[k] = strings.TrimSpace(s)
		}
	}
	return out
}

func argString(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func argInt(args map[string]any, key string, def, min, max int) int {
	v, ok := args[key]
	if !ok || v == nil {
		return def
	}
	n := def
	switch t := v.(type) {
	case float64:
		n = int(t)
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			n = parsed
		}
	case int:
		n = t
	}
	if n < min {
		n = min
	}
	if n > max {
		n = max
	}
	return n
}

func argList(args map[string]any, key string) []string {
	v, ok := args[key]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case string:
		parts := strings.Split(t, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

func parseInteger(value any) (int64, error) {
	switch v := value.(type) {
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) || math.Trunc(v) != v || v < 0 || v > 9007199254740991 {
			return 0, fmt.Errorf("invalid integer")
		}
		return int64(v), nil
	case json.Number:
		return v.Int64()
	default:
		return strconv.ParseInt(fmt.Sprint(value), 10, 64)
	}
}
