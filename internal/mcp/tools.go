package mcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/BaiLi-Labs/GuiLiu/internal/timeutil"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

const maxRange = 90 * 24 * time.Hour

func (s *Server) registerTools() {
	s.register(Tool{
		Name:        "list_cloud_accounts",
		Description: "List configured cloud accounts with ingestion health. Credentials are never returned.",
		InputSchema: obj(map[string]any{}),
		Handler:     s.toolListAccounts,
	})
	s.register(Tool{
		Name:        "list_alerts",
		Description: "List normalized cloud security alerts. Use this for cross-cloud triage and filtering by provider, severity, status, asset or keyword.",
		InputSchema: obj(mergeProps(map[string]any{
			"provider":   strProp("Provider id, e.g. tencent or aliyun"),
			"account_id": strProp("Configured account id"),
			"severity":   severityProp(),
			"status":     statusProp(),
			"keyword":    strProp("Full-text search across title, description, alert type and asset name"),
			"ip":         strProp("Exact match on source or destination IP"),
			"resource":   strProp("Asset id (exact) or asset name (substring)"),
			"sort":       strProp("event_time (default), severity, last_seen, first_seen"),
		}, mergeProps(timeProps(), map[string]any{
			"limit":  intProp("Maximum alerts to return", 20, 1, 200),
			"offset": intProp("Pagination offset", 0, 0, 10000),
		}))),
		Handler: s.toolListAlerts,
	})
	s.register(Tool{
		Name:        "list_alert_groups",
		Description: "Group alerts by signature, asset or source IP. Grouping is a read-only view; it never deletes or suppresses the original alerts.",
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
			"limit":  intProp("Maximum groups to return", 20, 1, 200),
			"offset": intProp("Pagination offset", 0, 0, 10000),
		}))),
		Handler: s.toolListAlertGroups,
	})
	s.register(Tool{
		Name:        "get_alert_group",
		Description: "Get the original alerts that belong to one alert group. group_key comes from list_alert_groups.",
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
			"limit":  intProp("Maximum member alerts to return", 50, 1, 200),
			"offset": intProp("Pagination offset", 0, 0, 10000),
		})), "group_by", "group_key"),
		Handler: s.toolGetAlertGroup,
	})
	s.register(Tool{
		Name:        "get_alert",
		Description: "Get one alert with its full OCSF Detection Finding payload and the original vendor JSON.",
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
		Description: "Find alerts where an IP is the source or destination. Defaults to the last 7 days.",
		InputSchema: obj(mergeProps(map[string]any{
			"ip": strProp("IPv4 or IPv6 address"),
		}, mergeProps(timeProps(), map[string]any{
			"limit": intProp("Maximum alerts to return", 50, 1, 200),
		})), "ip"),
		Handler: s.toolSearchByIP,
	})
	s.register(Tool{
		Name:        "search_alerts_by_asset",
		Description: "Find alerts for an asset id or name. Defaults to the last 7 days.",
		InputSchema: obj(mergeProps(map[string]any{
			"asset": strProp("Asset id (exact) or asset name (substring)"),
		}, mergeProps(timeProps(), map[string]any{
			"limit": intProp("Maximum alerts to return", 50, 1, 200),
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
	f, err := s.filterFromArgs(args, 0)
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
		f.GroupBy = model.GroupBySignature
	}
	groups, total, err := s.store.ListAlertGroups(ctx, f)
	if err != nil {
		return nil, err
	}
	return map[string]any{
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
	id := argString(args, "alert_id")
	if id == "" {
		return nil, errors.New("alert_id is required")
	}
	rec, err := s.store.GetAlert(ctx, id)
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
	id := argString(args, "alert_id")
	if id == "" {
		return nil, errors.New("alert_id is required")
	}
	rec, err := s.store.GetAlert(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("alert %s not found", id)
		}
		return nil, err
	}
	a := view.AlertFromRecord(rec, true)
	return map[string]any{
		"alert_id":    rec.ID,
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
	stats, err := s.store.AlertStats(ctx, f)
	if err != nil {
		return nil, err
	}
	return map[string]any{
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
		if a.Enabled && state.ConsecutiveFailures > 0 {
			status = "degraded"
		}
		runViews := make([]view.SyncRun, 0, len(runs))
		for i := range runs {
			runViews = append(runViews, view.SyncRunFromModel(&runs[i]))
		}
		items = append(items, map[string]any{
			"account":     view.AccountFromModel(a),
			"sync_state":  view.SyncStateFromModel(state),
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
		sv := view.SyncStateFromModel(state)
		v.SyncState = &sv
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) listAlerts(ctx context.Context, f model.AlertFilter) (any, error) {
	items, total, err := s.store.ListAlerts(ctx, f)
	if err != nil {
		return nil, err
	}
	alerts := make([]view.Alert, 0, len(items))
	for i := range items {
		alerts = append(alerts, view.AlertFromRecord(&items[i], false))
	}
	return map[string]any{
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
		"alerts": alerts,
	}, nil
}

func (s *Server) filterFromArgs(args map[string]any, defaultWindow time.Duration) (model.AlertFilter, error) {
	f := model.AlertFilter{
		Provider:  argString(args, "provider"),
		AccountID: argString(args, "account_id"),
		Keyword:   argString(args, "keyword"),
		IP:        argString(args, "ip"),
		Resource:  argString(args, "resource"),
		Sort:      argString(args, "sort"),
		Limit:     argInt(args, "limit", 20, 1, 200),
		Offset:    argInt(args, "offset", 0, 0, 10000),
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
	return f, nil
}

func parseRange(args map[string]any, defaultWindow time.Duration) (*time.Time, *time.Time, error) {
	now := time.Now().UTC()
	var start, end *time.Time

	if v := argString(args, "start"); v != "" {
		t, ok := timeutil.Parse(v)
		if !ok {
			return nil, nil, fmt.Errorf("invalid start %q", v)
		}
		start = &t
	}
	if v := argString(args, "end"); v != "" {
		t, ok := timeutil.Parse(v)
		if !ok {
			return nil, nil, fmt.Errorf("invalid end %q", v)
		}
		end = &t
	}
	if v := argString(args, "since"); v != "" {
		d, ok := timeutil.ParseDuration(v)
		if !ok {
			return nil, nil, fmt.Errorf("invalid since %q", v)
		}
		t := now.Add(-d)
		start = &t
		if end == nil {
			e := now
			end = &e
		}
	}
	if start != nil && end == nil {
		e := now
		end = &e
	}
	if start == nil && end == nil && defaultWindow > 0 {
		s := now.Add(-defaultWindow)
		start = &s
		e := now
		end = &e
	}
	if start != nil && end != nil {
		if end.Before(*start) {
			return nil, nil, errors.New("end must be after start")
		}
		if end.Sub(*start) > maxRange {
			return nil, nil, fmt.Errorf("time range exceeds %s; narrow the query", maxRange)
		}
	}
	return start, end, nil
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
