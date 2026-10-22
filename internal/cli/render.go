package cli

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

type column[T any] struct {
	key    string
	header string
	max    int
	value  func(T) string
}

func selectColumns[T any](all []column[T], defaults []string, fields string) ([]column[T], error) {
	keys := defaults
	if strings.TrimSpace(fields) != "" {
		keys = strings.Split(fields, ",")
	}
	byKey := make(map[string]column[T], len(all))
	available := make([]string, 0, len(all))
	for _, item := range all {
		byKey[item.key] = item
		available = append(available, item.key)
	}
	selected := make([]column[T], 0, len(keys))
	seen := map[string]bool{}
	for _, raw := range keys {
		key := strings.TrimSpace(raw)
		if key == "" {
			return nil, usagef("empty field name in --fields")
		}
		if seen[key] {
			continue
		}
		item, ok := byKey[key]
		if !ok {
			return nil, usagef("unknown field %q; available: %s", key, strings.Join(available, ","))
		}
		selected = append(selected, item)
		seen[key] = true
	}
	return selected, nil
}

func renderTable[T any](w io.Writer, columns []column[T], items []T) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	headers := make([]string, len(columns))
	for i, item := range columns {
		headers[i] = item.header
	}
	if _, err := fmt.Fprintln(tw, strings.Join(headers, "\t")); err != nil {
		return err
	}
	for _, row := range items {
		values := make([]string, len(columns))
		for i, item := range columns {
			values[i] = clean(item.value(row))
			if item.max > 0 {
				values[i] = truncate(values[i], item.max)
			}
		}
		if _, err := fmt.Fprintln(tw, strings.Join(values, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func clean(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\t", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	if value == "" {
		return "-"
	}
	return value
}

func truncate(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	if limit <= 1 {
		return string(runes[:limit])
	}
	return string(runes[:limit-1]) + "…"
}

func shortTime(value string) string {
	if value == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return t.UTC().Format("2006-01-02 15:04:05")
}

func shortTimeValue(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.UTC().Format("2006-01-02 15:04:05")
}

func shortTimePtr(value *time.Time) string {
	if value == nil {
		return "-"
	}
	return shortTimeValue(*value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func joinLimited(values []string, limit int) string {
	if len(values) == 0 {
		return "-"
	}
	if len(values) <= limit {
		return strings.Join(values, "; ")
	}
	return strings.Join(values[:limit], "; ") + fmt.Sprintf("; +%d more", len(values)-limit)
}

func alertAllColumns() []column[view.Alert] {
	return []column[view.Alert]{
		{key: "id", header: "ID", value: func(a view.Alert) string { return a.ID }},
		{key: "event_time", header: "EVENT_TIME", value: func(a view.Alert) string { return shortTime(a.EventTime) }},
		{key: "severity", header: "SEV", value: func(a view.Alert) string { return a.Severity }},
		{key: "status", header: "STATUS", value: func(a view.Alert) string { return a.Status }},
		{key: "provider", header: "PROVIDER", value: func(a view.Alert) string { return a.Provider }},
		{key: "account", header: "ACCOUNT", value: func(a view.Alert) string { return firstNonEmpty(a.AccountName, a.AccountID) }},
		{key: "title", header: "TITLE", max: 56, value: func(a view.Alert) string { return a.Title }},
		{key: "resource", header: "RESOURCE", max: 36, value: func(a view.Alert) string {
			return firstNonEmpty(a.Resource.Name, a.Resource.ID)
		}},
		{key: "resource_id", header: "RESOURCE_ID", value: func(a view.Alert) string { return a.Resource.ID }},
		{key: "resource_account", header: "RESOURCE_ACCOUNT", value: func(a view.Alert) string { return a.Resource.AccountUID }},
		{key: "resource_source", header: "RESOURCE_SOURCE", value: func(a view.Alert) string { return a.Resource.Source }},
		{key: "source_ip", header: "SRC", value: func(a view.Alert) string { return a.SourceIP }},
		{key: "source_location", header: "SRC_LOCATION", max: 28, value: func(a view.Alert) string { return a.SourceLocation }},
		{key: "source_country", header: "SRC_COUNTRY", value: func(a view.Alert) string { return a.SourceCountry }},
		{key: "destination_ip", header: "DST", value: func(a view.Alert) string { return a.DestinationIP }},
		{key: "response_action", header: "RESPONSE", max: 28, value: func(a view.Alert) string { return a.ResponseAction }},
		{key: "alert_type", header: "TYPE", max: 28, value: func(a view.Alert) string { return a.AlertType }},
		{key: "rule_id", header: "RULE_ID", value: func(a view.Alert) string { return a.RuleID }},
		{key: "revision", header: "REV", value: func(a view.Alert) string { return strconv.Itoa(a.Revision) }},
	}
}

func alertTableColumns(fields string) ([]column[view.Alert], error) {
	defaults := []string{"event_time", "severity", "provider", "title", "resource", "source_ip", "status", "id"}
	return selectColumns(alertAllColumns(), defaults, fields)
}

func groupAllColumns() []column[model.AlertGroup] {
	return []column[model.AlertGroup]{
		{key: "id", header: "GROUP_ID", value: func(g model.AlertGroup) string { return g.ID }},
		{key: "asset_count", header: "ASSETS", value: func(g model.AlertGroup) string {
			if !g.GroupBy.UsesAssetContext() {
				return "—"
			}
			return strconv.Itoa(g.AssetCount)
		}},
		{key: "finding_count", header: "COUNT", value: func(g model.AlertGroup) string { return strconv.Itoa(g.FindingCount) }},
		{key: "max_severity", header: "MAX_SEV", value: func(g model.AlertGroup) string { return g.MaxSeverity.String() }},
		{key: "title", header: "TITLE", max: 52, value: func(g model.AlertGroup) string { return g.Title }},
		{key: "resource", header: "RESOURCE", max: 36, value: func(g model.AlertGroup) string {
			return firstNonEmpty(g.ResourceName, g.ResourceID)
		}},
		{key: "source_ip", header: "SRC", value: func(g model.AlertGroup) string { return g.SourceIP }},
		{key: "first_seen_at", header: "FIRST_SEEN", value: func(g model.AlertGroup) string { return shortTimePtr(g.FirstSeenAt) }},
		{key: "last_seen_at", header: "LAST_SEEN", value: func(g model.AlertGroup) string { return shortTimePtr(g.LastSeenAt) }},
		{key: "group_by", header: "GROUP_BY", value: func(g model.AlertGroup) string { return string(g.GroupBy) }},
	}
}

func groupTableColumns(fields string) ([]column[model.AlertGroup], error) {
	defaults := []string{"finding_count", "asset_count", "max_severity", "title", "resource", "source_ip", "last_seen_at", "id"}
	return selectColumns(groupAllColumns(), defaults, fields)
}

func changeAllColumns() []column[model.AlertChange] {
	return []column[model.AlertChange]{
		{key: "sequence", header: "SEQ", value: func(c model.AlertChange) string { return strconv.FormatInt(c.Sequence, 10) }},
		{key: "change_type", header: "CHANGE", value: func(c model.AlertChange) string { return c.ChangeType }},
		{key: "provider", header: "PROVIDER", value: func(c model.AlertChange) string { return c.Provider }},
		{key: "account_id", header: "ACCOUNT", value: func(c model.AlertChange) string { return c.AccountID }},
		{key: "alert_id", header: "ALERT_ID", value: func(c model.AlertChange) string { return c.AlertID }},
		{key: "revision", header: "REV", value: func(c model.AlertChange) string { return strconv.Itoa(c.Revision) }},
		{key: "captured_at", header: "CAPTURED_AT", value: func(c model.AlertChange) string { return shortTimeValue(c.CapturedAt) }},
		{key: "projection_updated", header: "PROJECTED", value: func(c model.AlertChange) string { return strconv.FormatBool(c.ProjectionUpdated) }},
	}
}

func changeTableColumns(fields string) ([]column[model.AlertChange], error) {
	defaults := []string{"sequence", "change_type", "provider", "alert_id", "revision", "captured_at"}
	return selectColumns(changeAllColumns(), defaults, fields)
}

func assetAllColumns() []column[model.Asset] {
	return []column[model.Asset]{
		{key: "id", header: "ASSET_ID", value: func(a model.Asset) string { return a.ID }},
		{key: "resource_type", header: "TYPE", value: func(a model.Asset) string { return a.ResourceType }},
		{key: "resource_id", header: "RESOURCE_ID", value: func(a model.Asset) string { return a.ResourceID }},
		{key: "name", header: "NAME", max: 40, value: func(a model.Asset) string { return a.Name }},
		{key: "region", header: "REGION", value: func(a model.Asset) string { return a.Region }},
		{key: "account_id", header: "ACCOUNT", value: func(a model.Asset) string { return a.AccountID }},
		{key: "state", header: "STATE", value: func(a model.Asset) string { return a.State }},
		{key: "public_ips", header: "PUBLIC_IPS", value: func(a model.Asset) string { return strings.Join(a.PublicIPs, ",") }},
		{key: "private_ips", header: "PRIVATE_IPS", value: func(a model.Asset) string { return strings.Join(a.PrivateIPs, ",") }},
		{key: "last_observed_at", header: "OBSERVED", value: func(a model.Asset) string { return shortTimeValue(a.LastObservedAt) }},
		{key: "revision", header: "REV", value: func(a model.Asset) string { return strconv.Itoa(a.Revision) }},
	}
}

func assetTableColumns(fields string) ([]column[model.Asset], error) {
	defaults := []string{"resource_type", "resource_id", "name", "region", "account_id", "state", "last_observed_at", "revision"}
	return selectColumns(assetAllColumns(), defaults, fields)
}

func revisionAllColumns() []column[view.Revision] {
	return []column[view.Revision]{
		{key: "revision", header: "REV", value: func(r view.Revision) string { return strconv.Itoa(r.Revision) }},
		{key: "change_type", header: "CHANGE", value: func(r view.Revision) string { return r.ChangeType }},
		{key: "captured_at", header: "CAPTURED_AT", value: func(r view.Revision) string { return shortTime(r.CapturedAt) }},
		{key: "mapper_version", header: "MAPPER", value: func(r view.Revision) string { return r.MapperVersion }},
		{key: "raw_hash", header: "RAW_HASH", max: 12, value: func(r view.Revision) string { return r.RawHash }},
		{key: "projection_updated", header: "PROJECTED", value: func(r view.Revision) string { return strconv.FormatBool(r.ProjectionUpdated) }},
		{key: "id", header: "ID", value: func(r view.Revision) string { return r.ID }},
	}
}

func revisionTableColumns(fields string) ([]column[view.Revision], error) {
	defaults := []string{"revision", "change_type", "captured_at", "mapper_version", "raw_hash", "projection_updated"}
	return selectColumns(revisionAllColumns(), defaults, fields)
}

func healthAllColumns() []column[view.Account] {
	state := func(a view.Account) view.SyncState {
		if a.SyncState == nil {
			return view.SyncState{}
		}
		return *a.SyncState
	}
	return []column[view.Account]{
		{key: "id", header: "ACCOUNT_ID", value: func(a view.Account) string { return a.ID }},
		{key: "name", header: "ACCOUNT", max: 28, value: func(a view.Account) string { return a.Name }},
		{key: "provider", header: "PROVIDER", value: func(a view.Account) string { return a.Provider }},
		{key: "enabled", header: "ENABLED", value: func(a view.Account) string { return strconv.FormatBool(a.Enabled) }},
		{key: "status", header: "STATUS", value: func(a view.Account) string { return state(a).Status }},
		{key: "last_success_at", header: "LAST_SUCCESS", value: func(a view.Account) string { return shortTime(state(a).LastSuccessAt) }},
		{key: "failed_records", header: "FAILED", value: func(a view.Account) string { return strconv.Itoa(state(a).FailedRecords) }},
		{key: "consecutive_failures", header: "FAILS", value: func(a view.Account) string { return strconv.Itoa(state(a).ConsecutiveFailures) }},
		{key: "pending", header: "PENDING", value: func(a view.Account) string { return strconv.FormatBool(state(a).Pending) }},
		{key: "last_error", header: "ERROR", max: 48, value: func(a view.Account) string { return state(a).LastError }},
	}
}

func healthTableColumns(fields string) ([]column[view.Account], error) {
	defaults := []string{"name", "provider", "enabled", "status", "last_success_at", "failed_records", "last_error"}
	return selectColumns(healthAllColumns(), defaults, fields)
}

func coverageAllColumns() []column[model.AccountCoverage] {
	scope := func(c model.AccountCoverage) string {
		if len(c.Scope) == 0 {
			return ""
		}
		keys := make([]string, 0, len(c.Scope))
		for key := range c.Scope {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, key+"="+c.Scope[key])
		}
		return strings.Join(parts, ",")
	}
	return []column[model.AccountCoverage]{
		{key: "name", header: "ACCOUNT", max: 28, value: func(c model.AccountCoverage) string { return c.Name }},
		{key: "provider", header: "PROVIDER", value: func(c model.AccountCoverage) string { return c.Provider }},
		{key: "status", header: "STATUS", value: func(c model.AccountCoverage) string { return c.Status }},
		{key: "complete", header: "COMPLETE", value: func(c model.AccountCoverage) string { return strconv.FormatBool(c.Complete) }},
		{key: "coverage_start", header: "FROM", value: func(c model.AccountCoverage) string { return shortTimePtr(c.CoverageStart) }},
		{key: "watermark", header: "WATERMARK", value: func(c model.AccountCoverage) string { return shortTimePtr(c.Watermark) }},
		{key: "last_success_at", header: "LAST_SUCCESS", value: func(c model.AccountCoverage) string { return shortTimePtr(c.LastSuccessAt) }},
		{key: "failed_records", header: "FAILED", value: func(c model.AccountCoverage) string { return strconv.Itoa(c.FailedRecords) }},
		{key: "scope", header: "SCOPE", max: 48, value: scope},
		{key: "last_error", header: "ERROR", max: 40, value: func(c model.AccountCoverage) string { return c.LastError }},
	}
}

func renderAlertDetail(w io.Writer, a view.Alert) error {
	pairs := [][2]string{
		{"id", a.ID},
		{"title", a.Title},
		{"severity", a.Severity},
		{"status", a.Status},
		{"provider", a.Provider},
		{"account", firstNonEmpty(a.AccountName, a.AccountID)},
		{"event_time", shortTime(a.EventTime)},
		{"first_seen", shortTime(a.FirstSeenAt)},
		{"last_seen", shortTime(a.LastSeenAt)},
		{"resource", firstNonEmpty(a.Resource.Name, a.Resource.ID)},
		{"resource_type", a.Resource.Type},
		{"resource_id", a.Resource.ID},
		{"resource_account", a.Resource.AccountUID},
		{"resource_source", a.Resource.Source},
		{"source_ip", a.SourceIP},
		{"source_location", a.SourceLocation},
		{"source_country", a.SourceCountry},
		{"destination_ip", a.DestinationIP},
		{"response_action", a.ResponseAction},
		{"alert_type", a.AlertType},
		{"rule_id", a.RuleID},
		{"finding_kind", a.FindingKind},
		{"vendor_status", a.VendorStatus},
		{"revision", strconv.Itoa(a.Revision)},
		{"sequence", strconv.FormatInt(a.Sequence, 10)},
		{"raw_url", a.RawURL},
	}
	if err := renderDetail(w, pairs); err != nil {
		return err
	}
	if a.Description != "" {
		fmt.Fprintf(w, "\n%s\n", strings.TrimSpace(a.Description))
	}
	if len(a.Observables) > 0 {
		fmt.Fprintf(w, "\nobservables (%d)\n", len(a.Observables))
		for i, item := range a.Observables {
			if i >= 20 {
				fmt.Fprintf(w, "  ... %d more\n", len(a.Observables)-20)
				break
			}
			fmt.Fprintf(w, "  %-12s %s\n", clean(item.Type), clean(item.Value))
		}
	}
	if len(a.Evidences) > 0 {
		fmt.Fprintf(w, "\nevidences (%d)\n", len(a.Evidences))
		for i, item := range a.Evidences {
			if i >= 20 {
				fmt.Fprintf(w, "  ... %d more\n", len(a.Evidences)-20)
				break
			}
			fmt.Fprintf(w, "  %s\n", clean(item.Type))
		}
	}
	fmt.Fprintln(w, "\nUse --json for the full OCSF and raw payloads.")
	return nil
}

func renderDetail(w io.Writer, pairs [][2]string) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, pair := range pairs {
		if strings.TrimSpace(pair[1]) == "" {
			continue
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\n", pair[0], clean(pair[1])); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func renderAssetDetail(w io.Writer, a model.Asset) error {
	tags := make([]string, 0, len(a.Tags))
	for _, tag := range a.Tags {
		tags = append(tags, tag.Key+"="+tag.Value)
	}
	pairs := [][2]string{
		{"id", a.ID},
		{"resource_type", a.ResourceType},
		{"resource_id", a.ResourceID},
		{"name", a.Name},
		{"provider", a.Provider},
		{"account_id", a.AccountID},
		{"account_uid", a.AccountUID},
		{"region", a.Region},
		{"zone", a.Zone},
		{"state", a.State},
		{"os", a.OS},
		{"instance_type", a.InstanceType},
		{"public_ips", strings.Join(a.PublicIPs, ",")},
		{"private_ips", strings.Join(a.PrivateIPs, ",")},
		{"vpc_id", a.VPCID},
		{"subnet_id", a.SubnetID},
		{"security_groups", strings.Join(a.SecurityGroupIDs, ",")},
		{"tags", strings.Join(tags, ",")},
		{"observed_at", shortTimeValue(a.ObservedAt)},
		{"last_observed_at", shortTimeValue(a.LastObservedAt)},
		{"revision", strconv.Itoa(a.Revision)},
		{"mapper_version", a.MapperVersion},
		{"synthetic", strconv.FormatBool(a.Synthetic)},
	}
	if a.Network != nil {
		pairs = append(pairs,
			[2]string{"network_cidr", a.Network.CIDRBlock},
			[2]string{"network_ipv6_cidr", a.Network.IPv6CIDRBlock},
			[2]string{"network_description", a.Network.Description},
		)
	}
	if err := renderDetail(w, pairs); err != nil {
		return err
	}
	if len(a.Components) > 0 {
		keys := make([]string, 0, len(a.Components))
		for key := range a.Components {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		fmt.Fprintf(w, "\ncomponents (%d)\n", len(keys))
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "COMPONENT\tSTATUS\tOBSERVED\tRAW")
		for _, key := range keys {
			component := a.Components[key]
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", key, component.Status, shortTimePtr(component.ObservedAt), component.RawURL)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(a.References) > 0 {
		fmt.Fprintf(w, "\nreferences (%d)\n", len(a.References))
		for i, ref := range a.References {
			if i >= 10 {
				fmt.Fprintf(w, "  ... %d more\n", len(a.References)-10)
				break
			}
			fmt.Fprintf(w, "  %-18s %s/%s\n", clean(ref.Relation), clean(ref.ResourceType), clean(ref.ResourceID))
		}
	}
	fmt.Fprintln(w, "\nUse --json for provenance and full component metadata.")
	return nil
}

func renderAssetLookup(w io.Writer, result assetLookupResponse) error {
	fmt.Fprintf(w, "status %s\n", clean(result.Status))
	if result.Asset != nil {
		fmt.Fprintln(w)
		if err := renderAssetDetail(w, *result.Asset); err != nil {
			return err
		}
	}
	renderAssetScope(w, result.Scope)
	if result.Refresh != nil {
		fmt.Fprintf(w, "\nrefresh %s at %s\n", clean(result.Refresh.Status), shortTimeValue(result.Refresh.AttemptedAt))
		renderSourceError(w, result.Refresh.SourceError)
	}
	if len(result.Limitations) > 0 {
		fmt.Fprintf(w, "\nlimitations: %s\n", joinLimited(result.Limitations, 5))
	}
	return nil
}

func renderAssetContext(w io.Writer, context query.AssetContext) error {
	pairs := [][2]string{
		{"alert_id", context.AlertID},
		{"alert_revision", strconv.Itoa(context.AlertRevision)},
		{"status", context.Status},
		{"reason", context.Reason},
		{"resource_id", context.ResourceID},
		{"matched_on", strings.Join(context.MatchedOn, ",")},
	}
	if err := renderDetail(w, pairs); err != nil {
		return err
	}
	renderAssetScope(w, context.Scope)
	if context.Asset != nil {
		fmt.Fprintln(w)
		if err := renderAssetDetail(w, *context.Asset); err != nil {
			return err
		}
	}
	if context.Refresh != nil {
		fmt.Fprintf(w, "\nrefresh %s at %s\n", clean(context.Refresh.Status), shortTimeValue(context.Refresh.AttemptedAt))
		renderSourceError(w, context.Refresh.SourceError)
	}
	if len(context.Limitations) > 0 {
		fmt.Fprintf(w, "\nlimitations: %s\n", joinLimited(context.Limitations, 5))
	}
	return nil
}

func renderAssetScope(w io.Writer, scope *query.AssetScope) {
	if scope == nil {
		return
	}
	pairs := [][2]string{
		{"provider", scope.Provider},
		{"account_uid", scope.AccountUID},
		{"region", scope.Region},
		{"resource_type", scope.ResourceType},
		{"resource_id", scope.ResourceID},
		{"source_api", scope.SourceAPI},
		{"api_version", scope.APIVersion},
	}
	fmt.Fprintln(w, "\nattempted scope")
	_ = renderDetail(w, pairs)
}

func renderSourceError(w io.Writer, sourceError *model.SourceError) {
	if sourceError == nil {
		return
	}
	pairs := [][2]string{
		{"provider", sourceError.Provider},
		{"kind", sourceError.Kind},
		{"code", sourceError.Code},
	}
	if sourceError.HTTPStatus > 0 {
		pairs = append(pairs, [2]string{"http_status", strconv.Itoa(sourceError.HTTPStatus)})
	}
	pairs = append(pairs, [2]string{"source_api", sourceError.SourceAPI})
	fmt.Fprintln(w, "source_error")
	_ = renderDetail(w, pairs)
}

func printCoverage(w io.Writer, coverage *model.Coverage) {
	if coverage != nil && !coverage.Complete {
		fmt.Fprint(w, ", coverage incomplete")
	}
}

func renderStats(w io.Writer, stats statsResponse) error {
	fmt.Fprintf(w, "total %d\n", stats.Statistics.Total)
	if stats.Window.Start != "" {
		fmt.Fprintf(w, "window %s .. %s\n", shortTime(stats.Window.Start), shortTime(stats.Window.End))
	}
	if stats.SnapshotSequence != nil {
		fmt.Fprintf(w, "snapshot %d\n", *stats.SnapshotSequence)
	}
	if stats.Coverage != nil && !stats.Coverage.Complete {
		fmt.Fprintln(w, "coverage incomplete")
	}
	renderCounts(w, "by_severity", stats.Statistics.BySeverity, severityKeys(stats.Statistics.BySeverity))
	renderCounts(w, "by_provider", stats.Statistics.ByProvider, countKeys(stats.Statistics.ByProvider))
	renderCounts(w, "by_status", stats.Statistics.ByStatus, countKeys(stats.Statistics.ByStatus))
	if len(stats.Statistics.ByDay) > 0 {
		fmt.Fprintln(w, "\nby_day")
		for _, item := range stats.Statistics.ByDay {
			fmt.Fprintf(w, "  %-12s %d\n", item.Day, item.Count)
		}
	}
	if len(stats.Statistics.TopResources) > 0 {
		fmt.Fprintln(w, "\ntop_resources")
		for _, item := range stats.Statistics.TopResources {
			label := item.Key
			if item.Name != "" {
				label += " (" + item.Name + ")"
			}
			fmt.Fprintf(w, "  %-40s %d\n", truncate(clean(label), 40), item.Count)
		}
	}
	return nil
}

func renderCounts(w io.Writer, title string, values map[string]int, keys []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(w, "\n%s\n", title)
	for _, key := range keys {
		fmt.Fprintf(w, "  %-12s %d\n", key, values[key])
	}
}

func countKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if values[keys[i]] != values[keys[j]] {
			return values[keys[i]] > values[keys[j]]
		}
		return keys[i] < keys[j]
	})
	return keys
}

func severityKeys(values map[string]int) []string {
	order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "fatal": 5, "unknown": 6}
	keys := countKeys(values)
	sort.SliceStable(keys, func(i, j int) bool {
		left, leftOK := order[keys[i]]
		right, rightOK := order[keys[j]]
		if !leftOK {
			left = 99
		}
		if !rightOK {
			right = 99
		}
		return left < right
	})
	return keys
}

func renderCoverage(w io.Writer, coverage model.Coverage) error {
	fmt.Fprintf(w, "complete %v\n", coverage.Complete)
	fmt.Fprintf(w, "boundary %s\n\n", clean(coverage.Boundary))
	if len(coverage.Accounts) == 0 {
		fmt.Fprintln(w, "No accounts.")
		return nil
	}
	columns, err := selectColumns(coverageAllColumns(), []string{"name", "provider", "status", "complete", "watermark", "failed_records", "last_error"}, "")
	if err != nil {
		return err
	}
	return renderTable(w, columns, coverage.Accounts)
}

func renderHealth(w io.Writer, columns []column[view.Account], health healthResponse) error {
	fmt.Fprintf(w, "status %s, database %s, version %s\n\n", clean(health.Status), clean(health.Database), clean(health.Version))
	if len(health.Accounts) == 0 {
		fmt.Fprintln(w, "No accounts.")
		return nil
	}
	return renderTable(w, columns, health.Accounts)
}

func renderAccountHealth(w io.Writer, health accountHealthResponse) error {
	pairs := [][2]string{
		{"status", health.Status},
		{"account", health.Account.Name},
		{"provider", health.Account.Provider},
		{"enabled", strconv.FormatBool(health.Account.Enabled)},
		{"sync_status", health.SyncState.Status},
		{"healthy", strconv.FormatBool(health.SyncState.Healthy)},
		{"last_success", shortTime(health.SyncState.LastSuccessAt)},
		{"coverage_start", shortTime(health.SyncState.CoverageStart)},
		{"cursor_end", shortTime(health.SyncState.CursorEnd)},
		{"failed_records", strconv.Itoa(health.SyncState.FailedRecords)},
		{"consecutive_failures", strconv.Itoa(health.SyncState.ConsecutiveFailures)},
		{"pending", strconv.FormatBool(health.SyncState.Pending)},
		{"last_error", health.SyncState.LastError},
	}
	if err := renderDetail(w, pairs); err != nil {
		return err
	}
	if len(health.RecentRuns) > 0 {
		fmt.Fprintf(w, "\nrecent_runs (%d)\n", len(health.RecentRuns))
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "STARTED\tSTATUS\tTRIGGER\tFETCHED\tCREATED\tUPDATED\tFAILED\tDURATION_MS\tERROR")
		for _, run := range health.RecentRuns {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n",
				shortTime(run.StartedAt), run.Status, run.Trigger, run.Fetched, run.Created, run.Updated, run.Failed, run.DurationMS, truncate(clean(run.Error), 48))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	return nil
}
