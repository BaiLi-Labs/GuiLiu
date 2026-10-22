package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/timeutil"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

type filterOptions struct {
	defaultSince string
	paging       bool
	groupBy      bool
	expandGroup  bool
}

type alertFilterFlags struct {
	provider        string
	accountID       string
	severity        string
	status          string
	keyword         string
	ip              string
	resource        string
	sort            string
	timeField       string
	ruleID          string
	findingKind     string
	vendorStatus    string
	observableValue string
	observableType  int
	snapshot        int64
	assetSnapshot   int64
	vendorTitle     string
	afterID         string
	limit           int
	offset          int
	since           string
	start           string
	end             string
	groupBy         string
	groupKey        string
	all             bool
	maxItems        int

	fs            *flagSet
	defaultSince  string
	resolved      bool
	resolvedStart string
	resolvedEnd   string
}

func (f *alertFilterFlags) register(fs *flagSet, opts filterOptions) {
	f.fs = fs
	f.defaultSince = opts.defaultSince
	if f.defaultSince == "" {
		f.defaultSince = "7d"
	}
	f.snapshot = -1
	f.assetSnapshot = -1
	f.maxItems = query.AgentDefaultMaxItems
	if opts.paging {
		f.limit = 20
	}

	fs.String(&f.provider, "provider", "", "Provider id, e.g. tencent")
	fs.String(&f.accountID, "account", "", "Configured account ID")
	fs.String(&f.severity, "severity", "", "Comma-separated severities: informational,low,medium,high,critical")
	fs.String(&f.status, "status", "", "Comma-separated platform statuses: open,acknowledged,suppressed,closed")
	fs.String(&f.keyword, "keyword", "", "Full-text search across title, description, alert type and asset name")
	fs.String(&f.keyword, "q", "", "Alias for --keyword")
	fs.String(&f.ip, "ip", "", "Exact source, destination or observable IP")
	fs.String(&f.resource, "resource", "", "Asset ID (exact) or asset name (substring)")
	fs.String(&f.timeField, "time-field", "", "event_time (default), source_updated_at or ingested_at")
	fs.Int64(&f.snapshot, "snapshot-sequence", -1, "Reuse a returned Finding snapshot for queries and statistics")
	fs.String(&f.vendorTitle, "vendor-title", "", "Exact source-reported finding title (statistical equality)")
	fs.String(&f.ruleID, "rule-id", "", "Exact native rule ID, scoped by provider and product")
	fs.String(&f.findingKind, "finding-kind", "", "detection, vulnerability, compliance, incident or other")
	fs.String(&f.vendorStatus, "vendor-status", "", "Exact source status, independent of local annotation")
	fs.String(&f.observableValue, "observable-value", "", "Exact typed observable value: IP, domain, hash, account, user or resource")
	fs.Int(&f.observableType, "observable-type", -1, "OCSF observable type ID; requires --observable-value")
	if opts.paging {
		fs.String(&f.sort, "sort", "", "event_time (default), severity, last_seen, first_seen or id")
		fs.Int(&f.limit, "limit", 20, fmt.Sprintf("Records per page (1-%d)", query.AgentMaxPageSize))
		fs.Int(&f.offset, "offset", 0, "Page offset")
		if !opts.groupBy {
			fs.String(&f.afterID, "after-id", "", "Continue an ID-sorted snapshot using next_cursor")
		}
		fs.Int64(&f.assetSnapshot, "asset-snapshot-sequence", -1, "Reuse the returned asset watermark for stable network groups")
		fs.Bool(&f.all, "all", false, "Follow pages until exhausted or --max-items")
		fs.Int(&f.maxItems, "max-items", query.AgentDefaultMaxItems, "Maximum records emitted with --all")
	}
	groupDefault := ""
	groupUsage := "Expand a group returned by the groups command: asset, name_asset, vpc, subnet, security_group, nic, type_asset, signature or source"
	if opts.groupBy {
		groupDefault = "asset"
		groupUsage = "Exact-field grouping: asset (default), name_asset, vpc, subnet, security_group, nic, type_asset, signature or source"
	}
	if opts.groupBy || opts.expandGroup {
		fs.String(&f.groupBy, "group-by", groupDefault, groupUsage)
	}
	if opts.groupBy || opts.expandGroup {
		fs.String(&f.groupKey, "group-key", "", `Group key as a JSON object, e.g. '{"provider":"tencent",...}'`)
	}
	fs.String(&f.since, "since", f.defaultSince, "Relative window, e.g. 24h or 7d (bounded to 90 days)")
	fs.String(&f.start, "start", "", "Start time (RFC3339 or YYYY-MM-DD); do not combine with --since")
	fs.String(&f.end, "end", "", "End time (RFC3339 or YYYY-MM-DD); defaults to now")
}

func (f *alertFilterFlags) pinWindow(start, end string) {
	if start == "" || end == "" {
		return
	}
	f.resolved = true
	f.resolvedStart = start
	f.resolvedEnd = end
}

func (f *alertFilterFlags) pinSnapshot(seq *int64) {
	if seq != nil {
		f.snapshot = *seq
	}
}

func (f *alertFilterFlags) values(now time.Time) (url.Values, error) {
	if f.offset < 0 {
		return nil, fmt.Errorf("offset must be non-negative")
	}
	if f.afterID != "" && f.offset != 0 {
		return nil, fmt.Errorf("use --after-id or --offset, not both")
	}
	if f.assetSnapshot < -1 {
		return nil, fmt.Errorf("invalid asset_snapshot_sequence")
	}
	if f.snapshot < -1 {
		return nil, fmt.Errorf("invalid snapshot_sequence")
	}
	if f.observableType < -1 {
		return nil, fmt.Errorf("invalid observable_type")
	}
	if !f.resolved {
		since := f.since
		startSet, endSet, sinceSet := f.fs.Changed("start"), f.fs.Changed("end"), f.fs.Changed("since")
		if !sinceSet && (startSet || endSet) {
			since = ""
		}
		window := query.AgentAlertWindow
		if d, ok := timeutil.ParseDuration(f.defaultSince); ok {
			window = d
		}
		start, end, err := query.ResolveWindow(f.start, f.end, since, window, now)
		if err != nil {
			return nil, err
		}
		f.resolvedStart = timeutil.Format(*start)
		f.resolvedEnd = timeutil.Format(*end)
		f.resolved = true
	}

	values := url.Values{}
	values.Set("start", f.resolvedStart)
	values.Set("end", f.resolvedEnd)
	setValue(values, "provider", f.provider)
	setValue(values, "account_id", f.accountID)
	setValue(values, "severity", f.severity)
	setValue(values, "status", f.status)
	setValue(values, "keyword", f.keyword)
	setValue(values, "ip", f.ip)
	setValue(values, "resource", f.resource)
	setValue(values, "sort", f.sort)
	setValue(values, "time_field", f.timeField)
	setValue(values, "vendor_title", f.vendorTitle)
	if f.assetSnapshot >= 0 {
		values.Set("asset_snapshot_sequence", strconv.FormatInt(f.assetSnapshot, 10))
	}
	setValue(values, "rule_id", f.ruleID)
	setValue(values, "finding_kind", f.findingKind)
	setValue(values, "vendor_status", f.vendorStatus)
	setValue(values, "observable_value", f.observableValue)
	if f.observableType >= 0 {
		values.Set("observable_type", strconv.Itoa(f.observableType))
	}
	if f.snapshot >= 0 {
		values.Set("snapshot_sequence", strconv.FormatInt(f.snapshot, 10))
	}
	if f.limit > 0 {
		values.Set("limit", strconv.Itoa(f.limit))
		values.Set("offset", strconv.Itoa(f.offset))
	}
	setValue(values, "after_id", f.afterID)
	setValue(values, "group_by", f.groupBy)
	setValue(values, "group_key", f.groupKey)
	return values, nil
}

func setValue(values url.Values, key, value string) {
	if value != "" {
		values.Set(key, value)
	}
}

func validatePaging(out *outputOptions, all bool, afterID string, limit, maxItems int) error {
	if out.JSON && all {
		return usagef("--all requires table or --ndjson; use --limit for one JSON page")
	}
	if all && afterID != "" {
		return usagef("use --all or --after-id, not both")
	}
	if limit < 1 || limit > query.AgentMaxPageSize {
		return usagef("--limit must be between 1 and %d", query.AgentMaxPageSize)
	}
	if maxItems < 1 {
		return usagef("--max-items must be positive")
	}
	return nil
}

type alertListResponse struct {
	Alerts                []view.Alert     `json:"alerts"`
	Total                 int              `json:"total"`
	Limit                 int              `json:"limit"`
	Offset                int              `json:"offset"`
	AssetSnapshotSequence *int64           `json:"asset_snapshot_sequence"`
	SnapshotSequence      *int64           `json:"snapshot_sequence"`
	NextCursor            string           `json:"next_cursor"`
	HasMore               bool             `json:"has_more"`
	Window                view.QueryWindow `json:"window"`
	Coverage              *model.Coverage  `json:"coverage"`
}

func newAlertsCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("alerts", io.Discard)
	registerGlobalFlags(fs, g)
	var filters alertFilterFlags
	filters.register(fs, filterOptions{defaultSince: "7d", paging: true, expandGroup: true})
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		return runAlerts(ctx, c, out, &filters, stdout, stderr)
	}
}

func runAlerts(ctx context.Context, c *client, out *outputOptions, f *alertFilterFlags, stdout, stderr io.Writer) error {
	if err := validatePaging(out, f.all, f.afterID, f.limit, f.maxItems); err != nil {
		return err
	}
	columns, err := alertTableColumns(out.tableFields())
	if err != nil {
		return err
	}
	var items []view.Alert
	var last alertListResponse
	offset := f.offset
	emitted := 0
	truncated := false
	for {
		f.offset = offset
		params, err := f.values(time.Now())
		if err != nil {
			return usagef("%v", err)
		}
		body, err := c.get(ctx, "/alerts", params)
		if err != nil {
			return err
		}
		page, err := decode[alertListResponse](body)
		if err != nil {
			return err
		}
		last = page
		f.pinWindow(page.Window.Start, page.Window.End)
		f.pinSnapshot(page.SnapshotSequence)
		if page.AssetSnapshotSequence != nil {
			f.assetSnapshot = *page.AssetSnapshotSequence
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		batch := page.Alerts
		if f.all && emitted+len(batch) > f.maxItems {
			batch = batch[:f.maxItems-emitted]
			truncated = true
			last.Offset = offset
			last.Limit = len(batch)
		}
		if out.NDJSON {
			if err := emitNDJSON(stdout, batch, out.Fields); err != nil {
				return err
			}
		} else {
			items = append(items, batch...)
		}
		emitted += len(batch)
		if !f.all || len(batch) == 0 || !page.HasMore || emitted >= f.maxItems {
			break
		}
		offset += len(page.Alerts)
	}
	if !out.NDJSON && len(items) > 0 {
		if err := renderTable(stdout, columns, items); err != nil {
			return err
		}
	}
	if out.Quiet {
		return nil
	}
	fmt.Fprintf(stderr, "%d alert(s)", emitted)
	if last.Total > 0 {
		fmt.Fprintf(stderr, " of %d", last.Total)
	}
	printWindow(stderr, last.Window)
	if last.SnapshotSequence != nil {
		fmt.Fprintf(stderr, ", snapshot %d", *last.SnapshotSequence)
	}
	if last.AssetSnapshotSequence != nil {
		fmt.Fprintf(stderr, ", asset snapshot %d", *last.AssetSnapshotSequence)
	}
	printCoverage(stderr, last.Coverage)
	if f.all {
		if truncated || (emitted >= f.maxItems && last.HasMore) {
			fmt.Fprintf(stderr, ", stopped at --max-items, next offset %d", last.Offset+last.Limit)
		}
		fmt.Fprintln(stderr)
		return nil
	}
	if last.HasMore {
		fmt.Fprintf(stderr, ", next offset %d", last.Offset+last.Limit)
	}
	fmt.Fprintln(stderr)
	return nil
}

func printWindow(w io.Writer, window view.QueryWindow) {
	if window.Start == "" || window.End == "" {
		return
	}
	fmt.Fprintf(w, ", window %s .. %s", shortTime(window.Start), shortTime(window.End))
}

func newAlertCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("alert", io.Discard)
	registerGlobalFlags(fs, g)
	var raw bool
	var revision int
	var snapshot int64
	fs.Bool(&raw, "raw", false, "Print the exact vendor JSON instead of the normalized alert")
	fs.Int(&revision, "revision", 0, "Exact immutable revision")
	fs.Int64(&snapshot, "snapshot-sequence", -1, "Read the alert from a pinned snapshot")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if fs.NArg() != 1 {
			return usagef("usage: %s", "guiliu query alert <alert-id> [flags]")
		}
		if revision > 0 && snapshot >= 0 {
			return usagef("use --revision or --snapshot-sequence, not both")
		}
		if out.NDJSON {
			return usagef("--ndjson is not supported for one alert")
		}
		if out.Fields != "" {
			return usagef("--fields is not supported for one alert; use --json with jq")
		}
		if raw {
			if out.JSON || out.Pretty {
				return usagef("--raw writes exact bytes; do not combine it with --json or --pretty")
			}
			params := url.Values{}
			if revision > 0 {
				params.Set("revision", strconv.Itoa(revision))
			}
			if snapshot >= 0 {
				params.Set("snapshot_sequence", strconv.FormatInt(snapshot, 10))
			}
			body, err := c.get(ctx, "/alerts/"+url.PathEscape(fs.Arg(0))+"/raw", params)
			if err != nil {
				return err
			}
			return emitRaw(stdout, body)
		}
		params := url.Values{}
		if revision > 0 {
			params.Set("revision", strconv.Itoa(revision))
		}
		if snapshot >= 0 {
			params.Set("snapshot_sequence", strconv.FormatInt(snapshot, 10))
		}
		body, err := c.get(ctx, "/alerts/"+url.PathEscape(fs.Arg(0)), params)
		if err != nil {
			return err
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		alert, err := decode[view.Alert](body)
		if err != nil {
			return err
		}
		return renderAlertDetail(stdout, alert)
	}
}

type groupListResponse struct {
	Groups                []model.AlertGroup     `json:"groups"`
	Total                 int                    `json:"total"`
	Limit                 int                    `json:"limit"`
	Offset                int                    `json:"offset"`
	AssetSnapshotSequence *int64                 `json:"asset_snapshot_sequence"`
	SnapshotSequence      *int64                 `json:"snapshot_sequence"`
	Window                view.QueryWindow       `json:"window"`
	GroupBy               string                 `json:"group_by"`
	Coverage              *model.Coverage        `json:"coverage"`
	Summary               *model.GroupingSummary `json:"summary"`
	Limitations           []string               `json:"limitations"`
}

func newGroupsCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("groups", io.Discard)
	registerGlobalFlags(fs, g)
	var filters alertFilterFlags
	filters.register(fs, filterOptions{defaultSince: "24h", paging: true, groupBy: true})
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		return runGroups(ctx, c, out, &filters, stdout, stderr)
	}
}

func runGroups(ctx context.Context, c *client, out *outputOptions, f *alertFilterFlags, stdout, stderr io.Writer) error {
	if err := validatePaging(out, f.all, "", f.limit, f.maxItems); err != nil {
		return err
	}
	columns, err := groupTableColumns(out.tableFields())
	if err != nil {
		return err
	}
	var items []model.AlertGroup
	var last groupListResponse
	offset := f.offset
	emitted := 0
	truncated := false
	for {
		f.offset = offset
		params, err := f.values(time.Now())
		if err != nil {
			return usagef("%v", err)
		}
		body, err := c.get(ctx, "/alerts/groups", params)
		if err != nil {
			return err
		}
		page, err := decode[groupListResponse](body)
		if err != nil {
			return err
		}
		last = page
		f.pinWindow(page.Window.Start, page.Window.End)
		f.pinSnapshot(page.SnapshotSequence)
		if page.AssetSnapshotSequence != nil {
			f.assetSnapshot = *page.AssetSnapshotSequence
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		batch := page.Groups
		if f.all && emitted+len(batch) > f.maxItems {
			batch = batch[:f.maxItems-emitted]
			truncated = true
			last.Offset = offset
			last.Limit = len(batch)
		}
		if out.NDJSON {
			if err := emitNDJSON(stdout, batch, out.Fields); err != nil {
				return err
			}
		} else {
			items = append(items, batch...)
		}
		emitted += len(batch)
		if !f.all || len(batch) == 0 || emitted >= f.maxItems || page.Offset+len(page.Groups) >= page.Total {
			break
		}
		offset += len(page.Groups)
	}
	if !out.NDJSON && len(items) > 0 {
		if err := renderTable(stdout, columns, items); err != nil {
			return err
		}
	}
	if out.Quiet {
		return nil
	}
	fmt.Fprintf(stderr, "%d group(s)", emitted)
	if last.Total > 0 {
		fmt.Fprintf(stderr, " of %d", last.Total)
	}
	fmt.Fprintf(stderr, ", group_by %s", last.GroupBy)
	printWindow(stderr, last.Window)
	if last.SnapshotSequence != nil {
		fmt.Fprintf(stderr, ", snapshot %d", *last.SnapshotSequence)
	}
	if last.AssetSnapshotSequence != nil {
		fmt.Fprintf(stderr, ", asset snapshot %d", *last.AssetSnapshotSequence)
	}
	printCoverage(stderr, last.Coverage)
	if f.all {
		if truncated || (emitted >= f.maxItems && last.Offset+last.Limit < last.Total) {
			fmt.Fprintf(stderr, ", stopped at --max-items, next offset %d", last.Offset+last.Limit)
		}
		fmt.Fprintln(stderr)
		return nil
	}
	if last.Offset+len(last.Groups) < last.Total {
		fmt.Fprintf(stderr, ", next offset %d", last.Offset+last.Limit)
	}
	fmt.Fprintln(stderr)
	return nil
}

type revisionPageResponse struct {
	AlertID            string          `json:"alert_id"`
	Revisions          []view.Revision `json:"revisions"`
	HasMore            bool            `json:"has_more"`
	NextBeforeRevision int             `json:"next_before_revision"`
}

func newRevisionsCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("revisions", io.Discard)
	registerGlobalFlags(fs, g)
	var limit, before, maxItems int
	var all bool
	fs.Int(&limit, "limit", 20, fmt.Sprintf("Revisions per page (1-%d)", query.AgentMaxPageSize))
	fs.Int(&before, "before-revision", 0, "Exclusive revision boundary")
	fs.Bool(&all, "all", false, "Follow pages until exhausted or --max-items")
	fs.Int(&maxItems, "max-items", query.AgentDefaultMaxItems, "Maximum revisions emitted with --all")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if fs.NArg() != 1 {
			return usagef("usage: guiliu query revisions <alert-id> [flags]")
		}
		if err := validatePaging(out, all, "", limit, maxItems); err != nil {
			return err
		}
		columns, err := revisionTableColumns(out.tableFields())
		if err != nil {
			return err
		}
		var items []view.Revision
		var last revisionPageResponse
		cursor := before
		emitted := 0
		truncated := false
		for {
			params := url.Values{}
			params.Set("limit", strconv.Itoa(limit))
			if cursor > 0 {
				params.Set("before_revision", strconv.Itoa(cursor))
			}
			body, err := c.get(ctx, "/alerts/"+url.PathEscape(fs.Arg(0))+"/revisions", params)
			if err != nil {
				return err
			}
			page, err := decode[revisionPageResponse](body)
			if err != nil {
				return err
			}
			last = page
			if out.JSON {
				return emitJSON(stdout, body, out.Pretty)
			}
			batch := page.Revisions
			if all && emitted+len(batch) > maxItems {
				batch = batch[:maxItems-emitted]
				truncated = true
			}
			if out.NDJSON {
				if err := emitNDJSON(stdout, batch, out.Fields); err != nil {
					return err
				}
			} else {
				items = append(items, batch...)
			}
			emitted += len(batch)
			next := page.NextBeforeRevision
			if truncated && len(batch) > 0 {
				next = batch[len(batch)-1].Revision
			}
			if !all || !page.HasMore || next == 0 || emitted >= maxItems || len(page.Revisions) == 0 {
				last.NextBeforeRevision = next
				break
			}
			cursor = next
		}
		if !out.NDJSON && len(items) > 0 {
			if err := renderTable(stdout, columns, items); err != nil {
				return err
			}
		}
		if out.Quiet {
			return nil
		}
		fmt.Fprintf(stderr, "%d revision(s)", emitted)
		if last.NextBeforeRevision > 0 {
			fmt.Fprintf(stderr, ", next_before_revision %d", last.NextBeforeRevision)
		}
		if truncated || (all && emitted >= maxItems && last.HasMore) {
			fmt.Fprintf(stderr, ", stopped at --max-items")
		} else if all && !last.HasMore {
			fmt.Fprintf(stderr, ", end of revisions")
		}
		fmt.Fprintln(stderr)
		return nil
	}
}

type statsResponse struct {
	SnapshotSequence *int64           `json:"snapshot_sequence"`
	Window           view.QueryWindow `json:"window"`
	Statistics       statsView        `json:"statistics"`
	Coverage         *model.Coverage  `json:"coverage"`
}

type statsView struct {
	Total         int                                `json:"total"`
	BySeverity    map[string]int                     `json:"by_severity"`
	ByProvider    map[string]int                     `json:"by_provider"`
	ByStatus      map[string]int                     `json:"by_status"`
	ByDay         []model.DayCount                   `json:"by_day"`
	TopResources  []model.Count                      `json:"top_resources"`
	Distributions map[string]model.FieldDistribution `json:"distributions"`
	DayTimezone   string                             `json:"day_timezone"`
}

func newStatsCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("stats", io.Discard)
	registerGlobalFlags(fs, g)
	var filters alertFilterFlags
	filters.register(fs, filterOptions{defaultSince: "7d"})
	var topBy string
	var topN int
	fs.String(&topBy, "top-by", "title,source_ip,source_country", "Exact-value distributions: "+model.StatsDimensions)
	fs.Int(&topN, "top-n", model.StatsDefaultTopN, "Maximum values per distribution (1-100)")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		if out.NDJSON {
			return usagef("--ndjson is not supported for statistics")
		}
		if out.Fields != "" {
			return usagef("--fields is not supported for statistics")
		}
		params, err := filters.values(time.Now())
		if err != nil {
			return usagef("%v", err)
		}
		if _, err := query.ParseStatsOptions(topBy, strconv.Itoa(topN)); err != nil {
			return usagef("%v", err)
		}
		params.Set("top_by", topBy)
		params.Set("top_n", strconv.Itoa(topN))
		body, err := c.get(ctx, "/stats", params)
		if err != nil {
			return err
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		stats, err := decode[statsResponse](body)
		if err != nil {
			return err
		}
		return renderStats(stdout, stats)
	}
}

func newCoverageCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("coverage", io.Discard)
	registerGlobalFlags(fs, g)
	var filters alertFilterFlags
	filters.register(fs, filterOptions{defaultSince: "7d"})
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		if out.NDJSON {
			return usagef("--ndjson is not supported for coverage")
		}
		if out.Fields != "" {
			return usagef("--fields is not supported for coverage")
		}
		params, err := filters.values(time.Now())
		if err != nil {
			return usagef("%v", err)
		}
		body, err := c.get(ctx, "/coverage", params)
		if err != nil {
			return err
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		coverage, err := decode[model.Coverage](body)
		if err != nil {
			return err
		}
		return renderCoverage(stdout, coverage)
	}
}

type changePage struct {
	Changes    []model.AlertChange `json:"changes"`
	NextCursor string              `json:"next_cursor"`
	HasMore    bool                `json:"has_more"`
}

func newChangesCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("changes", io.Discard)
	registerGlobalFlags(fs, g)
	var cursor, provider, account string
	var limit, maxItems int
	var all bool
	fs.String(&cursor, "cursor", "", "Last consumed sequence; empty starts at the beginning")
	fs.Int(&limit, "limit", query.ChangeDefaultLimit, fmt.Sprintf("Changes per page (1-%d)", query.ChangeMaxLimit))
	fs.String(&provider, "provider", "", "Optional provider scope")
	fs.String(&account, "account", "", "Optional account scope")
	fs.Bool(&all, "all", false, "Follow the cursor until exhausted or --max-items")
	fs.Int(&maxItems, "max-items", query.AgentDefaultMaxItems, "Maximum changes emitted with --all")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		if limit < 1 || limit > query.ChangeMaxLimit {
			return usagef("--limit must be between 1 and %d", query.ChangeMaxLimit)
		}
		if maxItems < 1 {
			return usagef("--max-items must be positive")
		}
		if out.JSON && all {
			return usagef("--all requires table or --ndjson; use --limit for one JSON page")
		}
		columns, err := changeTableColumns(out.tableFields())
		if err != nil {
			return err
		}
		var items []model.AlertChange
		var last changePage
		next := cursor
		emitted := 0
		truncated := false
		for {
			params := url.Values{}
			params.Set("limit", strconv.Itoa(limit))
			setValue(params, "cursor", next)
			setValue(params, "provider", provider)
			setValue(params, "account_id", account)
			body, err := c.get(ctx, "/alerts/changes", params)
			if err != nil {
				return err
			}
			page, err := decode[changePage](body)
			if err != nil {
				return err
			}
			last = page
			if out.JSON {
				return emitJSON(stdout, body, out.Pretty)
			}
			batch := page.Changes
			if all && emitted+len(batch) > maxItems {
				batch = batch[:maxItems-emitted]
				truncated = true
			}
			if out.NDJSON {
				if err := emitNDJSON(stdout, batch, out.Fields); err != nil {
					return err
				}
			} else {
				items = append(items, batch...)
			}
			emitted += len(batch)
			next = page.NextCursor
			if truncated && len(batch) > 0 {
				next = strconv.FormatInt(batch[len(batch)-1].Sequence, 10)
			}
			if !all || !page.HasMore || next == "" || emitted >= maxItems || len(page.Changes) == 0 {
				break
			}
		}
		if !out.NDJSON && len(items) > 0 {
			if err := renderTable(stdout, columns, items); err != nil {
				return err
			}
		}
		if out.Quiet {
			return nil
		}
		fmt.Fprintf(stderr, "%d change(s)", emitted)
		if next != "" {
			fmt.Fprintf(stderr, ", next_cursor %s", next)
		}
		if truncated || (all && emitted >= maxItems && last.HasMore) {
			fmt.Fprintf(stderr, ", stopped at --max-items")
		} else if all && !last.HasMore {
			fmt.Fprintf(stderr, ", end of change log")
		}
		fmt.Fprintln(stderr)
		return nil
	}
}

func newContextCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("context", io.Discard)
	registerGlobalFlags(fs, g)
	var revision int
	var snapshot int64
	fs.Int(&revision, "revision", 0, "Exact alert revision")
	fs.Int64(&snapshot, "snapshot-sequence", -1, "Read the alert from a pinned snapshot")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if fs.NArg() != 1 {
			return usagef("usage: guiliu query context <alert-id> [flags]")
		}
		if out.NDJSON {
			return usagef("--ndjson is not supported for asset context")
		}
		if out.Fields != "" {
			return usagef("--fields is not supported for asset context; use --json with jq")
		}
		params := url.Values{}
		if revision > 0 {
			params.Set("revision", strconv.Itoa(revision))
		}
		if snapshot >= 0 {
			params.Set("snapshot_sequence", strconv.FormatInt(snapshot, 10))
		}
		body, err := c.get(ctx, "/alerts/"+url.PathEscape(fs.Arg(0))+"/asset-context", params)
		if err != nil {
			return err
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		context, err := decode[query.AssetContext](body)
		if err != nil {
			return err
		}
		return renderAssetContext(stdout, context)
	}
}
