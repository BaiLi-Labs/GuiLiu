package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/view"
)

type assetListResponse struct {
	Assets      []model.Asset `json:"assets"`
	HasMore     bool          `json:"has_more"`
	NextCursor  string        `json:"next_cursor"`
	Limit       int           `json:"limit"`
	Limitations []string      `json:"limitations"`
}

func newAssetsCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("assets", io.Discard)
	registerGlobalFlags(fs, g)
	var provider, account, accountUID, region, resourceID, resourceType, afterID string
	var limit, maxItems int
	var all bool
	fs.String(&provider, "provider", "", "Provider id, e.g. tencent")
	fs.String(&account, "account", "", "Configured account ID")
	fs.String(&accountUID, "account-uid", "", "Native cloud account UID")
	fs.String(&region, "region", "", "Cloud region")
	fs.String(&resourceID, "resource-id", "", "Exact native resource ID")
	fs.String(&resourceType, "resource-type", "", "host type, nic, security_group, vpc or subnet")
	fs.Int(&limit, "limit", query.AssetDefaultLimit, fmt.Sprintf("Assets per page (1-%d)", query.AssetMaxLimit))
	fs.String(&afterID, "after-id", "", "Continue using next_cursor")
	fs.Bool(&all, "all", false, "Follow next_cursor until exhausted or --max-items")
	fs.Int(&maxItems, "max-items", query.AgentDefaultMaxItems, "Maximum assets emitted with --all")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		if limit < 1 || limit > query.AssetMaxLimit {
			return usagef("--limit must be between 1 and %d", query.AssetMaxLimit)
		}
		if maxItems < 1 {
			return usagef("--max-items must be positive")
		}
		if out.JSON && all {
			return usagef("--all requires table or --ndjson; use --limit for one JSON page")
		}
		columns, err := assetTableColumns(out.Fields)
		if err != nil {
			return err
		}
		var items []model.Asset
		var last assetListResponse
		after := afterID
		emitted := 0
		truncated := false
		for {
			params := url.Values{}
			params.Set("limit", strconv.Itoa(limit))
			setValue(params, "provider", provider)
			setValue(params, "account_id", account)
			setValue(params, "account_uid", accountUID)
			setValue(params, "region", region)
			setValue(params, "resource_id", resourceID)
			setValue(params, "resource_type", resourceType)
			setValue(params, "after_id", after)
			body, err := c.get(ctx, "/assets", params)
			if err != nil {
				return err
			}
			page, err := decode[assetListResponse](body)
			if err != nil {
				return err
			}
			last = page
			if out.JSON {
				return emitJSON(stdout, body, out.Pretty)
			}
			batch := page.Assets
			if all && emitted+len(batch) > maxItems {
				batch = batch[:maxItems-emitted]
				truncated = true
			}
			if out.NDJSON {
				if err := emitNDJSON(stdout, batch); err != nil {
					return err
				}
			} else {
				items = append(items, batch...)
			}
			emitted += len(batch)
			after = page.NextCursor
			if truncated && len(batch) > 0 {
				after = batch[len(batch)-1].ID
			}
			if !all || !page.HasMore || after == "" || emitted >= maxItems || len(page.Assets) == 0 {
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
		fmt.Fprintf(stderr, "%d asset(s)", emitted)
		if after != "" {
			fmt.Fprintf(stderr, ", next_cursor %s", after)
		}
		if truncated || (all && emitted >= maxItems && last.HasMore) {
			fmt.Fprintf(stderr, ", stopped at --max-items")
		}
		if len(last.Limitations) > 0 {
			fmt.Fprintf(stderr, ", limitations: %s", joinLimited(last.Limitations, 3))
		}
		fmt.Fprintln(stderr)
		return nil
	}
}

func newAssetCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("asset", io.Discard)
	registerGlobalFlags(fs, g)
	var revision int
	fs.Int(&revision, "revision", 0, "Exact asset revision")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if fs.NArg() != 1 {
			return usagef("usage: guiliu query asset <asset-id> [flags]")
		}
		if out.NDJSON {
			return usagef("--ndjson is not supported for one asset")
		}
		if out.Fields != "" {
			return usagef("--fields is not supported for one asset; use --json with jq")
		}
		params := url.Values{}
		if revision > 0 {
			params.Set("revision", strconv.Itoa(revision))
		}
		body, err := c.get(ctx, "/assets/"+url.PathEscape(fs.Arg(0)), params)
		if err != nil {
			return err
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		asset, err := decode[model.Asset](body)
		if err != nil {
			return err
		}
		return renderAssetDetail(stdout, asset)
	}
}

func newComponentCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("component", io.Discard)
	registerGlobalFlags(fs, g)
	var revision int
	var component string
	fs.Int(&revision, "revision", 0, "Exact asset revision (required)")
	fs.String(&component, "component", "", "Component key returned by the asset detail (required)")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if fs.NArg() != 1 {
			return usagef("usage: guiliu query component <asset-id> --revision N --component KEY")
		}
		if revision < 1 {
			return usagef("--revision is required")
		}
		if component == "" {
			return usagef("--component is required")
		}
		if out.JSON || out.NDJSON || out.Pretty || out.Fields != "" {
			return usagef("component writes exact source bytes; --json/--ndjson/--pretty/--fields are not applicable")
		}
		path := "/assets/" + url.PathEscape(fs.Arg(0)) + "/revisions/" + strconv.Itoa(revision) + "/components/" + url.PathEscape(component) + "/raw"
		body, err := c.get(ctx, path, url.Values{})
		if err != nil {
			return err
		}
		return emitRaw(stdout, body)
	}
}

type assetLookupResponse struct {
	Status      string              `json:"status"`
	Asset       *model.Asset        `json:"asset,omitempty"`
	Refresh     *model.AssetRefresh `json:"refresh,omitempty"`
	Scope       *query.AssetScope   `json:"scope,omitempty"`
	Limitations []string            `json:"limitations"`
}

func newLookupCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("lookup", io.Discard)
	registerGlobalFlags(fs, g)
	var provider, account, accountUID, region, resourceType, resourceID string
	fs.String(&provider, "provider", "", "Provider; currently tencent")
	fs.String(&account, "account", "", "Optional source connection ID for refresh status")
	fs.String(&accountUID, "account-uid", "", "Native cloud account UID")
	fs.String(&region, "region", "", "Cloud region")
	fs.String(&resourceType, "resource-type", "", "host type, nic, security_group, vpc or subnet")
	fs.String(&resourceID, "resource-id", "", "Exact native resource ID")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		if out.NDJSON {
			return usagef("--ndjson is not supported for one lookup")
		}
		if out.Fields != "" {
			return usagef("--fields is not supported for one lookup; use --json with jq")
		}
		missing := []string{}
		for _, item := range []struct {
			name  string
			value string
		}{
			{"--provider", provider},
			{"--account-uid", accountUID},
			{"--region", region},
			{"--resource-type", resourceType},
			{"--resource-id", resourceID},
		} {
			if item.value == "" {
				missing = append(missing, item.name)
			}
		}
		if len(missing) > 0 {
			return usagef("missing %v", missing)
		}
		params := url.Values{}
		params.Set("provider", provider)
		setValue(params, "account_id", account)
		params.Set("account_uid", accountUID)
		params.Set("region", region)
		params.Set("resource_type", resourceType)
		params.Set("resource_id", resourceID)
		body, err := c.get(ctx, "/assets/lookup", params)
		if err != nil {
			return err
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		result, err := decode[assetLookupResponse](body)
		if err != nil {
			return err
		}
		return renderAssetLookup(stdout, result)
	}
}

type assetFindingsResponse struct {
	AssetID          string       `json:"asset_id"`
	Alerts           []view.Alert `json:"alerts"`
	Total            int          `json:"total"`
	SnapshotSequence *int64       `json:"snapshot_sequence"`
	HasMore          bool         `json:"has_more"`
	NextCursor       string       `json:"next_cursor"`
	Limit            int          `json:"limit"`
	MatchedOn        []string     `json:"matched_on"`
	Limitations      []string     `json:"limitations"`
}

func newFindingsCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("findings", io.Discard)
	registerGlobalFlags(fs, g)
	var limit, maxItems int
	var all bool
	var afterID string
	var snapshot int64
	fs.Int(&limit, "limit", query.AssetDefaultLimit, fmt.Sprintf("Findings per page (1-%d)", query.AssetMaxLimit))
	fs.String(&afterID, "after-id", "", "Continue using next_cursor")
	fs.Int64(&snapshot, "snapshot-sequence", -1, "Reuse a returned snapshot sequence")
	fs.Bool(&all, "all", false, "Follow next_cursor until exhausted or --max-items")
	fs.Int(&maxItems, "max-items", query.AgentDefaultMaxItems, "Maximum findings emitted with --all")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if fs.NArg() != 1 {
			return usagef("usage: guiliu query findings <asset-id> [flags]")
		}
		if limit < 1 || limit > query.AssetMaxLimit {
			return usagef("--limit must be between 1 and %d", query.AssetMaxLimit)
		}
		if maxItems < 1 {
			return usagef("--max-items must be positive")
		}
		if out.JSON && all {
			return usagef("--all requires table or --ndjson; use --limit for one JSON page")
		}
		columns, err := alertTableColumns(out.Fields)
		if err != nil {
			return err
		}
		var items []view.Alert
		var last assetFindingsResponse
		after := afterID
		emitted := 0
		truncated := false
		for {
			params := url.Values{}
			params.Set("limit", strconv.Itoa(limit))
			setValue(params, "after_id", after)
			if snapshot >= 0 {
				params.Set("snapshot_sequence", strconv.FormatInt(snapshot, 10))
			}
			body, err := c.get(ctx, "/assets/"+url.PathEscape(fs.Arg(0))+"/findings", params)
			if err != nil {
				return err
			}
			page, err := decode[assetFindingsResponse](body)
			if err != nil {
				return err
			}
			last = page
			if page.SnapshotSequence != nil {
				snapshot = *page.SnapshotSequence
			}
			if out.JSON {
				return emitJSON(stdout, body, out.Pretty)
			}
			batch := page.Alerts
			if all && emitted+len(batch) > maxItems {
				batch = batch[:maxItems-emitted]
				truncated = true
			}
			if out.NDJSON {
				if err := emitNDJSON(stdout, batch); err != nil {
					return err
				}
			} else {
				items = append(items, batch...)
			}
			emitted += len(batch)
			after = page.NextCursor
			if truncated && len(batch) > 0 {
				after = batch[len(batch)-1].ID
			}
			if !all || !page.HasMore || after == "" || emitted >= maxItems || len(page.Alerts) == 0 {
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
		fmt.Fprintf(stderr, "%d finding(s)", emitted)
		if last.Total > 0 {
			fmt.Fprintf(stderr, " of %d", last.Total)
		}
		if last.SnapshotSequence != nil {
			fmt.Fprintf(stderr, ", snapshot %d", *last.SnapshotSequence)
		}
		if after != "" {
			fmt.Fprintf(stderr, ", next_cursor %s", after)
		}
		if truncated || (all && emitted >= maxItems && last.HasMore) {
			fmt.Fprintf(stderr, ", stopped at --max-items")
		}
		if len(last.Limitations) > 0 {
			fmt.Fprintf(stderr, ", limitations: %s", joinLimited(last.Limitations, 3))
		}
		fmt.Fprintln(stderr)
		return nil
	}
}

type healthResponse struct {
	Status   string         `json:"status"`
	Database string         `json:"database"`
	Version  string         `json:"version"`
	Accounts []view.Account `json:"accounts"`
}

type accountHealthResponse struct {
	Status     string         `json:"status"`
	Account    view.Account   `json:"account"`
	SyncState  view.SyncState `json:"sync_state"`
	RecentRuns []view.SyncRun `json:"recent_runs"`
}

func newHealthCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("health", io.Discard)
	registerGlobalFlags(fs, g)
	var account string
	fs.String(&account, "account", "", "Show one account with recent runs")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		if out.NDJSON {
			return usagef("--ndjson is not supported for health")
		}
		if account != "" {
			if out.Fields != "" {
				return usagef("--fields is only supported for the all-accounts table")
			}
			body, err := c.get(ctx, "/accounts/"+url.PathEscape(account)+"/health", url.Values{})
			if err != nil {
				return err
			}
			if out.JSON {
				return emitJSON(stdout, body, out.Pretty)
			}
			health, err := decode[accountHealthResponse](body)
			if err != nil {
				return err
			}
			return renderAccountHealth(stdout, health)
		}
		columns, err := healthTableColumns(out.Fields)
		if err != nil {
			return err
		}
		body, err := c.get(ctx, "/health", url.Values{})
		if err != nil {
			return err
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		health, err := decode[healthResponse](body)
		if err != nil {
			return err
		}
		return renderHealth(stdout, columns, health)
	}
}
