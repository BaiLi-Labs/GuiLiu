package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func eventCommands() []*command {
	return []*command{
		{name: "events", summary: "Query upstream events on demand with bounded filters and source evidence references", usage: "gl-cli query events --account <id> [flags]", endpoint: "POST /api/v1/events/search", examples: []string{"gl-cli query events --account SOURCE_ID --since 24h --keyword 'request failed' --json", "gl-cli query events --account SOURCE_ID --ip 198.51.100.10 --all --max-items 200 --ndjson"}, newRun: newEventsCommand},
		{name: "event-fields", summary: "Inspect current upstream field types and normalized event mapping", usage: "gl-cli query event-fields --account <id> [flags]", endpoint: "GET /api/v1/events/fields", examples: []string{"gl-cli query event-fields --account SOURCE_ID --json"}, newRun: newEventFieldsCommand},
		{name: "event", summary: "Read current upstream evidence by exact source reference and compare its hash", usage: "gl-cli query event --account <id> --index <index> --id <document-id> [flags]", endpoint: "POST /api/v1/events/evidence", examples: []string{"gl-cli query event --account SOURCE_ID --index logs-web-000001 --id RECORD_ID --raw"}, newRun: newEventCommand},
	}
}

func newEventsCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("events", io.Discard)
	registerGlobalFlags(fs, g)
	var q model.EventSearch
	var filters string
	var all bool
	var maxItems int
	fs.String(&q.AccountID, "account", "", "Required upstream source connection ID")
	fs.String(&q.Start, "start", "", "Inclusive start; RFC3339 or UTC date")
	fs.String(&q.End, "end", "", "Inclusive end; defaults to now")
	fs.String(&q.Since, "since", "", "Lookback, e.g. 24h; default 24h, maximum 90d")
	fs.String(&q.Keyword, "keyword", "", "Phrase on the mapped message field, using source analyzer semantics")
	fs.String(&q.IP, "ip", "", "Exact IPv4/IPv6 in mapped source/destination fields")
	fs.String(&q.Host, "host", "", "Exact term in the mapped host name field")
	fs.String(&q.User, "user", "", "Exact term in the mapped user field")
	fs.String(&filters, "filters", "", "JSON object of native source field -> exact string value filters (maximum 16)")
	fs.String(&q.GroupBy, "group-by", "", "One aggregatable native field, e.g. source.ip, for top document counts")
	fs.Int(&q.TopN, "top-n", 0, "With --group-by only; defaults to 10, maximum 50")
	fs.Int(&q.Limit, "limit", 20, "Events per page, 1-200; omit on continuation")
	fs.String(&q.Cursor, "cursor", "", "Continue with only --account and --cursor; expires after 90 seconds")
	fs.Bool(&all, "all", false, "Follow pinned cursors within --max-items; stops before a page would exceed the budget")
	fs.Int(&maxItems, "max-items", 1000, "Maximum emitted events with --all; never skip a partly emitted page")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		if q.AccountID == "" {
			return usagef("--account is required")
		}
		if maxItems < 1 || q.Limit < 1 || q.Limit > 200 {
			return usagef("--max-items must be positive and --limit must be 1-200")
		}
		if all && out.JSON {
			return usagef("--all requires table or --ndjson")
		}
		if filters != "" && (json.Unmarshal([]byte(filters), &q.Filters) != nil || q.Filters == nil) {
			return usagef("--filters must be a JSON object of strings")
		}
		if q.Cursor != "" && !fs.Changed("limit") {
			q.Limit = 0
		}
		if all && q.Cursor == "" && q.Limit > maxItems {
			q.Limit = maxItems
		}
		cols, err := selectColumns(eventColumns(), []string{"event_time", "host_names", "source_ips", "message"}, out.tableFields())
		if err != nil {
			return err
		}
		var items []model.Event
		var last model.EventPage
		emitted := 0
		budgetStop := false
		for {
			body, err := c.post(ctx, "/events/search", q)
			if err != nil {
				return err
			}
			page, err := decode[model.EventPage](body)
			if err != nil {
				return err
			}
			last = page
			if out.JSON {
				if err := emitJSON(stdout, body, out.Pretty); err != nil {
					return err
				}
				if !page.Coverage.ExecutionComplete {
					return fmt.Errorf("upstream query is incomplete; inspect coverage")
				}
				return nil
			}
			if all && emitted+len(page.Events) > maxItems {
				return fmt.Errorf("source exceeded the event budget; page was not emitted")
			}
			if out.NDJSON {
				if err := emitNDJSON(stdout, page.Events, out.Fields); err != nil {
					return err
				}
			} else {
				items = append(items, page.Events...)
			}
			emitted += len(page.Events)
			if !all || !page.HasMore || page.NextCursor == "" || !page.Coverage.ExecutionComplete {
				break
			}
			if len(page.Events) == 0 {
				return fmt.Errorf("source returned an empty page with a continuation")
			}
			if emitted+page.Query.Limit > maxItems {
				budgetStop = true
				break
			}
			if q.Cursor == page.NextCursor {
				return fmt.Errorf("source repeated its event cursor")
			}
			q = model.EventSearch{AccountID: q.AccountID, Cursor: page.NextCursor}
		}
		if !out.NDJSON && len(items) > 0 {
			if err := renderTable(stdout, cols, items); err != nil {
				return err
			}
		}
		if !out.Quiet {
			fmt.Fprintf(stderr, "%d event(s); source matches %s %d; execution_complete=%t; window %s..%s\n", emitted, last.Total.Relation, last.Total.Value, last.Coverage.ExecutionComplete, last.Query.Start, last.Query.End)
			if last.HasMore {
				fmt.Fprintf(stderr, "has_more=true next_cursor=%s\n", last.NextCursor)
			}
			if budgetStop {
				fmt.Fprintln(stderr, "Stopped before the next complete page to respect --max-items; use the cursor to continue without skipping records.")
			}
			if last.Aggregation != nil {
				data, _ := json.Marshal(last.Aggregation)
				fmt.Fprintf(stderr, "aggregation=%s\n", data)
			}
			fmt.Fprintf(stderr, "limitations=%s\n", strings.Join(last.Coverage.Limitations, ","))
		}
		if !last.Coverage.ExecutionComplete {
			return fmt.Errorf("upstream query is incomplete; inspect coverage")
		}
		return nil
	}
}

func eventColumns() []column[model.Event] {
	return []column[model.Event]{
		{key: "id", header: "ID", max: 24, value: func(e model.Event) string { return e.ID }},
		{key: "event_time", header: "EVENT_TIME", value: func(e model.Event) string {
			if e.EventTime == nil {
				return ""
			}
			return e.EventTime.Format(time.RFC3339Nano)
		}},
		{key: "host_names", header: "HOST", max: 30, value: func(e model.Event) string { return strings.Join(e.HostNames, ",") }},
		{key: "source_ips", header: "SOURCE_IP", max: 40, value: func(e model.Event) string { return strings.Join(e.SourceIPs, ",") }},
		{key: "destination_ips", header: "DESTINATION_IP", max: 40, value: func(e model.Event) string { return strings.Join(e.DestinationIPs, ",") }},
		{key: "users", header: "USER", max: 30, value: func(e model.Event) string { return strings.Join(e.Users, ",") }},
		{key: "message", header: "MESSAGE", max: 100, value: func(e model.Event) string { return e.Message }},
	}
}

func newEventFieldsCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("event-fields", io.Discard)
	registerGlobalFlags(fs, g)
	var account string
	fs.String(&account, "account", "", "Required upstream source connection ID")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		if account == "" {
			return usagef("--account is required")
		}
		body, err := c.get(ctx, "/events/fields", url.Values{"account_id": {account}})
		if err != nil {
			return err
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		fields, err := decode[model.EventFields](body)
		if err != nil {
			return err
		}
		if out.NDJSON {
			return emitNDJSON(stdout, fields.Fields, out.Fields)
		}
		cols, err := selectColumns([]column[model.EventField]{
			{key: "name", header: "FIELD", max: 70, value: func(f model.EventField) string { return f.Name }},
			{key: "types", header: "TYPES", value: func(f model.EventField) string { return strings.Join(f.Types, ",") }},
			{key: "searchable", header: "SEARCHABLE", value: func(f model.EventField) string { return fmt.Sprint(f.Searchable) }},
			{key: "aggregatable", header: "AGGREGATABLE", value: func(f model.EventField) string { return fmt.Sprint(f.Aggregatable) }},
		}, []string{"name", "types", "searchable", "aggregatable"}, out.tableFields())
		if err != nil {
			return err
		}
		if err := renderTable(stdout, cols, fields.Fields); err != nil {
			return err
		}
		if !out.Quiet {
			fmt.Fprintf(stderr, "%d field(s); truncated=%t; mapper=%s\n", len(fields.Fields), fields.Truncated, fields.MapperVersion)
		}
		return nil
	}
}

func newEventCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("event", io.Discard)
	registerGlobalFlags(fs, g)
	var ref model.EventReference
	var raw bool
	fs.String(&ref.AccountID, "account", "", "Required source connection ID")
	fs.String(&ref.Index, "index", "", "Exact backing index from events[].evidence.index")
	fs.String(&ref.ID, "id", "", "Native document ID from events[].evidence.id")
	fs.String(&ref.Routing, "routing", "", "Routing from the evidence reference, when present")
	fs.String(&ref.RawHash, "raw-hash", "", "Canonical JSON SHA-256 from the reference, to detect source changes")
	fs.Bool(&raw, "raw", false, "Print only the current source JSON; change status is written to stderr")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		if ref.AccountID == "" || ref.Index == "" || ref.ID == "" {
			return usagef("--account, --index and --id are required")
		}
		if raw && (out.JSON || out.NDJSON || out.Fields != "") {
			return usagef("--raw cannot be combined with output projection or JSON modes")
		}
		body, err := c.post(ctx, "/events/evidence", ref)
		if err != nil {
			return err
		}
		evidence, err := decode[model.EventEvidence](body)
		if err != nil {
			return err
		}
		if !out.Quiet {
			fmt.Fprintf(stderr, "current upstream evidence; raw_hash=%s hash_compared=%t changed=%t; not an immutable local revision\n", evidence.RawHash, evidence.HashCompared, evidence.Changed)
		}
		if raw {
			return emitRaw(stdout, evidence.Raw)
		}
		if out.NDJSON {
			return emitNDJSON(stdout, []model.EventEvidence{evidence}, out.Fields)
		}
		if out.Fields != "" {
			return usagef("--fields requires --ndjson for event evidence")
		}
		return emitJSON(stdout, body, out.Pretty)
	}
}
