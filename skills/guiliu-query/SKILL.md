---
name: guiliu-query
description: Query GuiLiu (归流) alerts, groups, change feeds, coverage, statistics, assets and ingestion health from a shell. Use when an agent needs GuiLiu data without MCP, or needs bounded pagination, batching, NDJSON output or scripted access.
---

# GuiLiu query CLI

`guiliu query` is a read-only REST client for GuiLiu. It is the shell/agent
alternative to the MCP server: same data, same API key, same audit trail, but
with deterministic output, pagination and file/pipe composition.

Use MCP when the client already supports tool calls and the task is a few
interactive lookups. Use this CLI when the agent has a shell, needs to batch or
paginate, wants to keep large results out of its context, or runs in CI/cron.

## Setup

```bash
export GUILIU_URL="http://127.0.0.1:8080"   # default
export GUILIU_API_KEY="glk_..."             # created in the console: API & MCP
guiliu query --help
guiliu query describe                      # commands, flags and response JSON Schemas
guiliu query alerts --help                 # one command
```

Never put the API key in argv. If the key is in a file, use
`GUILIU_API_KEY_FILE=/path/to/key` or `--api-key-file /path/to/key` (0600).

Exit codes: `0` success (including empty), `1` API/network error, `2` usage or
local validation error. Data goes to stdout; errors, pagination metadata and
coverage warnings go to stderr.

## Output contract

| Flag | Meaning |
| --- | --- |
| default | Human table. Columns can be selected with `--fields`. |
| `--json` | Exact REST response body, one page. Use `jq` to project. |
| `--ndjson` | One JSON record per line. Combine with `--all` for batches. |
| `--all` | Follow the server cursor/offset until exhausted or `--max-items` (default 1000). |
| `--fields` | Table columns, or real JSON paths with `--ndjson` (e.g. `id,resource.id`). Not allowed with exact `--json`. |
| `--quiet` | Suppress the stderr metadata line. |

Agent-sized defaults: alert lists and stats use the last 7 days, groups use the
last 24 hours, and the window is capped at 90 days. Pass `--since 24h`,
`--start`/`--end` to change it. `--start` and `--since` are mutually exclusive.

Use `<command> --describe` to read `response_schema` and `ndjson_item_schema`
before choosing field paths. NDJSON projection keeps nested objects and exact
JSON numbers, returns null for absent optional fields, and rejects unknown or
overlapping paths. Select arrays/maps/raw payloads whole; no query expressions.
Table timestamps carry an explicit UTC suffix.

## Recipes

### 1. Triage high/critical alerts (compact JSON)

```bash
guiliu query alerts --since 24h --severity high,critical --limit 20 --json \
  | jq -c '.alerts[] | {id,severity,title,event_time,resource:.resource.name,source_ip}'
guiliu query alerts --since 72h --limit 20 \
  --fields event_time,title,resource,resource_source,resource_declared_name,source_ip,source_country,response_action
```

`resource.name` is the name the source declared for that asset; `resource.source`
says whether it is `vendor_declared` or an `identifier_fallback` (domain, IP or
native ID). A fallback name is not an asset name, so do not quote it as one.
`resource.declared_name` is the source's own name for the resource role (Tencent
`Victim.Name`); its meaning is defined by the source and is not asserted to be
the cloud instance name. Only asset context gives the host name the cloud
inventory reports.
`source_location` / `source_country` and `response_action` are the source's own
statements (for example `BlockAttackIP`); they are not platform verdicts.

### 2. Batch/export with bounded context

```bash
guiliu query alerts --since 7d --all --max-items 500 --ndjson \
  --fields id,severity,title,event_time,source_ip,resource.id \
  > alerts.ndjson
```

`--all` pins `snapshot_sequence` and the resolved window across pages, so the
result is a stable page set. If the stderr line says `stopped at --max-items`,
continue with `--offset <next offset>` or raise `--max-items`.

### 3. Investigate one alert

```bash
ID="<alert-id>"
guiliu query alert "$ID" --json \
  | jq '{id,title,severity,status,description,observables,evidences,raw_url}'
guiliu query alert "$ID" --raw | jq .        # exact vendor JSON
guiliu query context "$ID" --json            # current local asset context
guiliu query revisions "$ID" --limit 20 --json
```

Only fetch `--raw` for a specific alert. Alert list endpoints deliberately omit
raw payloads; `--json` on one alert includes them. Ingestion failure records are
the exception: `failures --json` includes the stored malformed payload.

### 4. Groups and expansion

```bash
guiliu query groups --group-by signature --since 24h --limit 20 --json
```

Grouping is exact-field grouping, not an incident or verdict. To expand a
group, reuse its `group_by`, `key` and the returned `window.start/end`:

```bash
guiliu query alerts \
  --group-by signature \
  --group-key '{"provider":"tencent","account_id":"...","account_uid":"...","region":"ap-guangzhou","product":"...","rule_id":"...","resource_id":"...","source_ip":"..."}' \
  --start '2026-10-20T00:00:00Z' --end '2026-10-21T00:00:00Z' \
  --json
```

Group members use `finding_count`, `top_titles[].key/count` and `max_severity`.
`summary` is null for `signature`, `source` and `type_asset`; it is an object
only for asset/network grouping. This does not mean those groups failed.

### 5. Incremental consumption

```bash
# One page: read next_cursor, process changes, then save the cursor.
guiliu query changes --limit 100 --json

# Batch backfill from a saved cursor.
guiliu query changes --cursor "$CURSOR" --all --max-items 5000 --ndjson \
  > changes.ndjson
```

An empty cursor starts at the beginning of the persisted change log. Save
`next_cursor` only after processing the page; repeated ingestion does not create
changes. For resumable automation prefer `--json` per page and persist
`next_cursor`, because `--all --ndjson` writes records to stdout and the cursor
to stderr.

### 6. Before concluding "no alerts"

```bash
guiliu query coverage --since 7d --json \
  | jq '{query_window,snapshot_sequence,complete,accounts:[.accounts[]|{name,status,time_basis,coverage_start,watermark,observed_events,outside_completed_windows,pending_window,reasons,last_error}]}'
```

`coverage_start` is the first successfully completed source query's start,
not the oldest event time. `watermark` is the last completed source query's
end. `observed_events` separately reports matching stored Finding counts and
event times at the returned snapshot. Older events may arrive in later windows.
`outside_completed_windows` compares requested timestamp bounds to source
query bounds; durations are not missing-event counts or percentages. Read the
source `time_basis` before comparing it with the query's `time_field`.
Sync status remains current even for an old Finding snapshot.

`complete` is a mechanical collection check, not a usability score or delivery
guarantee. An empty list never proves absence in all upstream products.
CLI metadata explains bounds outside completed collection and reason codes.
Check `guiliu query health --json` for ingestion errors.

For exact counts without exporting every Finding:

```bash
guiliu query stats --since 72h --top-by title,source_ip,source_country,severity_day --top-n 20 --json
```

Read `statistics.distributions.<dimension>.distinct_count/missing_count/top/other_count/has_more`.
`top` contains `key/count`, and `severity_day` adds `severity` with UTC dates.
All counts refer to Finding records; top counts + other_count + missing_count
equal total. Source IP counts use the explicit source field; `group_by=source`
instead groups source IP plus alert type. Constant values are reported as facts,
without a field-quality verdict. Reuse `--snapshot-sequence` and absolute bounds
for matching statistics, list and coverage queries.

### 7. Assets

```bash
guiliu query assets --provider tencent --limit 20 --json
guiliu query asset "$ASSET_ID" --json
guiliu query lookup --provider tencent --account-uid 123456789 \
  --region ap-guangzhou --resource-type cvm --resource-id ins-xxx --json
guiliu query findings "$ASSET_ID" --all --ndjson
guiliu query component "$ASSET_ID" --revision 2 --component runtime | jq .
```

`lookup` needs the complete explicit identity (`provider`, `account_uid`,
`region`, `resource_type`, `resource_id`). IP or name matches are not identity
links.

`context` and `lookup` always return `scope` (provider, region, resource type,
native ID, source API and API version): one failed refresh no longer means an
unknown reason. `refresh.source_error` is present only when the source request
itself failed; `not_found_or_not_visible` with an empty error means an
authorized read returned no record in that exact scope, not a permission
problem. `scope_mismatch` and `not_requested` mean **no cloud request was made**
(local scope check or missing client), so they are not evidence about the
resource. `refresh_reason=resource_account_not_connected` means the resource
belongs to an account with no configured connection; do not retry it through the
reporting account.

### 8. Source mapping and ingestion failures

```bash
guiliu query providers --json
guiliu query mapping --provider tencent --json
guiliu query failures --account "$ACCOUNT_ID" --json
```

`mapping` shows the versioned source pointers and transforms a connector uses;
`failures` shows stored malformed or unmappable records. Run
`guiliu query health --json` first to see whether a failure affects the account.

## Discipline

- Start with `guiliu query describe`; it is generated from the binary, so trust
  it over this document if a flag changes.
- Prefer `--ndjson` + `jq` for large or repeated reads; keep full envelopes and
  raw evidence out of the model context.
- Grouping, statistics and coverage are facts about records, not verdicts.
  Do not infer attack success, false positives or asset identity from them.
- Use `--limit` and `--max-items`; avoid unbounded output.
- Do not pass the API key on the command line or write it into a skill file.

### Asset and network grouping

Use `groups --group-by asset` (default), `name_asset` (exact source title, not a rule), `vpc`, `subnet`, `security_group`, or `nic`. Network groups reflect explicit saved primary-host references, not traffic paths or effective policy. Check page `summary`: unique Finding count differs from overlapping memberships; missing context is not absence of cloud resources. Group asset/title samples are limited to 5.

`lookup` with `reason=no_recorded_refresh` means no saved attempt for the selected
connection; `no_saved_observation_refresh_not_checked` means no matching local
observation and refresh was not checked (for example no connection was selected).
Use the explicit connection ID to inspect recorded failures. These read queries
never collect cloud assets implicitly.

For paging or expansion preserve **both** `--snapshot-sequence` and `--asset-snapshot-sequence` plus absolute start/end and filters. Expand with `alerts --group-by security_group --group-key '<returned key>' ...`; add `--vendor-title` only for exact source-title filtering. Preserve title whitespace and case. Queries never implicitly refresh cloud assets. Current asset observations are not event-time configuration; use returned asset IDs/revisions for exact evidence.
