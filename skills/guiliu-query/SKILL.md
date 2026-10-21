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
guiliu query describe                      # machine-readable commands and flags
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
| `--fields` | Table-only column selection; not allowed with `--json`/`--ndjson`. |
| `--quiet` | Suppress the stderr metadata line. |

Agent-sized defaults: alert lists and stats use the last 7 days, groups use the
last 24 hours, and the window is capped at 90 days. Pass `--since 24h`,
`--start`/`--end` to change it. `--start` and `--since` are mutually exclusive.

## Recipes

### 1. Triage high/critical alerts (compact JSON)

```bash
guiliu query alerts --since 24h --severity high,critical --limit 20 --json \
  | jq -c '.alerts[] | {id,severity,title,event_time,resource:.resource.name,source_ip}'
```

### 2. Batch/export with bounded context

```bash
guiliu query alerts --since 7d --all --max-items 500 --ndjson \
  | jq -c '{id,severity,title,event_time,source_ip,resource:.resource.name}' \
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
  | jq '{complete, accounts:[.accounts[]|{name,status,complete,watermark,last_error}]}'
```

`complete=false`, a stale watermark or a disabled account means the empty list
is not proof of absence. `list`/`stats` stderr also says `coverage incomplete`
when applicable. Check `guiliu query health --json` for ingestion errors.

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
