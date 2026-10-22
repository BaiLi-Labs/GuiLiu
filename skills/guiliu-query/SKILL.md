---
name: guiliu-query
description: Query saved GuiLiu security Findings, groups, coverage, changes and asset evidence through gl-cli. Use for shell access, bounded exports and scripted pagination; MCP tools are available for interactive lookups.
---

# GuiLiu queries with gl-cli

`gl-cli query` is a read-only REST client. It reads the same saved facts as Web
and MCP, with the same authorization and audit trail. Queries do not refresh
cloud APIs. The product is GuiLiu; the executable is `gl-cli` (`gl-cli.exe` on
Windows).

Use `gl-cli query describe` for a compact command catalog, then
`gl-cli query <command> --describe` for flags and response field names.
Add `--schema` to that command description only when nested field types or
semantics are needed. Discovery works offline and needs no credentials.

Configure `GUILIU_URL` (default `http://127.0.0.1:8080`) and either
`GUILIU_API_KEY` or `GUILIU_API_KEY_FILE` / `--api-key-file` (0600 file).
Keep credentials out of command arguments, Skill text and exported data.

## Read only what the task needs

- Start with bounded `stats`, `groups` or `alerts`; retrieve individual `alert`
  evidence and `context` on demand. Existing full evidence need not be fetched
  again through a second tool.
- Use `--json` for an exact single-page REST envelope, including window,
  snapshot and cursors. It cannot be combined with `--all` or `--fields`.
- Use `--all --ndjson --max-items 1000` to save batches outside model context.
  `--fields id,source_ip,occurrence_count,product,alert_type,resource.name`
  projects one consistent pull; arrays/maps/raw payloads can be selected whole.
  Unknown/overlapping field paths fail; missing optional values become null.
- stdout contains data; stderr contains errors, coverage and continuation
  metadata. Exit `0` includes empty results and capped batches, `1` is a
  request failure, `2` is invalid usage. `--quiet` also hides cursors and
  truncation notices, so leave it off when saving resumable exports.

## Preserve the query identity

Alert lists, stats and coverage default to 7d; groups default to 24h. Maximum
range is 90d. `--start` and `--since` conflict. Dates without a time use UTC;
`--since` is relative to now. Use returned absolute bounds for repeatable reads.

`--all` pins the resolved window and snapshot within one invocation. When
stderr says `stopped at --max-items`, the batch is partial. The next
`continuation: {"args":[...]}` line contains the exact query arguments,
including full precision bounds, filters, sort, offset and snapshots. Resume
with those arguments under the same server and credentials. Do not rerun only
`--since` and a new offset: that selects a new time window/snapshot.
For durable automation prefer single-page `--json` and persist its checkpoint.

To expand a group, pass **`groups[].key` as `--group-key`** (JSON object), the
page `group_by`, `window.start/end`, `snapshot_sequence`, optional
`asset_snapshot_sequence`, and the original filters. Members are Finding
summaries; read selected full evidence separately. Network group memberships
can overlap. `summary` is null for `signature`, `source`, `type_asset`; this is
not a failed grouping. Counts are `finding_count`, title samples are
`top_titles[].key/count`, and source display maximum is `max_severity`.

## Interpret returned facts precisely

- `coverage` describes saved source query bounds, source time basis, observed
  event bounds and failures. `complete` is a mechanical collection check, not
  a usability score or proof that all upstream events arrived. An empty result
  never proves global absence. Read [collection and counts](references/semantics.md)
  when reporting coverage, occurrence counts or statistics.
- `resource.id` is a native resource ID. `asset_id` is GuiLiu's internal asset
  ID returned by `assets`, `lookup` or `context`. `account_id` is a connection
  ID; `account_uid` is the native account identity. Copy scoped references;
  IP/name matches are retrieval hits, not identity links.
- `resource.source=identifier_fallback` means the display name comes from an
  identifier. `resource.declared_name` is a source-defined role/name, not an
  asserted cloud instance name. Geolocation and `response_action` are source
  statements; they do not establish location accuracy or successful blocking.
- Saved asset observations are independent from Finding revisions and are
  not event-time configuration. Security-group allowed ports, host listening
  ports and source-observed reachability are distinct facts.
- Finding counts, revision counts and source `occurrence_count` are different
  measures. Missing occurrence counts are null, not zero or one. Do not sum
  across records/products without established source scope and non-overlap.

For grouped investigations, exact revision reads, resumable changes and asset
reference traversal, read the relevant recipe in
[query recipes](references/recipes.md). Follow the requested investigation;
this Skill does not authorize cloud changes, response actions or notifications.
