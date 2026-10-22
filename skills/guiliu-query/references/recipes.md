# Query recipes

## Summaries, evidence and exact revisions

```bash
gl-cli query stats --since 24h --top-by title,source_ip --top-n 20 --json
gl-cli query groups --group-by asset --since 24h --limit 20 --json
gl-cli query alert "$FINDING_ID" --json
gl-cli query alert "$FINDING_ID" --raw
gl-cli query revisions "$FINDING_ID" --limit 20 --json
gl-cli query alert "$FINDING_ID" --revision "$REVISION" --json
```

Without a revision/snapshot a detail read returns the latest saved projection.
`--revision` selects an exact Finding revision; it conflicts with
`--snapshot-sequence`. The list omits raw/OCSF data; full detail includes it.
Only fetch raw evidence needed for this investigation.

## Group expansion

Save one bounded groups page to `groups.json`. Copy the original filters to
member queries too. The following example assumes there were no other filters:

```bash
gl-cli query groups --group-by security_group --since 24h --json > groups.json
gl-cli query alerts --group-by security_group \
  --group-key "$(jq -c '.groups[0].key' groups.json)" \
  --start "$(jq -r '.window.start' groups.json)" \
  --end "$(jq -r '.window.end' groups.json)" \
  --snapshot-sequence "$(jq -r '.snapshot_sequence' groups.json)" \
  --asset-snapshot-sequence "$(jq -r '.asset_snapshot_sequence' groups.json)" \
  --limit 20 --json
```

Check that `.groups[0]` exists before expansion. The default asset/network
summary counts overlapping memberships; source/title samples are limited to 5.

## Batched and incremental consumption

```bash
gl-cli query alerts --since 72h --all --max-items 1000 --ndjson \
  --fields id,source_ip,occurrence_count,occurrence_scope,product,alert_type,resource.name \
  > alerts.ndjson 2> alerts.meta
gl-cli query changes --cursor "$CURSOR" --limit 100 --json
```

For capped alert/group batches, read the `continuation: ` JSON line from stderr
and pass its `args` array to `gl-cli query` as arguments (not an eval string).
Keep server, credentials and output projection the same. Save export data and
metadata together. Two independent exports cannot be joined by line number.

For changes, process the page before saving `next_cursor` under the same
provider/account scope. Empty cursor starts at the beginning. Fetch the exact
`alert_id`/`revision` from each change if needed. A change with
`projection_updated=false` is a retained older observation, not a replacement
of the latest projection. On failure, reread the same cursor and consume
idempotently. `--all --ndjson` puts cursors on stderr; use per-page JSON for
durable checkpointing.

## Asset and network evidence

```bash
gl-cli query context "$FINDING_ID" --json
gl-cli query assets --provider tencent --limit 20 --json
gl-cli query asset "$ASSET_ID" --json
gl-cli query findings "$ASSET_ID" --limit 20 --json
gl-cli query component "$ASSET_ID" --revision "$ASSET_REVISION" --component "$COMPONENT"
```

`findings` searches all stored history by scoped native host identity, with no
implicit 7d window. Follow its snapshot and next_cursor when paging.
`component` needs the explicit asset revision and component key returned by
`asset`; Finding and asset revisions are different sequences.

Follow returned network `references` using `lookup --provider ...
--account-uid ... --region ... --resource-type ... --resource-id ... --json`.
Supply `--account` to inspect refresh status for a particular connection.
Do not derive a resource identity from an IP, name or similar title.

Inspect `providers`, `mapping --provider ...`, `health` and
`failures --account ...` when the task concerns mapping or collection failures.
Failure envelopes can contain malformed source payloads; keep large/private
payloads outside model context and fetch only what the task needs.
