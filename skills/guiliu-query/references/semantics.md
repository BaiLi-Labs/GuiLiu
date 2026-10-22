# Collection, counts and source semantics

`coverage_start` is the first completed source query's start, not the oldest
stored event time. `watermark` is the last completed source query's end.
`observed_events` gives matching stored Finding counts and event-time bounds
at `snapshot_sequence`. Old events can arrive in a later source window.
`outside_completed_windows` compares timestamp bounds with completed source
queries; duration is not a missing-event count or percentage. Compare
`time_basis` with query `time_field` before interpreting bounds.
Collection metadata describes current saved sync state even for an old Finding
snapshot. `pending_window`, `reasons` and `health` explain recorded limitations.

`stats --top-by title,source_ip,source_country,severity_day --top-n 20` returns
exact-value distributions under `statistics.distributions.<dimension>`:
`distinct_count`, `missing_count`, `top`, `other_count`, `has_more`.
`top[]` uses `key/count`; `severity_day` also uses `severity` with UTC dates.
Each dimension's top counts + other_count + missing_count equal total Findings.
Source IP means explicit source_ip, not every observable IP. `group_by=source`
groups source IP plus alert type. Constant values are facts about stored
records, not an accuracy/quality assessment.

`occurrence_count` is a vendor-reported quantity with `occurrence_scope`.
It may describe the source record's lifetime rather than this query window.
Equal scope strings alone establish neither non-overlap nor comparability.
There is no default occurrence weighting or platform attack-count estimate.
A Finding ID identifies a source record; a revision records a content change.
Repeated unchanged synchronization creates neither a new Finding nor revision.

Asset lookup reasons describe recorded observations/attempts:
- `no_recorded_refresh`: no saved attempt for the selected connection.
- `no_saved_observation_refresh_not_checked`: no local observation and no
  refresh inspection (for example no selected connection).
- `not_found_or_not_visible`: the source request returned no visible record
  in that scope; it does not prove resource absence or complete permissions.
- `scope_mismatch` / `not_requested`: the recorded operation made no cloud
  request (scope check or missing client).
- `resource_account_not_connected`: no connection for that resource account;
  using the reporting account is not a substitute.

`context` can return early with `provider_not_supported` or
`no_explicit_primary_host_reference`, before a `scope` is available. Read
`reason` rather than assuming every response has a scope. `refresh.source_error`
appears only for recorded source request failures. These read queries do not
collect assets or retry cloud requests implicitly.
