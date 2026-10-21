CREATE TABLE IF NOT EXISTS accounts (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    provider        TEXT NOT NULL,
    account_uid     TEXT NOT NULL DEFAULT '',
    region          TEXT NOT NULL DEFAULT '',
    enabled         INTEGER NOT NULL DEFAULT 1,
    options         TEXT NOT NULL DEFAULT '{}',
    credential      TEXT NOT NULL DEFAULT '',
    access_key_hint TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id                TEXT PRIMARY KEY,
    provider          TEXT NOT NULL,
    account_id        TEXT NOT NULL,
    account_name      TEXT NOT NULL DEFAULT '',
    account_uid       TEXT NOT NULL DEFAULT '',
    product           TEXT NOT NULL DEFAULT '',
    external_id       TEXT NOT NULL,
    dedupe_key        TEXT NOT NULL UNIQUE,
    title             TEXT NOT NULL DEFAULT '',
    description       TEXT NOT NULL DEFAULT '',
    severity_id       INTEGER NOT NULL DEFAULT 0,
    severity          TEXT NOT NULL DEFAULT 'unknown',
    original_severity TEXT NOT NULL DEFAULT '',
    vendor_status     TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'open',
    alert_type        TEXT NOT NULL DEFAULT '',
    event_time        INTEGER NOT NULL DEFAULT 0,
    first_seen_at     INTEGER NOT NULL DEFAULT 0,
    last_seen_at      INTEGER NOT NULL DEFAULT 0,
    region            TEXT NOT NULL DEFAULT '',
    resource_id       TEXT NOT NULL DEFAULT '',
    resource_name     TEXT NOT NULL DEFAULT '',
    resource_type     TEXT NOT NULL DEFAULT '',
    src_ip            TEXT NOT NULL DEFAULT '',
    dst_ip            TEXT NOT NULL DEFAULT '',
    actor             TEXT NOT NULL DEFAULT '',
    tactic            TEXT NOT NULL DEFAULT '',
    technique         TEXT NOT NULL DEFAULT '',
    observables       TEXT NOT NULL DEFAULT '[]',
    evidences         TEXT NOT NULL DEFAULT '[]',
    mapper_version    TEXT NOT NULL DEFAULT '',
    rule_id           TEXT NOT NULL DEFAULT '',
    finding_kind      TEXT NOT NULL DEFAULT 'other',
    source_updated_at INTEGER NOT NULL DEFAULT 0,
    canonical         TEXT NOT NULL DEFAULT '{}',
    raw_hash          TEXT NOT NULL,
    content_hash      TEXT NOT NULL,
    revision          INTEGER NOT NULL,
    sequence          INTEGER NOT NULL,
    ingested_at       INTEGER NOT NULL,
    last_ingested_at  INTEGER NOT NULL,
    ocsf              TEXT NOT NULL,
    raw               TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_event_time    ON alerts(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_provider      ON alerts(provider, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_account       ON alerts(account_id, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity      ON alerts(severity_id, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status        ON alerts(status, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_resource      ON alerts(resource_id);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip        ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_dst_ip        ON alerts(dst_ip);

-- Cover the grouping projection so time-bounded aggregations do not have to
-- read the much larger raw/OCSF payload rows.
CREATE INDEX IF NOT EXISTS idx_alerts_grouping_time ON alerts(
    event_time, provider, account_id, region, product, alert_type,
    resource_id, src_ip, id, severity_id, first_seen_at, last_seen_at, resource_name
);

CREATE TABLE IF NOT EXISTS sync_states (
    account_id           TEXT PRIMARY KEY,
    coverage_start       INTEGER NOT NULL DEFAULT 0,
    cursor_end           INTEGER NOT NULL DEFAULT 0,
    pending_start        INTEGER NOT NULL DEFAULT 0,
    pending_end          INTEGER NOT NULL DEFAULT 0,
    pending_token        TEXT NOT NULL DEFAULT '',
    last_success_at      INTEGER NOT NULL DEFAULT 0,
    last_attempt_at      INTEGER NOT NULL DEFAULT 0,
    last_error           TEXT NOT NULL DEFAULT '',
    last_error_at        INTEGER NOT NULL DEFAULT 0,
    last_duration_ms     INTEGER NOT NULL DEFAULT 0,
    items_last_run       INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    updated_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_revisions (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    account_id TEXT NOT NULL,
    change_type TEXT NOT NULL,
    projection_updated INTEGER NOT NULL DEFAULT 1,
    mapper_version TEXT NOT NULL,
    raw_hash TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    id            TEXT NOT NULL UNIQUE,
    alert_id      TEXT NOT NULL,
    revision      INTEGER NOT NULL,
    change_hash   TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'unknown',
    vendor_status TEXT NOT NULL DEFAULT '',
    ocsf          TEXT NOT NULL DEFAULT '{}',
    raw           TEXT NOT NULL DEFAULT '{}',
    captured_at   INTEGER NOT NULL,
    UNIQUE(alert_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_alert_revisions_alert ON alert_revisions(alert_id, revision DESC);

CREATE TABLE IF NOT EXISTS sync_runs (
    id          TEXT PRIMARY KEY,
    account_id  TEXT NOT NULL,
    provider    TEXT NOT NULL DEFAULT '',
    trigger     TEXT NOT NULL DEFAULT 'schedule',
    status      TEXT NOT NULL DEFAULT 'running',
    started_at  INTEGER NOT NULL,
    finished_at INTEGER NOT NULL DEFAULT 0,
    pages       INTEGER NOT NULL DEFAULT 0,
    fetched     INTEGER NOT NULL DEFAULT 0,
    created     INTEGER NOT NULL DEFAULT 0,
    updated     INTEGER NOT NULL DEFAULT 0,
    failed      INTEGER NOT NULL DEFAULT 0,
    error       TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sync_runs_account ON sync_runs(account_id, started_at DESC);

CREATE TABLE IF NOT EXISTS users (
    id                  TEXT PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL DEFAULT 'admin',
    disabled            INTEGER NOT NULL DEFAULT 0,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL,
    password_changed_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL UNIQUE,
    prefix      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL DEFAULT 0,
    expires_at  INTEGER NOT NULL DEFAULT 0,
    revoked_at  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);

CREATE TABLE IF NOT EXISTS ingest_failures (
    id              TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL,
    raw             TEXT NOT NULL,
    ingested_at     INTEGER NOT NULL,
    mapper_version  TEXT NOT NULL,
    error           TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL,
    last_attempt_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ingest_failures_account ON ingest_failures(account_id, last_attempt_at, id);

CREATE INDEX IF NOT EXISTS idx_revisions_scope ON alert_revisions(account_id, sequence);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(provider, product, rule_id);
CREATE TABLE IF NOT EXISTS alert_observables (
 alert_id TEXT NOT NULL,
 sequence INTEGER NOT NULL,
 type_id INTEGER NOT NULL,
 name TEXT NOT NULL,
 value TEXT NOT NULL,
 PRIMARY KEY(sequence,type_id,name,value)
);
CREATE INDEX IF NOT EXISTS idx_observable_lookup ON alert_observables(type_id,value,alert_id);
CREATE TABLE IF NOT EXISTS alert_versions AS SELECT id, provider, account_id, account_name, account_uid, product, external_id, title, description, severity_id, severity, original_severity, vendor_status, status, alert_type, event_time, first_seen_at, last_seen_at, region, resource_id, resource_name, resource_type, src_ip, dst_ip, actor, tactic, technique, observables, evidences, mapper_version, created_at, updated_at, canonical, raw_hash, revision, sequence, ingested_at, last_ingested_at, rule_id, finding_kind, source_updated_at FROM alerts WHERE 0;
CREATE UNIQUE INDEX IF NOT EXISTS idx_versions_identity ON alert_versions(id,sequence);
CREATE INDEX IF NOT EXISTS idx_versions_sequence ON alert_versions(sequence);
PRAGMA user_version = 5;

-- Independent, opt-in control-plane observations. No Finding feed entries.
CREATE TABLE IF NOT EXISTS assets (
 id TEXT PRIMARY KEY,
 account_id TEXT NOT NULL,
 provider TEXT NOT NULL,
 account_uid TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 content_hash TEXT NOT NULL,
 record TEXT NOT NULL,
 UNIQUE(provider, account_uid, region, resource_id)
);
CREATE INDEX IF NOT EXISTS idx_assets_scope ON assets(account_id, id);
CREATE TABLE IF NOT EXISTS asset_revisions (
 asset_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(asset_id, revision)
);
CREATE TABLE IF NOT EXISTS asset_refreshes (
 account_id TEXT NOT NULL,
 region TEXT NOT NULL,
 resource_id TEXT NOT NULL,
 status TEXT NOT NULL,
 attempted_at INTEGER NOT NULL,
 PRIMARY KEY(account_id, region, resource_id)
);
