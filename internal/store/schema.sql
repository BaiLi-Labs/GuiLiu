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
    event_time        INTEGER NOT NULL,
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

CREATE TABLE IF NOT EXISTS sync_states (
    account_id           TEXT PRIMARY KEY,
    cursor_end           INTEGER NOT NULL DEFAULT 0,
    pending_start        INTEGER NOT NULL DEFAULT 0,
    pending_end          INTEGER NOT NULL DEFAULT 0,
    pending_token        TEXT NOT NULL DEFAULT '',
    pending_records      TEXT NOT NULL DEFAULT '[]',
    last_success_at      INTEGER NOT NULL DEFAULT 0,
    last_attempt_at      INTEGER NOT NULL DEFAULT 0,
    last_error           TEXT NOT NULL DEFAULT '',
    last_error_at        INTEGER NOT NULL DEFAULT 0,
    last_duration_ms     INTEGER NOT NULL DEFAULT 0,
    items_last_run       INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    updated_at           INTEGER NOT NULL
);

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

PRAGMA user_version = 2;
