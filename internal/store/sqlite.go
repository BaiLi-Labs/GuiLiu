package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

//go:embed schema.sql
var schemaSQL string

// SQLite is the bundled store implementation.
type SQLite struct {
	db *sql.DB
}

var _ Store = (*SQLite)(nil)

// Open opens (and migrates) a SQLite database.
func Open(path string) (*SQLite, error) {
	if path == "" {
		path = "data/guiliu.db"
	}
	dsn := path
	if path == ":memory:" {
		dsn = "file::memory:?cache=shared"
	} else {
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return nil, err
		}
		u := url.URL{Scheme: "file", Path: abs}
		q := u.Query()
		q.Add("_pragma", "busy_timeout(5000)")
		q.Add("_pragma", "journal_mode(WAL)")
		q.Add("_pragma", "synchronous(NORMAL)")
		u.RawQuery = q.Encode()
		dsn = u.String()
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &SQLite{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLite) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version == 0 {
		var existing int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='alerts'").Scan(&existing); err != nil {
			return err
		}
		if existing > 0 {
			return fmt.Errorf("unversioned database is unsupported; use a new development database")
		}
	}
	if version != 0 && version != 5 {
		return fmt.Errorf("database schema %d is unsupported; use a new database for the development data contract (schema 5)", version)
	}
	_, err := s.db.Exec(schemaSQL)
	if err != nil {
		return err
	}
	// Additive operational diagnostics preserve existing development data.
	// These columns do not change source records or either query watermark.
	for _, table := range []string{"sync_states", "sync_runs", "asset_refreshes"} {
		var exists int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name='source_error'", table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			if _, err := s.db.Exec("ALTER TABLE " + table + " ADD COLUMN source_error TEXT NOT NULL DEFAULT 'null'"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *SQLite) Close() error { return s.db.Close() }

func (s *SQLite) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// ---------------------------------------------------------------- accounts

func (s *SQLite) CreateAccount(ctx context.Context, a *model.Account) error {
	now := time.Now().UTC()
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.UpdatedAt = now
	options, err := json.Marshal(a.Options)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO accounts (id, name, provider, account_uid, region, enabled, options, credential, access_key_hint, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, a.Provider, a.AccountUID, a.Region, boolInt(a.Enabled), string(options),
		a.CredentialEncrypted, a.AccessKeyHint, millis(a.CreatedAt), millis(a.UpdatedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	a.CredentialSet = a.CredentialEncrypted != ""
	return nil
}

func (s *SQLite) UpdateAccount(ctx context.Context, a *model.Account, credential *string) error {
	old, err := s.GetAccount(ctx, a.ID)
	if err != nil {
		return err
	}
	scopeChanged := old.Region != a.Region || old.AccountUID != a.AccountUID
	for _, key := range []string{"project_id", "workspace_id", "parent", "location", "subscription_id", "status", "api_version", "endpoint"} {
		if old.Options[key] != a.Options[key] {
			scopeChanged = true
		}
	}
	if scopeChanged {
		var count int
		if err := s.db.QueryRowContext(ctx, "SELECT (SELECT COUNT(*) FROM sync_states WHERE account_id=?)+(SELECT COUNT(*) FROM assets WHERE account_id=?)", a.ID, a.ID).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			return fmt.Errorf("%w: collection scope is immutable after synchronization; create a separate account connection", ErrConflict)
		}
	}
	a.UpdatedAt = time.Now().UTC()
	options, err := json.Marshal(a.Options)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var res sql.Result
	if credential != nil {
		res, err = tx.ExecContext(ctx, `
			UPDATE accounts SET name=?, account_uid=?, region=?, enabled=?, options=?, credential=?, access_key_hint=?, updated_at=?
			WHERE id=?`,
			a.Name, a.AccountUID, a.Region, boolInt(a.Enabled), string(options), *credential, a.AccessKeyHint, millis(a.UpdatedAt), a.ID)
	} else {
		res, err = tx.ExecContext(ctx, `
			UPDATE accounts SET name=?, account_uid=?, region=?, enabled=?, options=?, updated_at=?
			WHERE id=?`,
			a.Name, a.AccountUID, a.Region, boolInt(a.Enabled), string(options), millis(a.UpdatedAt), a.ID)
	}
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, "UPDATE alerts SET account_name=? WHERE account_id=?", a.Name, a.ID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite) UpsertAccountByName(ctx context.Context, a *model.Account) (bool, error) {
	existing, err := s.GetAccountByName(ctx, a.Name)
	if errors.Is(err, ErrNotFound) {
		return true, s.CreateAccount(ctx, a)
	}
	if err != nil {
		return false, err
	}
	if existing.Provider != a.Provider {
		return false, fmt.Errorf("account %q already exists with provider %q; rename the account to change provider", a.Name, existing.Provider)
	}
	a.ID = existing.ID
	a.CreatedAt = existing.CreatedAt
	var credential *string
	if a.CredentialEncrypted != "" {
		credential = &a.CredentialEncrypted
	} else {
		a.AccessKeyHint = existing.AccessKeyHint
	}
	return false, s.UpdateAccount(ctx, a, credential)
}

func (s *SQLite) GetAccount(ctx context.Context, id string) (*model.Account, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, provider, account_uid, region, enabled, options, credential, access_key_hint, created_at, updated_at
		FROM accounts WHERE id=?`, id)
	return scanAccount(row)
}

func (s *SQLite) GetAccountByName(ctx context.Context, name string) (*model.Account, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, provider, account_uid, region, enabled, options, credential, access_key_hint, created_at, updated_at
		FROM accounts WHERE name=?`, name)
	return scanAccount(row)
}

func (s *SQLite) ListAccounts(ctx context.Context) ([]model.Account, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, provider, account_uid, region, enabled, options, credential, access_key_hint, created_at, updated_at
		FROM accounts ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		// Never ship the encrypted blob to callers that only need metadata.
		a.CredentialEncrypted = ""
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *SQLite) DeleteAccount(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM sync_runs WHERE account_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sync_states WHERE account_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM ingest_failures WHERE account_id=?`, id); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM accounts WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *SQLite) AccountCredential(ctx context.Context, id string) (string, error) {
	var blob string
	err := s.db.QueryRowContext(ctx, `SELECT credential FROM accounts WHERE id=?`, id).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return blob, err
}

func scanAccount(row interface{ Scan(...any) error }) (*model.Account, error) {
	var a model.Account
	var enabled int
	var options string
	var created, updated int64
	err := row.Scan(&a.ID, &a.Name, &a.Provider, &a.AccountUID, &a.Region, &enabled, &options, &a.CredentialEncrypted, &a.AccessKeyHint, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	a.Enabled = enabled != 0
	if options != "" {
		_ = json.Unmarshal([]byte(options), &a.Options)
	}
	a.CreatedAt = fromMillis(created)
	a.UpdatedAt = fromMillis(updated)
	a.CredentialSet = a.CredentialEncrypted != ""
	return &a, nil
}

// ------------------------------------------------------------------ alerts

// UpsertAlert commits the current projection, immutable revision and global
// change sequence together. Identical source content never emits a change.
func (s *SQLite) UpsertAlert(ctx context.Context, rec *model.AlertRecord) (bool, error) {
	if rec.ExternalID == "" {
		return false, errors.New("alert external id is required")
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	if rec.IngestedAt.IsZero() {
		rec.IngestedAt = now
	}
	if rec.LastIngestedAt.IsZero() {
		rec.LastIngestedAt = rec.IngestedAt
	}
	// Match the durable millisecond precision in both the index and immutable
	// snapshot, so reading a revision cannot change platform timestamp values.
	rec.IngestedAt = rec.IngestedAt.UTC().Truncate(time.Millisecond)
	rec.LastIngestedAt = rec.LastIngestedAt.UTC().Truncate(time.Millisecond)
	rec.RawHash = hashBytes(rec.Raw)
	if !json.Valid(rec.Raw) {
		return false, errors.New("source record must be valid JSON")
	}
	if rec.Status == "" {
		rec.Status = model.StatusOpen
	}
	if rec.FindingKind == "" {
		rec.FindingKind = model.FindingOther
	}
	a := rec.Alert
	a.Raw, a.OCSF = nil, nil
	canonical, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	normalizedRaw, err := canonicalJSON(rec.Raw)
	if err != nil {
		return false, err
	}
	normalizedOCSF := []byte("null")
	if len(rec.OCSF) > 0 {
		normalizedOCSF, err = canonicalJSON(rec.OCSF)
		if err != nil {
			return false, err
		}
	}
	contentHash := hashBytes(append(append(append(normalizedRaw, 0), canonical...), normalizedOCSF...))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var oldID, oldHash, oldStatus string
	var oldCanonical string
	var oldCreated, oldIngested, oldLastIngested int64
	var oldRevision int
	err = tx.QueryRowContext(ctx, "SELECT id,content_hash,status,created_at,ingested_at,last_ingested_at,revision,canonical FROM alerts WHERE dedupe_key=?", rec.DedupeKey()).Scan(&oldID, &oldHash, &oldStatus, &oldCreated, &oldIngested, &oldLastIngested, &oldRevision, &oldCanonical)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return false, err
	}
	if !created {
		rec.ID, rec.Status, rec.CreatedAt = oldID, model.AlertStatus(oldStatus), fromMillis(oldCreated)
		var old model.Alert
		if err := json.Unmarshal([]byte(oldCanonical), &old); err != nil {
			return false, err
		}
		rec.ProjectionUpdated = shouldUpdateProjection(old.SourceUpdatedAt, rec.SourceUpdatedAt, fromMillis(oldLastIngested), rec.LastIngestedAt)
		if oldHash == contentHash {
			rec.Changed = false
			rec.Revision = oldRevision
			rec.IngestedAt = fromMillis(oldIngested)
			rec.ProjectionUpdated = false
			_, err = tx.ExecContext(ctx, "UPDATE alerts SET last_ingested_at=MAX(last_ingested_at,?),account_name=? WHERE id=?", millis(rec.LastIngestedAt), rec.AccountName, rec.ID)
			if err != nil {
				return false, err
			}
			return false, tx.Commit()
		}
		if !rec.ProjectionUpdated {
			// A known older payload is retained once. Retrying the same stale
			// source content must not emit a new change on every collection run.
			var existingRevision int
			err := tx.QueryRowContext(ctx, "SELECT revision FROM alert_revisions WHERE alert_id=? AND change_hash=? ORDER BY revision DESC LIMIT 1", rec.ID, contentHash).Scan(&existingRevision)
			if err == nil {
				rec.Changed, rec.Revision = false, existingRevision
				return false, tx.Commit()
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return false, err
			}
		}
		if err := tx.QueryRowContext(ctx, "SELECT MAX(revision) FROM alert_revisions WHERE alert_id=?", rec.ID).Scan(&oldRevision); err != nil {
			return false, err
		}
	} else {
		if rec.ID == "" {
			rec.ID = uuid.NewString()
		}
		rec.CreatedAt = now
		rec.ProjectionUpdated = true
	}
	rec.Changed, rec.Revision, rec.UpdatedAt = true, oldRevision+1, now
	accountUID := rec.AccountUID
	if rec.CloudAccountUID != "" {
		accountUID = rec.CloudAccountUID
	}
	rec.AccountUID = accountUID
	changeType := "updated"
	if created {
		changeType = "created"
	}
	// The snapshot is updated with its assigned sequence before commit.
	result, err := tx.ExecContext(ctx, `INSERT INTO alert_revisions
 (id,alert_id,revision,change_hash,title,severity,vendor_status,ocsf,raw,captured_at,provider,account_id,change_type,mapper_version,raw_hash,snapshot,projection_updated)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, uuid.NewString(), rec.ID, rec.Revision, contentHash, rec.Title, rec.Severity.String(), rec.VendorStatus, string(rec.OCSF), string(rec.Raw), millis(now), rec.Provider, rec.AccountID, changeType, rec.MapperVersion, rec.RawHash, "{}", boolInt(rec.ProjectionUpdated))
	if err != nil {
		return false, err
	}
	rec.Sequence, err = result.LastInsertId()
	if err != nil {
		return false, err
	}
	snapshot, err := json.Marshal(rec)
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE alert_revisions SET snapshot=? WHERE sequence=?", string(snapshot), rec.Sequence); err != nil {
		return false, err
	}
	if !rec.ProjectionUpdated {
		return false, tx.Commit()
	}
	observablesJSON, err := marshalList(rec.Observables)
	if err != nil {
		return false, err
	}
	evidencesJSON, err := marshalList(rec.Evidences)
	if err != nil {
		return false, err
	}
	columns := []string{"id", "provider", "account_id", "account_name", "account_uid", "product", "external_id", "dedupe_key", "title", "description", "severity_id", "severity", "original_severity", "vendor_status", "status", "alert_type", "event_time", "first_seen_at", "last_seen_at", "region", "resource_id", "resource_name", "resource_type", "src_ip", "dst_ip", "actor", "tactic", "technique", "observables", "evidences", "mapper_version", "ocsf", "raw", "created_at", "updated_at", "rule_id", "finding_kind", "canonical", "raw_hash", "content_hash", "revision", "sequence", "ingested_at", "last_ingested_at", "source_updated_at"}
	values := []any{rec.ID, rec.Provider, rec.AccountID, rec.AccountName, accountUID, rec.Product, rec.ExternalID, rec.DedupeKey(), rec.Title, rec.Description, int(rec.Severity), rec.Severity.String(), rec.OriginalSeverity, rec.VendorStatus, string(rec.Status), rec.AlertType, millis(rec.EventTime), millis(rec.FirstSeenAt), millis(rec.LastSeenAt), rec.Region, rec.Resource.ID, rec.Resource.Name, rec.Resource.Type, rec.SourceIP, rec.DestinationIP, rec.Actor, rec.Tactic, rec.Technique, observablesJSON, evidencesJSON, rec.MapperVersion, string(rec.OCSF), string(rec.Raw), millis(rec.CreatedAt), millis(rec.UpdatedAt), rec.RuleID, rec.FindingKind, string(canonical), rec.RawHash, contentHash, rec.Revision, rec.Sequence, millis(rec.IngestedAt), millis(rec.LastIngestedAt), millis(rec.SourceUpdatedAt)}
	placeholders, updates := make([]string, len(columns)), make([]string, 0, len(columns))
	for i, col := range columns {
		placeholders[i] = "?"
		if col != "id" {
			updates = append(updates, col+"=excluded."+col)
		}
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO alerts ("+strings.Join(columns, ",")+") VALUES ("+strings.Join(placeholders, ",")+") ON CONFLICT(id) DO UPDATE SET "+strings.Join(updates, ","), values...)
	if err != nil {
		return false, err
	}

	for _, o := range rec.Observables {
		if o.Value == "" {
			continue
		}
		if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO alert_observables(alert_id,sequence,type_id,name,value) VALUES (?,?,?,?,?)", rec.ID, rec.Sequence, o.TypeID, o.Name, o.Value); err != nil {
			return false, err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO alert_versions SELECT `+alertColumns+`,rule_id,finding_kind,source_updated_at FROM alerts WHERE id=?`, rec.ID); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return created, nil
}

// Source modification times are comparable only when both are explicitly
// known. Otherwise select the latest collection observation, never event time.
func shouldUpdateProjection(oldSource, incomingSource, oldIngested, incomingIngested time.Time) bool {
	if !oldSource.IsZero() && !incomingSource.IsZero() && !oldSource.Equal(incomingSource) {
		return incomingSource.After(oldSource)
	}
	return !incomingIngested.Before(oldIngested)
}

func hashBytes(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
func canonicalJSON(data []byte) ([]byte, error) {
	var value any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

const alertColumns = `id, provider, account_id, account_name, account_uid, product, external_id,
	title, description, severity_id, severity, original_severity, vendor_status, status, alert_type,
	event_time, first_seen_at, last_seen_at, region, resource_id, resource_name, resource_type,
	src_ip, dst_ip, actor, tactic, technique, observables, evidences, mapper_version, created_at, updated_at, canonical, raw_hash, revision, sequence, ingested_at, last_ingested_at`

func (s *SQLite) GetAlert(ctx context.Context, id string) (*model.AlertRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+alertColumns+`, ocsf, raw FROM alerts WHERE id=?`, id)
	return scanAlert(row, true)
}

func (s *SQLite) ListAlerts(ctx context.Context, f model.AlertFilter) ([]model.AlertRecord, int, error) {
	where, args := buildAlertWhere(f)
	args = withContextArgs(f, args)
	prefix := snapshotPrefix(f)
	countQuery := prefix + `SELECT COUNT(*) FROM alerts` + where
	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return []model.AlertRecord{}, 0, nil
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	order := "event_time DESC, id DESC"
	if f.AfterID != "" {
		order = "id ASC"
	}
	switch f.Sort {
	case "severity", "severity_id":
		order = "severity_id DESC, event_time DESC, id DESC"
	case "last_seen", "last_seen_at":
		order = "last_seen_at DESC, id DESC"
	case "first_seen", "first_seen_at":
		order = "first_seen_at DESC, id DESC"
	case "id":
		order = "id ASC"
	case "event_time", "":
	default:
		order = "event_time DESC, id DESC"
	}

	query := prefix + `SELECT ` + alertColumns + ` FROM alerts` + where + ` ORDER BY ` + order + ` LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, query, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]model.AlertRecord, 0, limit)
	for rows.Next() {
		rec, err := scanAlert(rows, false)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *rec)
	}
	return out, total, rows.Err()
}

func (s *SQLite) ListAlertGroups(ctx context.Context, f model.AlertFilter) ([]model.AlertGroup, int, error) {
	groupBy := f.GroupBy
	if groupBy == "" {
		groupBy = model.GroupByAsset
	}
	f.GroupBy = groupBy
	if groupBy.UsesAssetContext() {
		return s.listContextGroups(ctx, f)
	}
	where, args := buildAlertWhere(f)
	args = withContextArgs(f, args)

	var keyCols, groupCols string
	switch groupBy {
	case model.GroupByTypeAsset:
		keyCols = `provider, account_id, region, product, alert_type, resource_id,
			CASE WHEN product='' OR alert_type='' OR resource_id='' THEN id ELSE '' END`
		groupCols = `1,2,3,4,5,6,7`
	case model.GroupBySignature:
		keyCols = `provider, account_id, account_uid, region, product, rule_id, resource_id, src_ip,
			CASE WHEN account_uid='' OR product='' OR rule_id='' OR resource_id='' OR src_ip='' THEN id ELSE '' END`
		groupCols = `1,2,3,4,5,6,7,8,9`
	case model.GroupByAsset:
		keyCols = `provider, account_id, region, resource_id,
			CASE WHEN resource_id='' THEN id ELSE '' END`
		groupCols = `1,2,3,4,5`
	case model.GroupBySource:
		keyCols = `src_ip, alert_type,
			CASE WHEN src_ip='' OR alert_type='' THEN id ELSE '' END`
		groupCols = `1,2,3`
	default:
		return nil, 0, fmt.Errorf("unknown group_by %q", groupBy)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	// Window counting shares this aggregation with the page instead of running
	// GROUP BY twice. The representative title is display metadata only; raw payload and evidence are not read.
	revisionWhere := "r.alert_id=alerts.id"
	if f.SnapshotSequence != nil {
		revisionWhere += fmt.Sprintf(" AND r.sequence<=%d", *f.SnapshotSequence)
	}
	selectCols := keyCols + `, COUNT(*), MAX(severity_id), COALESCE(MIN(NULLIF(first_seen_at,0)),0), MAX(last_seen_at),
		MIN(resource_name), MIN(title), GROUP_CONCAT(DISTINCT provider), COUNT(*) OVER (), SUM(COALESCE((SELECT MAX(r.revision)-1 FROM alert_revisions r WHERE ` + revisionWhere + `),revision-1))`
	query := snapshotPrefix(f) + `SELECT ` + selectCols + ` FROM alerts` + where +
		` GROUP BY ` + groupCols +
		` ORDER BY MAX(severity_id) DESC, COUNT(*) DESC, MAX(last_seen_at) DESC, ` + groupCols +
		` LIMIT ? OFFSET ?`
	rows, err := s.db.QueryContext(ctx, query, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var total int
	out := make([]model.AlertGroup, 0, limit)
	for rows.Next() {
		group := model.AlertGroup{GroupBy: groupBy}
		var singleton string
		var maxSeverity int
		var firstSeen, lastSeen int64
		var resourceName, sourceTitle, providers string
		var alertType string
		var count int
		switch groupBy {
		case model.GroupByTypeAsset:
			var provider, accountID, region, product, resourceID string
			if err := rows.Scan(&provider, &accountID, &region, &product, &alertType, &resourceID, &singleton,
				&count, &maxSeverity, &firstSeen, &lastSeen, &resourceName, &sourceTitle, &providers, &total, &group.RevisionCount); err != nil {
				return nil, 0, err
			}
			group.Key = map[string]string{
				"provider": provider, "account_id": accountID, "region": region,
				"product": product, "alert_type": alertType, "resource_id": resourceID,
			}
			group.ResourceID, group.ResourceName, group.AlertType = resourceID, resourceName, alertType
		case model.GroupBySignature:
			var provider, accountID, accountUID, region, product, resourceID, sourceIP string
			if err := rows.Scan(&provider, &accountID, &accountUID, &region, &product, &alertType, &resourceID, &sourceIP, &singleton,
				&count, &maxSeverity, &firstSeen, &lastSeen, &resourceName, &sourceTitle, &providers, &total, &group.RevisionCount); err != nil {
				return nil, 0, err
			}
			group.Key = map[string]string{
				"provider": provider, "account_id": accountID, "account_uid": accountUID, "region": region, "product": product,
				"rule_id": alertType, "resource_id": resourceID, "source_ip": sourceIP,
			}
			group.ResourceID, group.ResourceName, group.SourceIP, group.AlertType = resourceID, resourceName, sourceIP, alertType
		case model.GroupByAsset:
			var provider, accountID, region, resourceID string
			if err := rows.Scan(&provider, &accountID, &region, &resourceID, &singleton,
				&count, &maxSeverity, &firstSeen, &lastSeen, &resourceName, &sourceTitle, &providers, &total, &group.RevisionCount); err != nil {
				return nil, 0, err
			}
			group.Key = map[string]string{
				"provider": provider, "account_id": accountID, "region": region, "resource_id": resourceID,
			}
			group.ResourceID, group.ResourceName = resourceID, resourceName
		case model.GroupBySource:
			var sourceIP string
			if err := rows.Scan(&sourceIP, &alertType, &singleton,
				&count, &maxSeverity, &firstSeen, &lastSeen, &resourceName, &sourceTitle, &providers, &total, &group.RevisionCount); err != nil {
				return nil, 0, err
			}
			group.Key = map[string]string{"source_ip": sourceIP, "alert_type": alertType}
			group.SourceIP, group.AlertType, group.ResourceName = sourceIP, alertType, resourceName
		}
		if singleton != "" {
			group.Key["singleton"] = singleton
		}
		group.Title = groupTitle(groupBy, group.Key, resourceName, alertType)
		if singleton != "" {
			group.Title = firstNonEmpty(resourceName, group.ResourceID, group.SourceIP, "未归并告警") + " · " + sourceTitle
			group.TopTitles = []model.Count{{Key: sourceTitle, Count: 1}}
			required := []string{"product", "alert_type", "resource_id"}
			if groupBy == model.GroupBySignature {
				required = []string{"account_uid", "product", "rule_id", "resource_id", "source_ip"}
			}
			if groupBy == model.GroupBySource {
				required = []string{"source_ip", "alert_type"}
			}
			for _, key := range required {
				if group.Key[key] == "" {
					group.MissingFields = append(group.MissingFields, key)
				}
			}
		}
		group.ID = model.GroupID(groupBy, group.Key)
		group.FindingCount = count
		group.MaxSeverity = model.Severity(maxSeverity)
		group.FirstSeenAt = ptrTime(firstSeen)
		group.LastSeenAt = ptrTime(lastSeen)
		group.Providers = splitDistinct(providers)
		out = append(out, group)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	// An out-of-range page has no window-count row; count keys only in this case.
	if len(out) == 0 && offset > 0 {
		countQuery := snapshotPrefix(f) + `SELECT COUNT(*) FROM (SELECT ` + keyCols + ` FROM alerts` + where + ` GROUP BY ` + groupCols + `)`
		if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
	}
	return out, total, nil
}

func groupTitle(groupBy model.AlertGroupBy, key map[string]string, resourceName, alertType string) string {
	if key["singleton"] != "" {
		return "未归并告警 · " + firstNonEmpty(alertType, "unknown")
	}
	switch groupBy {
	case model.GroupByAsset:
		return firstNonEmpty(resourceName, key["resource_id"], "未命名资产")
	case model.GroupBySource:
		return firstNonEmpty(key["source_ip"], "未知来源") + " · " + firstNonEmpty(alertType, "未知类型")
	default:
		base := firstNonEmpty(resourceName, key["resource_id"], key["source_ip"], "未命名资产")
		if alertType != "" && !strings.Contains(base, alertType) {
			base += " · " + alertType
		}
		return base
	}
}

func splitDistinct(s string) []string {
	parts := strings.Split(s, ",")
	seen := map[string]bool{}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func (s *SQLite) ListAlertRevisions(ctx context.Context, alertID string, limit int) ([]model.AlertRevision, error) {
	return s.AlertRevisionPage(ctx, alertID, 0, limit)
}

func (s *SQLite) UpdateAlertStatus(ctx context.Context, id string, status model.AlertStatus) error {
	res, err := s.db.ExecContext(ctx, `UPDATE alerts SET status=? WHERE id=?`, string(status), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) AlertStats(ctx context.Context, f model.AlertFilter) (*model.AlertStats, error) {
	if _, err := f.StatsOptions.Normalize(); err != nil {
		return nil, err
	}
	if f.SnapshotSequence == nil {
		seq, err := s.SnapshotSequence(ctx)
		if err != nil {
			return nil, err
		}
		f.SnapshotSequence = &seq
	}
	// Keep all counts in one local read view, including mutable annotations.
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	where, args := buildAlertWhere(f)
	args = withContextArgs(f, args)
	stats := &model.AlertStats{
		BySeverity: map[string]int{},
		ByProvider: map[string]int{},
		ByStatus:   map[string]int{},
	}
	if err := tx.QueryRowContext(ctx, snapshotPrefix(f)+`SELECT COUNT(*) FROM alerts`+where, args...).Scan(&stats.Total); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, snapshotPrefix(f)+`SELECT severity_id, COUNT(*) FROM alerts`+where+` GROUP BY severity_id`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev int
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.BySeverity[model.Severity(sev).String()] = count
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	rows, err = tx.QueryContext(ctx, snapshotPrefix(f)+`SELECT provider, COUNT(*) FROM alerts`+where+` GROUP BY provider`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k string
		var count int
		if err := rows.Scan(&k, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.ByProvider[k] = count
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	rows, err = tx.QueryContext(ctx, snapshotPrefix(f)+`SELECT status, COUNT(*) FROM alerts`+where+` GROUP BY status`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k string
		var count int
		if err := rows.Scan(&k, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.ByStatus[k] = count
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	rows, err = tx.QueryContext(ctx, snapshotPrefix(f)+`
		SELECT strftime('%Y-%m-%d', event_time/1000, 'unixepoch') AS day, COUNT(*)
		FROM alerts`+where+`
		GROUP BY day ORDER BY day ASC`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var day string
		var count int
		if err := rows.Scan(&day, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.ByDay = append(stats.ByDay, model.DayCount{Day: day, Count: count})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	topWhere := where
	if topWhere == "" {
		topWhere = " WHERE resource_id <> ''"
	} else {
		topWhere += " AND resource_id <> ''"
	}
	rows, err = tx.QueryContext(ctx, snapshotPrefix(f)+`
		SELECT resource_id, MAX(resource_name), COUNT(*) AS c
		FROM alerts`+topWhere+`
		GROUP BY resource_id ORDER BY c DESC, resource_id ASC LIMIT 10`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, name string
		var count int
		if err := rows.Scan(&id, &name, &count); err != nil {
			rows.Close()
			return nil, err
		}
		stats.TopResources = append(stats.TopResources, model.Count{Key: id, Name: name, Count: count})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	stats.DayTimezone = "UTC"
	stats.Distributions, err = fieldDistributions(ctx, tx, f, stats.Total)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return stats, nil
}

func scanAlert(row interface{ Scan(...any) error }, withPayload bool) (*model.AlertRecord, error) {
	var rec model.AlertRecord
	var severityID int
	var severitySlug string
	var status string
	var observablesJSON, evidencesJSON string
	var eventTS, firstTS, lastTS, createdTS, updatedTS int64
	dest := []any{
		&rec.ID, &rec.Provider, &rec.AccountID, &rec.AccountName, &rec.AccountUID, &rec.Product, &rec.ExternalID,
		&rec.Title, &rec.Description, &severityID, &severitySlug, &rec.OriginalSeverity, &rec.VendorStatus, &status, &rec.AlertType,
		&eventTS, &firstTS, &lastTS, &rec.Region, &rec.Resource.ID, &rec.Resource.Name, &rec.Resource.Type,
		&rec.SourceIP, &rec.DestinationIP, &rec.Actor, &rec.Tactic, &rec.Technique, &observablesJSON, &evidencesJSON,
		&rec.MapperVersion, &createdTS, &updatedTS,
	}
	var canonical string
	var ingested, lastIngested int64
	dest = append(dest, &canonical, &rec.RawHash, &rec.Revision, &rec.Sequence, &ingested, &lastIngested)
	var ocsfPayload, rawPayload string
	if withPayload {
		dest = append(dest, &ocsfPayload, &rawPayload)
	}
	err := row.Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(canonical), &rec.Alert); err != nil {
		return nil, fmt.Errorf("decode canonical record: %w", err)
	}
	rec.IngestedAt, rec.LastIngestedAt = fromMillis(ingested), fromMillis(lastIngested)
	rec.Severity = model.Severity(severityID)
	rec.ProjectionUpdated = true
	rec.Status = model.AlertStatus(status)
	rec.EventTime = fromMillis(eventTS)
	rec.FirstSeenAt = fromMillis(firstTS)
	rec.LastSeenAt = fromMillis(lastTS)
	rec.CreatedAt = fromMillis(createdTS)
	rec.UpdatedAt = fromMillis(updatedTS)
	if observablesJSON != "" && observablesJSON != "null" {
		_ = json.Unmarshal([]byte(observablesJSON), &rec.Observables)
	}
	if evidencesJSON != "" && evidencesJSON != "null" {
		_ = json.Unmarshal([]byte(evidencesJSON), &rec.Evidences)
	}
	if withPayload {
		rec.OCSF = json.RawMessage(ocsfPayload)
		rec.Raw = json.RawMessage(rawPayload)
	}
	return &rec, nil
}

// resourceOwnerExpr resolves the account that owns the primary resource. A
// source-declared resource account wins; otherwise the alert's own account
// applies. Keep this in sync with model.AlertRecord.ResourceAccountUID.
func resourceOwnerExpr(alias string) string {
	canonical, account := "canonical", "account_uid"
	if alias != "" {
		canonical, account = alias+".canonical", alias+".account_uid"
	}
	return `COALESCE(NULLIF(json_extract(` + canonical + `,'$.resource.account_uid'),''),` + account + `)`
}

func buildAlertWhere(f model.AlertFilter) (string, []any) {
	clauses := make([]string, 0, 10)
	args := make([]any, 0, 10)

	if f.Provider != "" {
		clauses = append(clauses, "provider = ?")
		args = append(args, f.Provider)
	}
	if f.AccountID != "" {
		clauses = append(clauses, "account_id = ?")
		args = append(args, f.AccountID)
	}
	if f.AccountUID != "" {
		clauses = append(clauses, "account_uid=?")
		args = append(args, f.AccountUID)
	}
	if f.ResourceAccountUID != "" {
		clauses = append(clauses, resourceOwnerExpr("")+"=?")
		args = append(args, f.ResourceAccountUID)
	}
	if f.Region != "" {
		clauses = append(clauses, "region=?")
		args = append(args, f.Region)
	}
	if f.ExactResourceID != "" {
		clauses = append(clauses, "((resource_id=? AND resource_type=?) OR EXISTS (SELECT 1 FROM json_each(canonical,'$.resources') r WHERE json_extract(r.value,'$.id')=? AND json_extract(r.value,'$.type')=?))")
		args = append(args, f.ExactResourceID, f.ResourceType, f.ExactResourceID, f.ResourceType)
	}
	if len(f.ExactResourceIDs) > 0 {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(f.ExactResourceIDs)), ",")
		typeClause, typeClauseJSON := "", ""
		if f.ResourceType != "" {
			typeClause = " AND resource_type=?"
			typeClauseJSON = " AND json_extract(r.value,'$.type')=?"
		}
		for _, id := range f.ExactResourceIDs {
			args = append(args, id)
		}
		if f.ResourceType != "" {
			args = append(args, f.ResourceType)
		}
		for _, id := range f.ExactResourceIDs {
			args = append(args, id)
		}
		if f.ResourceType != "" {
			args = append(args, f.ResourceType)
		}
		clauses = append(clauses, "((resource_id IN ("+placeholders+")"+typeClause+") OR EXISTS (SELECT 1 FROM json_each(canonical,'$.resources') r WHERE json_extract(r.value,'$.id') IN ("+placeholders+")"+typeClauseJSON+"))")
	}
	if len(f.Severities) > 0 {
		ph := make([]string, len(f.Severities))
		for i, s := range f.Severities {
			ph[i] = "?"
			args = append(args, int(s))
		}
		clauses = append(clauses, "severity_id IN ("+strings.Join(ph, ",")+")")
	}
	if len(f.Statuses) > 0 {
		ph := make([]string, len(f.Statuses))
		for i, s := range f.Statuses {
			ph[i] = "?"
			args = append(args, string(s))
		}
		clauses = append(clauses, "status IN ("+strings.Join(ph, ",")+")")
	}
	if f.AfterID != "" {
		clauses = append(clauses, "id > ?")
		args = append(args, f.AfterID)
	}
	if f.VendorTitle != "" {
		clauses = append(clauses, "title=?")
		args = append(args, f.VendorTitle)
	}
	if f.RuleID != "" {
		clauses = append(clauses, "rule_id=?")
		args = append(args, f.RuleID)
	}
	if f.FindingKind != "" {
		clauses = append(clauses, "finding_kind=?")
		args = append(args, f.FindingKind)
	}
	if f.VendorStatus != "" {
		clauses = append(clauses, "vendor_status=?")
		args = append(args, f.VendorStatus)
	}
	if f.ObservableValue != "" {
		clause := "EXISTS (SELECT 1 FROM alert_observables o WHERE o.sequence=alerts.sequence AND o.value=?"
		args = append(args, f.ObservableValue)
		if f.ObservableType != nil {
			clause += " AND o.type_id=?"
			args = append(args, *f.ObservableType)
		}
		clauses = append(clauses, clause+")")
	}
	if f.IP != "" {
		clauses = append(clauses, "(src_ip=? OR dst_ip=? OR EXISTS (SELECT 1 FROM alert_observables o WHERE o.sequence=alerts.sequence AND o.type_id=2 AND o.value=?))")
		args = append(args, f.IP, f.IP, f.IP)
	}
	if f.Resource != "" {
		clauses = append(clauses, `(resource_id = ? OR resource_name LIKE ? ESCAPE '\' OR EXISTS (
			SELECT 1 FROM json_each(alerts.observables) o WHERE
			(json_extract(o.value, '$.type_id')=10 AND json_extract(o.value, '$.value')=?) OR
			(json_extract(o.value, '$.type_id')=38 AND json_extract(o.value, '$.value') LIKE ? ESCAPE '\')))`)
		args = append(args, f.Resource, likePattern(f.Resource), f.Resource, likePattern(f.Resource))
	}
	if f.Keyword != "" {
		p := likePattern(f.Keyword)
		clauses = append(clauses, "(title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR alert_type LIKE ? ESCAPE '\\' OR resource_name LIKE ? ESCAPE '\\')")
		args = append(args, p, p, p, p)
	}
	timeField := "event_time"
	if f.TimeField == "ingested_at" || f.TimeField == "source_updated_at" {
		timeField = f.TimeField
	}
	if f.Start != nil {
		clauses = append(clauses, timeField+" >= ?")
		args = append(args, millis(*f.Start))
	}
	if f.End != nil {
		clauses = append(clauses, timeField+" <= ?")
		args = append(args, millis(*f.End))
	}
	if f.GroupBy != "" && len(f.GroupKey) > 0 {
		gw, ga := buildGroupWhere(f)
		if gw == "" {
			clauses = append(clauses, "1=0")
		} else {
			clauses = append(clauses, gw)
			args = append(args, ga...)
		}
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func buildGroupWhere(f model.AlertFilter) (string, []any) {
	if f.GroupBy.UsesAssetContext() {
		return contextGroupWhere(f)
	}
	if id := f.GroupKey["singleton"]; id != "" {
		return "id = ?", []any{id}
	}
	clauses := make([]string, 0, 6)
	args := make([]any, 0, 6)
	add := func(column string) {
		v, ok := f.GroupKey[column]
		if !ok {
			return
		}
		clauses = append(clauses, column+" = ?")
		args = append(args, v)
	}
	addAs := func(column, key string) {
		if v, ok := f.GroupKey[key]; ok {
			clauses = append(clauses, column+" = ?")
			args = append(args, v)
		}
	}
	switch f.GroupBy {
	case model.GroupByTypeAsset:
		for _, col := range []string{"provider", "account_id", "region", "product", "alert_type", "resource_id"} {
			if _, ok := f.GroupKey[col]; !ok {
				return "", nil
			}
			add(col)
		}
	case model.GroupBySignature:
		for _, col := range []string{"provider", "account_id", "account_uid", "region", "product", "rule_id", "resource_id"} {
			add(col)
		}
		addAs("src_ip", "source_ip")
	case model.GroupByAsset:
		for _, col := range []string{"provider", "account_id", "region", "resource_id"} {
			add(col)
		}
	case model.GroupBySource:
		addAs("src_ip", "source_ip")
		add("alert_type")
	default:
		return "", nil
	}
	return strings.Join(clauses, " AND "), args
}

func likePattern(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return "%" + s + "%"
}

// --------------------------------------------------------------- sync state

func (s *SQLite) GetSyncState(ctx context.Context, accountID string) (*model.SyncState, error) {
	var st model.SyncState
	var cursor, coverageStart, pendingStart, pendingEnd, lastSuccess, lastAttempt, lastErrorAt, updated int64
	var sourceError string
	err := s.db.QueryRowContext(ctx, `
		SELECT account_id, coverage_start, cursor_end, pending_start, pending_end, pending_token,
		       last_success_at, last_attempt_at, last_error, last_error_at,
		       last_duration_ms, items_last_run, consecutive_failures, updated_at, source_error
		FROM sync_states WHERE account_id=?`, accountID).
		Scan(&st.AccountID, &coverageStart, &cursor, &pendingStart, &pendingEnd, &st.PendingToken,
			&lastSuccess, &lastAttempt, &st.LastError, &lastErrorAt,
			&st.LastDurationMS, &st.ItemsLastRun, &st.ConsecutiveFailures, &updated, &sourceError)
	if errors.Is(err, sql.ErrNoRows) {
		st.AccountID = accountID
		err = nil
	}
	if err != nil {
		return nil, err
	}
	if sourceError != "" {
		if err := json.Unmarshal([]byte(sourceError), &st.LastSourceError); err != nil {
			return nil, err
		}
	}
	st.CoverageStart = fromMillis(coverageStart)
	st.CursorEnd = fromMillis(cursor)
	st.PendingStart = fromMillis(pendingStart)
	st.PendingEnd = fromMillis(pendingEnd)
	st.LastSuccessAt = ptrTime(lastSuccess)
	st.LastAttemptAt = ptrTime(lastAttempt)
	st.LastErrorAt = ptrTime(lastErrorAt)
	st.UpdatedAt = fromMillis(updated)
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ingest_failures WHERE account_id=?`, accountID).Scan(&st.FailedRecords); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *SQLite) SaveSyncState(ctx context.Context, st *model.SyncState) error {
	st.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sync_states (account_id, coverage_start, cursor_end, pending_start, pending_end, pending_token,
			last_success_at, last_attempt_at, last_error, last_error_at,
			last_duration_ms, items_last_run, consecutive_failures, updated_at, source_error)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(account_id) DO UPDATE SET
			coverage_start=excluded.coverage_start,
			cursor_end=excluded.cursor_end,
			pending_start=excluded.pending_start,
			pending_end=excluded.pending_end,
			pending_token=excluded.pending_token,
			last_success_at=excluded.last_success_at,
			last_attempt_at=excluded.last_attempt_at,
			last_error=excluded.last_error,
			source_error=excluded.source_error,
			last_error_at=excluded.last_error_at,
			last_duration_ms=excluded.last_duration_ms,
			items_last_run=excluded.items_last_run,
			consecutive_failures=excluded.consecutive_failures,
			updated_at=excluded.updated_at`,
		st.AccountID, millis(st.CoverageStart), millis(st.CursorEnd), millis(st.PendingStart), millis(st.PendingEnd), st.PendingToken,
		millisPtr(st.LastSuccessAt), millisPtr(st.LastAttemptAt),
		st.LastError, millisPtr(st.LastErrorAt), st.LastDurationMS, st.ItemsLastRun, st.ConsecutiveFailures, millis(st.UpdatedAt), sourceErrorJSON(st.LastSourceError))
	return err
}

func (s *SQLite) StartSyncRun(ctx context.Context, run *model.SyncRun) error {
	if run.ID == "" {
		run.ID = uuid.NewString()
	}
	if run.StartedAt.IsZero() {
		run.StartedAt = time.Now().UTC()
	}
	if run.Status == "" {
		run.Status = "running"
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sync_runs (id, account_id, provider, trigger, status, started_at, finished_at,
			pages, fetched, created, updated, failed, error, duration_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		run.ID, run.AccountID, run.Provider, run.Trigger, run.Status, millis(run.StartedAt), 0,
		run.Pages, run.Fetched, run.Created, run.Updated, run.Failed, run.Error, 0)
	return err
}

func (s *SQLite) FinishSyncRun(ctx context.Context, run *model.SyncRun) error {
	finished := time.Now().UTC()
	if run.FinishedAt != nil {
		finished = *run.FinishedAt
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE sync_runs SET status=?, finished_at=?, pages=?, fetched=?, created=?, updated=?, failed=?, error=?, duration_ms=?, source_error=?
		WHERE id=?`,
		run.Status, millis(finished), run.Pages, run.Fetched, run.Created, run.Updated, run.Failed, run.Error, run.DurationMS, sourceErrorJSON(run.SourceError), run.ID)
	return err
}

func (s *SQLite) ListSyncRuns(ctx context.Context, accountID string, limit int) ([]model.SyncRun, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `SELECT id, account_id, provider, trigger, status, started_at, finished_at,
		pages, fetched, created, updated, failed, error, duration_ms, source_error FROM sync_runs`
	args := []any{}
	if accountID != "" {
		query += ` WHERE account_id=?`
		args = append(args, accountID)
	}
	query += ` ORDER BY started_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SyncRun
	for rows.Next() {
		var r model.SyncRun
		var started, finished int64
		var sourceError string
		if err := rows.Scan(&r.ID, &r.AccountID, &r.Provider, &r.Trigger, &r.Status, &started, &finished,
			&r.Pages, &r.Fetched, &r.Created, &r.Updated, &r.Failed, &r.Error, &r.DurationMS, &sourceError); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(sourceError), &r.SourceError); err != nil {
			return nil, err
		}
		r.StartedAt = fromMillis(started)
		r.FinishedAt = ptrTime(finished)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ----------------------------------------------------------------- helpers

func millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func millisPtr(t *time.Time) int64 {
	if t == nil || t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMillis(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func ptrTime(v int64) *time.Time {
	if v == 0 {
		return nil
	}
	t := fromMillis(v)
	return &t
}

func marshalList[T any](items []T) (string, error) {
	if len(items) == 0 {
		return "[]", nil
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func isUniqueViolation(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}

// Snapshot sequences freeze membership and field values across pagination,
// even while an older finding is updated or a late record is ingested.
func snapshotPrefix(f model.AlertFilter) string {
	if f.GroupBy.UsesAssetContext() {
		return contextPrefix(f)
	}
	return findingSnapshotPrefix(f)
}

func findingSnapshotPrefix(f model.AlertFilter) string {
	if f.SnapshotSequence == nil {
		return ""
	}
	seq := fmt.Sprintf("%d", *f.SnapshotSequence)
	columns := strings.Split(alertColumns+",rule_id,finding_kind,source_updated_at", ",")
	for i, column := range columns {
		column = strings.TrimSpace(column)
		if column == "status" || column == "account_name" {
			columns[i] = "current." + column + " AS " + column
		} else {
			columns[i] = "v." + column
		}
	}
	// Local annotations are current user-owned metadata, independent of the
	// immutable source version selected by the snapshot sequence.
	return "WITH alerts AS (SELECT " + strings.Join(columns, ",") + " FROM alert_versions v JOIN main.alerts current ON current.id=v.id WHERE v.sequence=(SELECT MAX(v2.sequence) FROM alert_versions v2 WHERE v2.id=v.id AND v2.sequence<=" + seq + ")) "
}
func (s *SQLite) SnapshotSequence(ctx context.Context) (int64, error) {
	var seq int64
	err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(sequence),0) FROM alert_revisions").Scan(&seq)
	return seq, err
}

func sourceErrorJSON(value *model.SourceError) string {
	data, _ := json.Marshal(value) // A SourceError contains only strings and an integer.
	return string(data)
}
