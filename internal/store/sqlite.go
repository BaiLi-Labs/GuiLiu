package store

import (
	"context"
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
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(0)

	s := &SQLite{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLite) migrate() error {
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	// Additive migrations for databases created before these columns existed.
	additive := []struct {
		name string
		ddl  string
	}{
		{"observables", `ALTER TABLE alerts ADD COLUMN observables TEXT NOT NULL DEFAULT '[]'`},
		{"evidences", `ALTER TABLE alerts ADD COLUMN evidences TEXT NOT NULL DEFAULT '[]'`},
	}
	for _, col := range []struct {
		table string
		name  string
		ddl   string
	}{
		{"sync_states", "pending_start", `ALTER TABLE sync_states ADD COLUMN pending_start INTEGER NOT NULL DEFAULT 0`},
		{"sync_states", "pending_end", `ALTER TABLE sync_states ADD COLUMN pending_end INTEGER NOT NULL DEFAULT 0`},
		{"sync_states", "pending_token", `ALTER TABLE sync_states ADD COLUMN pending_token TEXT NOT NULL DEFAULT ''`},
	} {
		exists, err := s.hasColumn(col.table, col.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := s.db.Exec(col.ddl); err != nil {
				return fmt.Errorf("migrate %s.%s: %w", col.table, col.name, err)
			}
		}
	}
	for _, col := range additive {
		exists, err := s.hasColumn("alerts", col.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := s.db.Exec(col.ddl); err != nil {
				return fmt.Errorf("migrate alerts.%s: %w", col.name, err)
			}
		}
	}
	return nil
}

func (s *SQLite) hasColumn(table, column string) (bool, error) {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
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
	a.UpdatedAt = time.Now().UTC()
	options, err := json.Marshal(a.Options)
	if err != nil {
		return err
	}
	var res sql.Result
	if credential != nil {
		res, err = s.db.ExecContext(ctx, `
			UPDATE accounts SET name=?, account_uid=?, region=?, enabled=?, options=?, credential=?, access_key_hint=?, updated_at=?
			WHERE id=?`,
			a.Name, a.AccountUID, a.Region, boolInt(a.Enabled), string(options), *credential, a.AccessKeyHint, millis(a.UpdatedAt), a.ID)
	} else {
		res, err = s.db.ExecContext(ctx, `
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
	return nil
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

func (s *SQLite) DeleteAccount(ctx context.Context, id string, purgeAlerts bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if purgeAlerts {
		if _, err := tx.ExecContext(ctx, `DELETE FROM alerts WHERE account_id=?`, id); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sync_runs WHERE account_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sync_states WHERE account_id=?`, id); err != nil {
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

func (s *SQLite) UpsertAlert(ctx context.Context, rec *model.AlertRecord) (bool, error) {
	if rec.ExternalID == "" {
		return false, errors.New("alert external id is required")
	}
	now := time.Now().UTC()
	if rec.EventTime.IsZero() {
		rec.EventTime = now
	}
	if rec.FirstSeenAt.IsZero() {
		rec.FirstSeenAt = rec.EventTime
	}
	if rec.LastSeenAt.IsZero() {
		rec.LastSeenAt = rec.EventTime
	}
	if rec.Status == "" {
		rec.Status = model.StatusOpen
	}
	if rec.ID == "" {
		rec.ID = uuid.NewString()
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now
	if len(rec.Raw) == 0 {
		rec.Raw = json.RawMessage(`{}`)
	}
	if len(rec.OCSF) == 0 {
		rec.OCSF = json.RawMessage(`{}`)
	}

	observablesJSON, err := marshalList(rec.Observables)
	if err != nil {
		return false, err
	}
	evidencesJSON, err := marshalList(rec.Evidences)
	if err != nil {
		return false, err
	}
	// The per-alert cloud account id (Tencent UIN, Aliyun UID) is more useful
	// than the configured account label, so it wins when present.
	accountUID := rec.AccountUID
	if rec.CloudAccountUID != "" {
		accountUID = rec.CloudAccountUID
	}

	key := rec.DedupeKey()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	var existingID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM alerts WHERE dedupe_key=?`, key).Scan(&existingID)
	created := false
	switch {
	case errors.Is(err, sql.ErrNoRows):
		created = true
		_, err = tx.ExecContext(ctx, `
			INSERT INTO alerts (
				id, provider, account_id, account_name, account_uid, product, external_id, dedupe_key,
				title, description, severity_id, severity, original_severity, vendor_status, status,
				alert_type, event_time, first_seen_at, last_seen_at, region, resource_id, resource_name,
				resource_type, src_ip, dst_ip, actor, tactic, technique, observables, evidences,
				mapper_version, ocsf, raw, created_at, updated_at
			) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			rec.ID, rec.Provider, rec.AccountID, rec.AccountName, accountUID, rec.Product, rec.ExternalID, key,
			rec.Title, rec.Description, int(rec.Severity), rec.Severity.String(), rec.OriginalSeverity, rec.VendorStatus, string(rec.Status),
			rec.AlertType, millis(rec.EventTime), millis(rec.FirstSeenAt), millis(rec.LastSeenAt), rec.Region, rec.Resource.ID, rec.Resource.Name,
			rec.Resource.Type, rec.SourceIP, rec.DestinationIP, rec.Actor, rec.Tactic, rec.Technique, observablesJSON, evidencesJSON,
			rec.MapperVersion, string(rec.OCSF), string(rec.Raw),
			millis(rec.CreatedAt), millis(rec.UpdatedAt))
	case err != nil:
		return false, err
	default:
		rec.ID = existingID
		_, err = tx.ExecContext(ctx, `
			UPDATE alerts SET
				account_name=?, account_uid=?, product=?, title=?, description=?,
				severity_id=?, severity=?, original_severity=?, vendor_status=?, alert_type=?,
				event_time=MAX(event_time, ?), first_seen_at=MIN(first_seen_at, ?), last_seen_at=MAX(last_seen_at, ?),
				region=?, resource_id=?, resource_name=?, resource_type=?, src_ip=?, dst_ip=?,
				actor=?, tactic=?, technique=?, observables=?, evidences=?, mapper_version=?, ocsf=?, raw=?, updated_at=?
			WHERE id=?`,
			rec.AccountName, accountUID, rec.Product, rec.Title, rec.Description,
			int(rec.Severity), rec.Severity.String(), rec.OriginalSeverity, rec.VendorStatus, rec.AlertType,
			millis(rec.EventTime), millis(rec.FirstSeenAt), millis(rec.LastSeenAt),
			rec.Region, rec.Resource.ID, rec.Resource.Name, rec.Resource.Type, rec.SourceIP, rec.DestinationIP,
			rec.Actor, rec.Tactic, rec.Technique, observablesJSON, evidencesJSON, rec.MapperVersion, string(rec.OCSF), string(rec.Raw), millis(rec.UpdatedAt),
			rec.ID)
	}
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return created, nil
}

const alertColumns = `id, provider, account_id, account_name, account_uid, product, external_id,
	title, description, severity_id, severity, original_severity, vendor_status, status, alert_type,
	event_time, first_seen_at, last_seen_at, region, resource_id, resource_name, resource_type,
	src_ip, dst_ip, actor, tactic, technique, observables, evidences, mapper_version, created_at, updated_at`

func (s *SQLite) GetAlert(ctx context.Context, id string) (*model.AlertRecord, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+alertColumns+`, ocsf, raw FROM alerts WHERE id=?`, id)
	return scanAlert(row, true)
}

func (s *SQLite) ListAlerts(ctx context.Context, f model.AlertFilter) ([]model.AlertRecord, int, error) {
	where, args := buildAlertWhere(f)
	countQuery := `SELECT COUNT(*) FROM alerts` + where
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
	switch f.Sort {
	case "severity", "severity_id":
		order = "severity_id DESC, event_time DESC"
	case "last_seen", "last_seen_at":
		order = "last_seen_at DESC, id DESC"
	case "first_seen", "first_seen_at":
		order = "first_seen_at DESC, id DESC"
	case "event_time", "":
	default:
		order = "event_time DESC, id DESC"
	}

	query := `SELECT ` + alertColumns + ` FROM alerts` + where + ` ORDER BY ` + order + ` LIMIT ? OFFSET ?`
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

func (s *SQLite) UpdateAlertStatus(ctx context.Context, id string, status model.AlertStatus) error {
	res, err := s.db.ExecContext(ctx, `UPDATE alerts SET status=?, updated_at=? WHERE id=?`, string(status), millis(time.Now().UTC()), id)
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
	where, args := buildAlertWhere(f)
	stats := &model.AlertStats{
		BySeverity: map[string]int{},
		ByProvider: map[string]int{},
		ByStatus:   map[string]int{},
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts`+where, args...).Scan(&stats.Total); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT severity_id, COUNT(*) FROM alerts`+where+` GROUP BY severity_id`, args...)
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
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `SELECT provider, COUNT(*) FROM alerts`+where+` GROUP BY provider`, args...)
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
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM alerts`+where+` GROUP BY status`, args...)
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
	rows.Close()

	rows, err = s.db.QueryContext(ctx, `
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
	rows.Close()

	topWhere := where
	if topWhere == "" {
		topWhere = " WHERE resource_id <> ''"
	} else {
		topWhere += " AND resource_id <> ''"
	}
	rows, err = s.db.QueryContext(ctx, `
		SELECT resource_id, MAX(resource_name), COUNT(*) AS c
		FROM alerts`+topWhere+`
		GROUP BY resource_id ORDER BY c DESC LIMIT 10`, args...)
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
	rows.Close()

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
	rec.Severity = model.Severity(severityID)
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
	if f.IP != "" {
		clauses = append(clauses, "(src_ip = ? OR dst_ip = ?)")
		args = append(args, f.IP, f.IP)
	}
	if f.Resource != "" {
		clauses = append(clauses, "(resource_id = ? OR resource_name LIKE ? ESCAPE '\\')")
		args = append(args, f.Resource, likePattern(f.Resource))
	}
	if f.Keyword != "" {
		p := likePattern(f.Keyword)
		clauses = append(clauses, "(title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' OR alert_type LIKE ? ESCAPE '\\' OR resource_name LIKE ? ESCAPE '\\')")
		args = append(args, p, p, p, p)
	}
	if f.Start != nil {
		clauses = append(clauses, "event_time >= ?")
		args = append(args, millis(*f.Start))
	}
	if f.End != nil {
		clauses = append(clauses, "event_time <= ?")
		args = append(args, millis(*f.End))
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
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
	var cursor, pendingStart, pendingEnd, lastSuccess, lastAttempt, lastErrorAt, updated int64
	err := s.db.QueryRowContext(ctx, `
		SELECT account_id, cursor_end, pending_start, pending_end, pending_token,
		       last_success_at, last_attempt_at, last_error, last_error_at,
		       last_duration_ms, items_last_run, consecutive_failures, updated_at
		FROM sync_states WHERE account_id=?`, accountID).
		Scan(&st.AccountID, &cursor, &pendingStart, &pendingEnd, &st.PendingToken,
			&lastSuccess, &lastAttempt, &st.LastError, &lastErrorAt,
			&st.LastDurationMS, &st.ItemsLastRun, &st.ConsecutiveFailures, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return &model.SyncState{AccountID: accountID}, nil
	}
	if err != nil {
		return nil, err
	}
	st.CursorEnd = fromMillis(cursor)
	st.PendingStart = fromMillis(pendingStart)
	st.PendingEnd = fromMillis(pendingEnd)
	st.LastSuccessAt = ptrTime(lastSuccess)
	st.LastAttemptAt = ptrTime(lastAttempt)
	st.LastErrorAt = ptrTime(lastErrorAt)
	st.UpdatedAt = fromMillis(updated)
	return &st, nil
}

func (s *SQLite) SaveSyncState(ctx context.Context, st *model.SyncState) error {
	st.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sync_states (account_id, cursor_end, pending_start, pending_end, pending_token,
			last_success_at, last_attempt_at, last_error, last_error_at,
			last_duration_ms, items_last_run, consecutive_failures, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(account_id) DO UPDATE SET
			cursor_end=excluded.cursor_end,
			pending_start=excluded.pending_start,
			pending_end=excluded.pending_end,
			pending_token=excluded.pending_token,
			last_success_at=excluded.last_success_at,
			last_attempt_at=excluded.last_attempt_at,
			last_error=excluded.last_error,
			last_error_at=excluded.last_error_at,
			last_duration_ms=excluded.last_duration_ms,
			items_last_run=excluded.items_last_run,
			consecutive_failures=excluded.consecutive_failures,
			updated_at=excluded.updated_at`,
		st.AccountID, millis(st.CursorEnd), millis(st.PendingStart), millis(st.PendingEnd), st.PendingToken,
		millisPtr(st.LastSuccessAt), millisPtr(st.LastAttemptAt),
		st.LastError, millisPtr(st.LastErrorAt), st.LastDurationMS, st.ItemsLastRun, st.ConsecutiveFailures, millis(st.UpdatedAt))
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
		UPDATE sync_runs SET status=?, finished_at=?, pages=?, fetched=?, created=?, updated=?, failed=?, error=?, duration_ms=?
		WHERE id=?`,
		run.Status, millis(finished), run.Pages, run.Fetched, run.Created, run.Updated, run.Failed, run.Error, run.DurationMS, run.ID)
	return err
}

func (s *SQLite) ListSyncRuns(ctx context.Context, accountID string, limit int) ([]model.SyncRun, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `SELECT id, account_id, provider, trigger, status, started_at, finished_at,
		pages, fetched, created, updated, failed, error, duration_ms FROM sync_runs`
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
		if err := rows.Scan(&r.ID, &r.AccountID, &r.Provider, &r.Trigger, &r.Status, &started, &finished,
			&r.Pages, &r.Fetched, &r.Created, &r.Updated, &r.Failed, &r.Error, &r.DurationMS); err != nil {
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
