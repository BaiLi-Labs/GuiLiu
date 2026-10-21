package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func (s *SQLite) SaveIngestFailure(ctx context.Context, f *model.IngestFailure) error {
	if f.ID == "" {
		f.ID = fmt.Sprintf("%x", sha256.Sum256(append([]byte(f.AccountID+"\x00"), f.Raw...)))
	}
	if f.IngestedAt.IsZero() {
		f.IngestedAt = time.Now().UTC()
	}
	now := millis(time.Now().UTC())
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO ingest_failures (id, account_id, raw, ingested_at, mapper_version, error, attempts, created_at, last_attempt_at)
		VALUES (?,?,?,?,?,?,1,?,?)
		ON CONFLICT(id) DO UPDATE SET mapper_version=excluded.mapper_version,
			error=excluded.error, attempts=ingest_failures.attempts+1, last_attempt_at=excluded.last_attempt_at`,
		f.ID, f.AccountID, string(f.Raw), millis(f.IngestedAt), f.MapperVersion, f.Error, now, now)
	return err
}

// Oldest attempts first ensures a permanently bad record cannot starve others.
func (s *SQLite) ListIngestFailures(ctx context.Context, accountID string, limit int) ([]model.IngestFailure, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM ingest_failures WHERE account_id=?`, accountID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, account_id, raw, ingested_at, mapper_version, error, attempts, created_at, last_attempt_at
		FROM ingest_failures WHERE account_id=? ORDER BY last_attempt_at, id LIMIT ?`, accountID, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]model.IngestFailure, 0)
	for rows.Next() {
		var f model.IngestFailure
		var raw string
		var end, created, attempted int64
		if err := rows.Scan(&f.ID, &f.AccountID, &raw, &end, &f.MapperVersion, &f.Error, &f.Attempts, &created, &attempted); err != nil {
			return nil, 0, err
		}
		f.Raw = json.RawMessage(raw)
		f.IngestedAt, f.CreatedAt, f.LastAttemptAt = fromMillis(end), fromMillis(created), fromMillis(attempted)
		items = append(items, f)
	}
	return items, total, rows.Err()
}

func (s *SQLite) DeleteIngestFailure(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ingest_failures WHERE id=?`, id)
	return err
}
