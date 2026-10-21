package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func (s *SQLite) ListAlertChanges(ctx context.Context, cursor string, limit int, provider, accountID string) (*model.ChangePage, error) {
	after := int64(0)
	if cursor != "" {
		n, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("cursor must be a non-negative change sequence")
		}
		after = n
	}
	if limit < 1 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	high, err := s.SnapshotSequence(ctx)
	if err != nil {
		return nil, err
	}
	if after > high {
		return nil, fmt.Errorf("cursor is ahead of this database's change log")
	}
	where, args := "sequence > ? AND sequence <= ?", []any{after, high}
	if provider != "" {
		where += " AND provider=?"
		args = append(args, provider)
	}
	if accountID != "" {
		where += " AND account_id=?"
		args = append(args, accountID)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sequence,alert_id,provider,account_id,change_type,revision,captured_at,projection_updated FROM alert_revisions WHERE `+where+` ORDER BY sequence LIMIT ?`, append(args, limit+1)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	page := &model.ChangePage{Changes: []model.AlertChange{}, NextCursor: strconv.FormatInt(after, 10)}
	for rows.Next() {
		var c model.AlertChange
		var captured int64
		if err := rows.Scan(&c.Sequence, &c.AlertID, &c.Provider, &c.AccountID, &c.ChangeType, &c.Revision, &captured, &c.ProjectionUpdated); err != nil {
			return nil, err
		}
		if len(page.Changes) == limit {
			page.HasMore = true
			break
		}
		c.CapturedAt = fromMillis(captured)
		page.Changes = append(page.Changes, c)
		page.NextCursor = strconv.FormatInt(c.Sequence, 10)
	}
	if !page.HasMore {
		page.NextCursor = strconv.FormatInt(high, 10)
	}
	return page, rows.Err()
}

// beforeRevision is exclusive. Each page can continue all the way to revision 1.
func (s *SQLite) AlertRevisionPage(ctx context.Context, id string, beforeRevision, limit int) ([]model.AlertRevision, error) {
	if limit < 1 {
		limit = 50
	}
	if limit > 201 {
		limit = 201
	}
	where, args := "alert_id=?", []any{id}
	if beforeRevision > 0 {
		where += " AND revision < ?"
		args = append(args, beforeRevision)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,sequence,revision,change_type,mapper_version,raw_hash,snapshot,captured_at,raw,ocsf,(SELECT status FROM alerts WHERE alerts.id=alert_revisions.alert_id),(SELECT account_name FROM alerts WHERE alerts.id=alert_revisions.alert_id) FROM alert_revisions WHERE `+where+` ORDER BY revision DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AlertRevision{}
	for rows.Next() {
		var r model.AlertRevision
		var snapshot, raw, ocsf, annotation, accountName string
		var captured int64
		if err := rows.Scan(&r.ID, &r.Sequence, &r.Revision, &r.ChangeType, &r.MapperVersion, &r.RawHash, &snapshot, &captured, &raw, &ocsf, &annotation, &accountName); err != nil {
			return nil, err
		}
		var rec model.AlertRecord
		if err := json.Unmarshal([]byte(snapshot), &rec); err != nil {
			return nil, err
		}
		rec.Raw = json.RawMessage(raw)
		if ocsf != "" {
			rec.OCSF = json.RawMessage(ocsf)
		} else {
			rec.OCSF = nil
		}
		rec.Status = model.AlertStatus(annotation)
		rec.AccountName = accountName
		r.ProjectionUpdated = rec.ProjectionUpdated
		r.Record = &rec
		r.AlertID = rec.ID
		r.CapturedAt = fromMillis(captured)
		r.Title = rec.Title
		r.Severity = rec.Severity
		r.VendorStatus = rec.VendorStatus
		r.Raw = rec.Raw
		r.OCSF = rec.OCSF
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLite) GetAlertRevision(ctx context.Context, id string, revision int) (*model.AlertRecord, error) {
	var snapshot, raw, ocsf, annotation, accountName string
	if err := s.db.QueryRowContext(ctx, "SELECT snapshot,raw,ocsf,(SELECT status FROM alerts WHERE alerts.id=alert_revisions.alert_id),(SELECT account_name FROM alerts WHERE alerts.id=alert_revisions.alert_id) FROM alert_revisions WHERE alert_id=? AND revision=?", id, revision).Scan(&snapshot, &raw, &ocsf, &annotation, &accountName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var rec model.AlertRecord
	if err := json.Unmarshal([]byte(snapshot), &rec); err != nil {
		return nil, err
	}
	rec.Raw = json.RawMessage(raw)
	if ocsf != "" {
		rec.OCSF = json.RawMessage(ocsf)
	} else {
		rec.OCSF = nil
	}
	rec.Status = model.AlertStatus(annotation)
	rec.AccountName = accountName
	return &rec, nil
}

func (s *SQLite) GetAlertAtSnapshot(ctx context.Context, id string, sequence int64) (*model.AlertRecord, error) {
	var snapshot, raw, ocsf, annotation, accountName string
	err := s.db.QueryRowContext(ctx, "SELECT snapshot,raw,ocsf,(SELECT status FROM alerts WHERE alerts.id=alert_revisions.alert_id),(SELECT account_name FROM alerts WHERE alerts.id=alert_revisions.alert_id) FROM alert_revisions WHERE alert_id=? AND sequence<=? AND projection_updated=1 ORDER BY sequence DESC LIMIT 1", id, sequence).Scan(&snapshot, &raw, &ocsf, &annotation, &accountName)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec model.AlertRecord
	if err = json.Unmarshal([]byte(snapshot), &rec); err != nil {
		return nil, err
	}
	rec.Raw = json.RawMessage(raw)
	if ocsf != "" {
		rec.OCSF = json.RawMessage(ocsf)
	} else {
		rec.OCSF = nil
	}
	rec.Status = model.AlertStatus(annotation)
	rec.AccountName = accountName
	return &rec, nil
}

func (s *SQLite) ListUnconfiguredSources(ctx context.Context, provider, accountID string) ([]model.Account, error) {
	where, args := "accounts.id IS NULL", []any{}
	if provider != "" {
		where += " AND alerts.provider=?"
		args = append(args, provider)
	}
	if accountID != "" {
		where += " AND alerts.account_id=?"
		args = append(args, accountID)
	}
	rows, err := s.db.QueryContext(ctx, "SELECT alerts.account_id,alerts.provider,MIN(alerts.account_name) FROM alerts LEFT JOIN accounts ON accounts.id=alerts.account_id WHERE "+where+" GROUP BY alerts.account_id,alerts.provider", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []model.Account{}
	for rows.Next() {
		var a model.Account
		if err := rows.Scan(&a.ID, &a.Provider, &a.Name); err != nil {
			return nil, err
		}
		items = append(items, a)
	}
	return items, rows.Err()
}
