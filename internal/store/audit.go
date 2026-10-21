package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func (s *SQLite) StartAuditEvent(ctx context.Context, event *model.AuditEvent) error {
	if event.RequestID == "" || event.StartedAt.IsZero() || event.Outcome != "in_progress" || event.FinishedAt != nil {
		return fmt.Errorf("invalid audit start")
	}
	// Allocate and store the public sequence atomically with the initial event.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, `INSERT INTO audit_events(request_id,surface,operation,tool,user_id,username,api_key_id,outcome,started_at,record) VALUES(?,?,?,?,?,?,?,?,?,?)`, event.RequestID, event.Surface, event.Operation, event.Tool, event.UserID, event.Username, event.APIKeyID, event.Outcome, millis(event.StartedAt), string(raw))
	if err != nil {
		return err
	}
	event.Sequence, err = r.LastInsertId()
	if err != nil {
		return err
	}
	raw, err = json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE audit_events SET record=? WHERE sequence=?`, string(raw), event.Sequence); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite) FinishAuditEvent(ctx context.Context, event *model.AuditEvent) error {
	if event.FinishedAt == nil || event.Outcome == "in_progress" {
		return fmt.Errorf("invalid audit completion")
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	r, err := s.db.ExecContext(ctx, `UPDATE audit_events SET operation=?,tool=?,user_id=?,username=?,api_key_id=?,outcome=?,record=? WHERE sequence=? AND request_id=? AND outcome='in_progress'`, event.Operation, event.Tool, event.UserID, event.Username, event.APIKeyID, event.Outcome, string(raw), event.Sequence, event.RequestID)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

// Resolve HTTP authentication durably before the authenticated handler runs.
func (s *SQLite) IdentifyAuditEvent(ctx context.Context, event *model.AuditEvent) error {
	if event.Outcome != "in_progress" || event.FinishedAt != nil {
		return fmt.Errorf("invalid audit identity update")
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	r, err := s.db.ExecContext(ctx, `UPDATE audit_events SET user_id=?,username=?,api_key_id=?,record=? WHERE sequence=? AND request_id=? AND outcome='in_progress'`, event.UserID, event.Username, event.APIKeyID, string(raw), event.Sequence, event.RequestID)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}

func (s *SQLite) ListAuditEvents(ctx context.Context, f model.AuditFilter) ([]model.AuditEvent, error) {
	clauses, args := []string{"1=1"}, []any{}
	for _, v := range []struct{ key, value string }{{"request_id", f.RequestID}, {"user_id", f.UserID}, {"username", f.Username}, {"api_key_id", f.APIKeyID}, {"surface", f.Surface}, {"operation", f.Operation}, {"tool", f.Tool}, {"outcome", f.Outcome}} {
		if v.value != "" {
			clauses = append(clauses, v.key+"=?")
			args = append(args, v.value)
		}
	}
	if f.BeforeSequence > 0 {
		clauses = append(clauses, "sequence<?")
		args = append(args, f.BeforeSequence)
	}
	if f.Start != nil {
		clauses = append(clauses, "started_at>=?")
		args = append(args, millis(*f.Start))
	}
	if f.End != nil {
		clauses = append(clauses, "started_at<=?")
		args = append(args, millis(*f.End))
	}
	limit := f.Limit
	if limit < 1 || limit > 101 {
		limit = 101
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT record FROM audit_events WHERE `+strings.Join(clauses, " AND ")+` ORDER BY sequence DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AuditEvent{}
	for rows.Next() {
		var raw string
		var e model.AuditEvent
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// A bounded maintenance batch avoids monopolizing the single SQLite writer.
func (s *SQLite) PruneAuditEvents(ctx context.Context, before time.Time) (int64, error) {
	r, err := s.db.ExecContext(ctx, `DELETE FROM audit_events WHERE sequence IN (SELECT sequence FROM audit_events WHERE started_at<? ORDER BY started_at LIMIT 10000)`, millis(before))
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}
