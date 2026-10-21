package store

import (
	"context"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// A stable ID cursor remains valid even when remapping corrects event times.
func (s *SQLite) ListReplayAlerts(ctx context.Context, f model.AlertFilter, mapperVersion, afterID string) ([]model.AlertRecord, error) {
	where, args := buildAlertWhere(f)
	if where == "" {
		where = " WHERE 1=1"
	}
	where += " AND id > ?"
	args = append(args, afterID)
	if mapperVersion != "" {
		where += " AND mapper_version=?"
		args = append(args, mapperVersion)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+alertColumns+`, ocsf, raw FROM alerts`+where+` ORDER BY id LIMIT 200`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []model.AlertRecord
	for rows.Next() {
		r, err := scanAlert(rows, true)
		if err != nil {
			return nil, err
		}
		items = append(items, *r)
	}
	return items, rows.Err()
}
