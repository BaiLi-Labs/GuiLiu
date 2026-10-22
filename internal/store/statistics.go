package store

import (
	"context"
	"database/sql"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func (s *SQLite) ObservedEventRanges(ctx context.Context, f model.AlertFilter) (map[string]model.ObservedEventRange, error) {
	where, args := buildAlertWhere(f)
	rows, err := s.db.QueryContext(ctx, snapshotPrefix(f)+`SELECT account_id, COUNT(*), MIN(NULLIF(event_time,0)), MAX(NULLIF(event_time,0)) FROM alerts`+where+` GROUP BY account_id`, withContextArgs(f, args)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]model.ObservedEventRange{}
	for rows.Next() {
		var id string
		var v model.ObservedEventRange
		var start, end sql.NullInt64
		if err := rows.Scan(&id, &v.FindingCount, &start, &end); err != nil {
			return nil, err
		}
		if start.Valid {
			t := fromMillis(start.Int64)
			v.Start = &t
		}
		if end.Valid {
			t := fromMillis(end.Int64)
			v.End = &t
		}
		out[id] = v
	}
	return out, rows.Err()
}

func fieldDistributions(ctx context.Context, tx *sql.Tx, f model.AlertFilter, total int) (map[string]model.FieldDistribution, error) {
	opts, err := f.StatsOptions.Normalize()
	if err != nil {
		return nil, err
	}
	where, args := buildAlertWhere(f)
	args = withContextArgs(f, args)
	out := map[string]model.FieldDistribution{}
	for _, dimension := range opts.TopBy {
		// Only literal expressions from this allowlist enter SQL. No caller SQL.
		expr := map[string]string{"title": "title", "source_ip": "src_ip", "destination_ip": "dst_ip", "source_country": "COALESCE(json_extract(canonical,'$.source_country'),'')", "severity": "severity", "provider": "provider", "alert_type": "alert_type", "rule_id": "rule_id", "severity_day": "strftime('%Y-%m-%d',event_time/1000,'unixepoch')"}[dimension]
		severity := "''"
		if dimension == "severity_day" {
			severity = "severity"
		}
		base := snapshotPrefix(f) + `SELECT ` + expr + ` AS key, ` + severity + ` AS severity_key, COUNT(*) AS n FROM alerts` + where + ` GROUP BY key,severity_key`
		v := model.FieldDistribution{Top: []model.DistributionCount{}, TopN: opts.TopN}
		var present int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(n),0) FROM (`+base+`) WHERE key IS NOT NULL AND key<>''`, args...).Scan(&v.DistinctCount, &present); err != nil {
			return nil, err
		}
		v.MissingCount = total - present
		rows, err := tx.QueryContext(ctx, `SELECT key,severity_key,n FROM (`+base+`) WHERE key IS NOT NULL AND key<>'' ORDER BY n DESC,key COLLATE BINARY ASC,severity_key COLLATE BINARY ASC LIMIT ?`, append(append([]any{}, args...), opts.TopN)...)
		if err != nil {
			return nil, err
		}
		v.OtherCount = present
		for rows.Next() {
			var count model.DistributionCount
			if err := rows.Scan(&count.Key, &count.Severity, &count.Count); err != nil {
				rows.Close()
				return nil, err
			}
			v.Top = append(v.Top, count)
			v.OtherCount -= count.Count
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		v.HasMore = v.DistinctCount > len(v.Top)
		out[dimension] = v
	}
	return out, nil
}
