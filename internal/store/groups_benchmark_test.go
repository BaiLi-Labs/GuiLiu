package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// Run explicitly with -run '^$' -bench BenchmarkAlertGroups300K -benchtime=1x.
// Each alert has ~1 KiB of raw/OCSF payload. Benchmark setup is not timed.
func BenchmarkAlertGroups300K(b *testing.B) {
	ctx := context.Background()
	path := filepath.Join(b.TempDir(), "groups.db")
	st, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO alerts
		(id,provider,account_id,account_name,product,external_id,dedupe_key,title,severity_id,severity,alert_type,
		event_time,first_seen_at,last_seen_at,region,resource_id,resource_name,src_ip,ocsf,raw,created_at,updated_at,canonical,raw_hash,content_hash,revision,sequence,ingested_at,last_ingested_at,rule_id,account_uid)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	payload := `{"pad":"` + strings.Repeat("x", 512) + `"}`
	providers := []string{"tencent", "aliyun", "aws"}
	for i := 0; i < 300000; i++ {
		g := i % 3000
		id := fmt.Sprintf("alert-%06d", i)
		ts := now.Add(-time.Duration(i/10000)*24*time.Hour - time.Duration(i%10000)*time.Second).UnixMilli()
		_, err := stmt.ExecContext(ctx, id, providers[g%3], fmt.Sprintf("acct-%d", g%3), "prod",
			fmt.Sprintf("product-%d", g%3), id, id, "synthetic alert", g%5+1, "medium", fmt.Sprintf("type-%d", g%25),
			ts, ts, ts, "region-1", fmt.Sprintf("asset-%d", g%1000), fmt.Sprintf("host-%d", g%1000),
			fmt.Sprintf("203.0.%d.%d", g/256, g%256), payload, payload, ts, ts, "{}", "raw-hash", "fingerprint", 1, i+1, ts, ts, fmt.Sprintf("rule-%d", g%25), fmt.Sprintf("cloud-%d", g%3))
		if err != nil {
			b.Fatal(err)
		}
	}
	if err := stmt.Close(); err != nil {
		b.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO alert_revisions(sequence,id,alert_id,revision,provider,account_id,change_type,mapper_version,raw_hash,snapshot,change_hash,captured_at)
 SELECT sequence,id,id,revision,provider,account_id,'created',mapper_version,raw_hash,'{}',content_hash,created_at FROM alerts`); err != nil {
		b.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO alert_versions SELECT `+alertColumns+`,rule_id,finding_kind,source_updated_at FROM alerts`); err != nil {
		b.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		b.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	databaseMiB := float64(info.Size()) / (1024 * 1024)
	measure := func(b *testing.B, days int, by model.AlertGroupBy) {
		start := now.Add(-time.Duration(days) * 24 * time.Hour)
		sequence := int64(300000)
		f := model.AlertFilter{SnapshotSequence: &sequence, Start: &start, End: &now, GroupBy: by, Limit: 50}
		b.ReportAllocs()
		b.ReportMetric(databaseMiB, "MiB/db")
		for i := 0; i < b.N; i++ {
			groups, total, err := st.ListAlertGroups(ctx, f)
			if err != nil {
				b.Fatal(err)
			}
			if len(groups) != 50 || total < 50 {
				b.Fatalf("unexpected page: groups=%d total=%d", len(groups), total)
			}
			b.ReportMetric(float64(total), "groups")
		}
	}
	for _, days := range []int{1, 7, 30} {
		for _, by := range []model.AlertGroupBy{model.GroupByTypeAsset, model.GroupBySignature, model.GroupByAsset, model.GroupBySource} {
			b.Run(fmt.Sprintf("%dd/%s", days, by), func(b *testing.B) { measure(b, days, by) })
		}
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE alert_versions SET alert_type=external_id,rule_id=external_id`); err != nil {
		b.Fatal(err)
	}
	for _, by := range []model.AlertGroupBy{model.GroupByTypeAsset, model.GroupBySignature} {
		b.Run("high_cardinality/"+string(by), func(b *testing.B) { measure(b, 30, by) })
	}
}
