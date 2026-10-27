package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func (s *SQLite) AssetSnapshotSequence(ctx context.Context) (int64, error) {
	var seq int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(sequence),0) FROM asset_revision_sequences`).Scan(&seq)
	return seq, err
}

// contextPrefix joins only explicit primary host identities and source references.
// It deliberately does not assign a Finding to a traffic interface, infer effective
// security policies, traverse arbitrary networks, or read vendor payloads.
func contextPrefix(f model.AlertFilter) string {
	prefix := findingSnapshotPrefix(f)
	if prefix == "" {
		prefix = "WITH "
	} else {
		prefix = strings.TrimSpace(prefix) + ", "
	}
	watermark := `(SELECT COALESCE(MAX(sequence),0) FROM asset_revision_sequences)`
	if f.AssetSnapshotSequence != nil {
		watermark = fmt.Sprint(*f.AssetSnapshotSequence)
	}
	baseWhere, _ := contextBaseWhere(f)
	prefix += `eligible AS (SELECT * FROM alerts` + baseWhere + `), asset_at AS (
 SELECT r.asset_id, r.revision, r.record,
 json_extract(r.record,'$.provider') provider,
 json_extract(r.record,'$.account_uid') account_uid,
 json_extract(r.record,'$.region') region,
 json_extract(r.record,'$.resource_id') resource_id,
 json_extract(r.record,'$.resource_type') resource_type
 FROM asset_revisions r JOIN asset_revision_sequences s ON s.asset_id=r.asset_id AND s.revision=r.revision
 WHERE s.sequence=(SELECT MAX(s2.sequence) FROM asset_revision_sequences s2 WHERE s2.asset_id=r.asset_id AND s2.sequence<=` + watermark + `)
 ), hosts AS (
 SELECT a.id finding_id, h.asset_id, h.record
 FROM eligible a JOIN asset_at h ON h.provider=a.provider AND h.account_uid=` + resourceOwnerExpr("a") + ` AND h.region=a.region
 AND ` + resourceOwnerExpr("a") + `<>'' AND a.resource_id<>'' AND (
 (a.provider='tencent' AND a.resource_type='host' AND h.resource_type='cvm' AND a.resource_id=h.resource_id) OR
 (a.provider='aliyun' AND a.resource_type='host' AND h.resource_type='ecs' AND a.resource_id=h.resource_id) OR
 (a.provider='huawei' AND lower(a.resource_type) IN ('host','server','vm','ecs') AND h.resource_type='ecs' AND a.resource_id=h.resource_id) OR
 (a.provider='aws' AND lower(a.resource_type) IN ('host','instance','awsec2instance','ec2 instance','ec2') AND h.resource_type='ec2'
 AND a.resource_id IN (h.resource_id,'arn:aws:ec2:'||h.region||':'||h.account_uid||':instance/'||h.resource_id)) OR
 (a.provider='gcp' AND lower(a.resource_type) IN ('host','instance','instances','gce','computeinstance','google.compute.instance') AND h.resource_type='gce'
 AND a.resource_id IN (h.resource_id,'//compute.googleapis.com/'||h.resource_id)) OR
 (a.provider='azure' AND lower(a.resource_type) IN ('host','vm','virtualmachine','microsoft.compute/virtualmachines') AND h.resource_type='vm' AND lower(a.resource_id)=h.resource_id)
 )
 ), direct_refs AS (
 SELECT h.finding_id,h.asset_id,h.record,j.value ref,h.asset_id source_asset_id,json_extract(h.record,'$.revision') source_revision FROM hosts h, json_each(h.record,'$.references') j
 ), refs AS (
 SELECT * FROM direct_refs
 UNION ALL
 SELECT d.finding_id,d.asset_id,d.record,j.value ref,n.asset_id source_asset_id,n.revision source_revision FROM direct_refs d
 JOIN asset_at n ON n.resource_type='nic' AND json_extract(d.ref,'$.resource_type')='nic'
 AND json_extract(d.ref,'$.relation')='attached_network_interface'
 AND json_extract(d.ref,'$.provider')=json_extract(d.record,'$.provider') AND json_extract(d.ref,'$.account_uid')=json_extract(d.record,'$.account_uid')
 AND COALESCE(json_extract(d.ref,'$.source_component'),'')<>'' AND COALESCE(json_extract(d.ref,'$.source_path'),'')<>''
 AND n.provider=json_extract(d.ref,'$.provider') AND n.account_uid=json_extract(d.ref,'$.account_uid')
 AND n.region=json_extract(d.ref,'$.region') AND n.resource_id=json_extract(d.ref,'$.resource_id'), json_each(n.record,'$.references') j
 )`
	if f.GroupBy.IsNetwork() {
		kind := string(f.GroupBy) // enum is selected by the caller, not user SQL
		prefix += `, network_edges AS (
  SELECT DISTINCT r.finding_id,r.asset_id,r.record,r.ref,r.source_asset_id,r.source_revision,
   json_object('provider',json_extract(r.ref,'$.provider'),'account_uid',json_extract(r.ref,'$.account_uid'),
   'region',json_extract(r.ref,'$.region'),'resource_type',json_extract(r.ref,'$.resource_type'),'resource_id',json_extract(r.ref,'$.resource_id')) group_key
  FROM refs r WHERE json_extract(r.ref,'$.resource_type')='` + kind + `'
   AND json_extract(r.ref,'$.provider')=json_extract(r.record,'$.provider')
   AND json_extract(r.ref,'$.account_uid')=json_extract(r.record,'$.account_uid')
   AND COALESCE(json_extract(r.ref,'$.resource_id'),'')<>''
   AND COALESCE(json_extract(r.ref,'$.source_component'),'')<>'' AND COALESCE(json_extract(r.ref,'$.source_path'),'')<>''
   AND json_extract(r.ref,'$.relation')=CASE json_extract(r.ref,'$.resource_type') WHEN 'vpc' THEN 'belongs_to_vpc' WHEN 'subnet' THEN 'in_subnet' WHEN 'security_group' THEN 'attached_security_group' WHEN 'nic' THEN 'attached_network_interface' END
  ), valid_refs AS (SELECT DISTINCT finding_id,asset_id,record,group_key FROM network_edges), context_members AS (
   SELECT finding_id,asset_id,record,group_key FROM valid_refs
   UNION ALL
   SELECT a.id,h.asset_id,h.record,json_object('singleton',a.id) FROM eligible a LEFT JOIN hosts h ON h.finding_id=a.id
   WHERE NOT EXISTS(SELECT 1 FROM valid_refs r WHERE r.finding_id=a.id)
  ) `
	} else {
		extra := ""
		owner := resourceOwnerExpr("a")
		// A missing region is not a missing identity: global resources (CDN,
		// domain-level endpoints) legitimately have no region, and the product
		// contract allows an explicit global scope. Only identity fields decide
		// whether a finding can join a group.
		required := owner + `='' OR a.resource_id='' OR a.resource_type=''`
		if f.GroupBy == model.GroupByNameAsset {
			extra = `,'product',a.product,'vendor_title',a.title`
			required += ` OR a.product='' OR a.title=''`
		}
		prefix += `, context_members AS (
  SELECT a.id finding_id,h.asset_id,h.record,
  CASE WHEN ` + required + ` THEN json_object('singleton',a.id)
  ELSE json_object('provider',a.provider,'account_uid',` + owner + `,'region',a.region,'resource_type',COALESCE(json_extract(h.record,'$.resource_type'),a.resource_type),'resource_id',COALESCE(json_extract(h.record,'$.resource_id'),a.resource_id)` + extra + `) END group_key
  FROM eligible a LEFT JOIN hosts h ON h.finding_id=a.id
) `
	}
	return prefix
}

func contextGroupWhere(f model.AlertFilter) (string, []any) {
	fields := []string{"provider", "account_uid", "region", "resource_type", "resource_id"}

	if f.GroupBy == model.GroupByNameAsset {
		fields = append(fields, "product", "vendor_title")
	}
	if f.GroupKey["singleton"] != "" {
		fields = []string{"singleton"}
	}
	clauses, args := []string{"m.finding_id=alerts.id"}, []any{}
	for _, field := range fields {
		value, ok := f.GroupKey[field]
		if !ok {
			return "1=0", nil
		}
		clauses = append(clauses, `json_extract(m.group_key,'$.`+field+`')=?`)
		args = append(args, value)
	}
	return `EXISTS(SELECT 1 FROM context_members m WHERE ` + strings.Join(clauses, " AND ") + `)`, args
}

func (s *SQLite) listContextGroups(ctx context.Context, f model.AlertFilter) ([]model.AlertGroup, int, error) {
	where, args := buildAlertWhere(f)
	args = withContextArgs(f, args)
	base := snapshotPrefix(f) + `SELECT m.group_key, COUNT(DISTINCT alerts.id), MAX(severity_id), COALESCE(MIN(NULLIF(first_seen_at,0)),0), MAX(last_seen_at),
 COUNT(DISTINCT m.asset_id), MIN(resource_name), GROUP_CONCAT(DISTINCT alerts.provider), COUNT(*) OVER(),
 SUM(COALESCE((SELECT MAX(r.revision)-1 FROM alert_revisions r WHERE r.alert_id=alerts.id` + revisionCeiling(f) + `),0))
 FROM alerts JOIN context_members m ON m.finding_id=alerts.id` + where + ` GROUP BY m.group_key
 ORDER BY (json_extract(m.group_key,'$.singleton') IS NOT NULL),MAX(severity_id) DESC,COUNT(DISTINCT alerts.id) DESC,MAX(last_seen_at) DESC,m.group_key`
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
	rows, err := s.db.QueryContext(ctx, base+` LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	out, total := []model.AlertGroup{}, 0
	var keys []string
	for rows.Next() {
		g := model.AlertGroup{GroupBy: f.GroupBy}
		var key, providers string
		var first, last int64
		if err = rows.Scan(&key, &g.FindingCount, &g.MaxSeverity, &first, &last, &g.AssetCount, &g.ResourceName, &providers, &total, &g.RevisionCount); err != nil {
			rows.Close()
			return nil, 0, err
		}
		if err = json.Unmarshal([]byte(key), &g.Key); err != nil {
			rows.Close()
			return nil, 0, err
		}
		g.ID = model.GroupID(f.GroupBy, g.Key)
		g.ResourceID = g.Key["resource_id"]
		g.FirstSeenAt = ptrTime(first)
		g.LastSeenAt = ptrTime(last)
		g.Providers = splitDistinct(providers)
		g.Title = g.ResourceID
		if !f.GroupBy.IsNetwork() && g.ResourceName != "" {
			g.Title = g.ResourceName
		}
		if f.GroupBy == model.GroupByNameAsset {
			g.Title = g.Key["vendor_title"]
		}
		if g.Key["singleton"] != "" {
			g.Title = firstNonEmpty(g.ResourceName, "Unlinked finding")
			g.MissingFields = []string{"explicit_scoped_resource_reference"}
			if f.GroupBy.IsNetwork() {
				g.MissingFields = []string{"saved_host_network_reference"}
			}
		}
		out = append(out, g)
		keys = append(keys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, 0, err
	}
	if len(out) == 0 && offset > 0 {
		if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM (`+base+`)`, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
	}
	if err = s.contextGroupDetails(ctx, f, out, keys); err != nil {
		return nil, 0, err
	}
	for i := range out {
		if f.GroupBy == model.GroupByAsset && len(out[i].Assets) > 0 && out[i].Assets[0].Name != "" {
			out[i].Title = out[i].Assets[0].Name
		}
	}
	return out, total, nil
}

func revisionCeiling(f model.AlertFilter) string {
	if f.SnapshotSequence != nil {
		return fmt.Sprintf(" AND r.sequence<=%d", *f.SnapshotSequence)
	}
	return ""
}

// Enrich the entire page in a fixed number of local queries, rather than
// rebuilding the context join once per group. All samples are capped per key.
func (s *SQLite) contextGroupDetails(ctx context.Context, f model.AlertFilter, groups []model.AlertGroup, keys []string) error {
	if len(groups) == 0 {
		return nil
	}
	byKey := make(map[string]*model.AlertGroup, len(groups))
	for i, key := range keys {
		byKey[key] = &groups[i]
	}
	encoded, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	where, args := buildAlertWhere(f)
	args = withContextArgs(f, args)
	if where == "" {
		where = " WHERE 1=1"
	}
	where += ` AND m.group_key IN (SELECT value FROM json_each(?))`
	args = append(args, string(encoded))
	prefix := strings.TrimSpace(snapshotPrefix(f)) + `, page_members AS (
 SELECT m.finding_id,m.group_key,m.asset_id,m.record,alerts.title FROM alerts JOIN context_members m ON m.finding_id=alerts.id` + where + `)`
	rows, err := s.db.QueryContext(ctx, prefix+`, asset_samples AS (
 SELECT DISTINCT group_key,asset_id,json_remove(record,'$.components','$.provenance') record FROM page_members WHERE asset_id IS NOT NULL
 ), ranked AS (SELECT group_key,record,ROW_NUMBER() OVER(PARTITION BY group_key ORDER BY asset_id) n FROM asset_samples)
 SELECT group_key,record FROM ranked WHERE n<=5 ORDER BY group_key,n`, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var key, raw string
		var a model.Asset
		if err = rows.Scan(&key, &raw); err != nil {
			break
		}
		if err = json.Unmarshal([]byte(raw), &a); err != nil {
			break
		}
		g := byKey[key]
		g.Assets = append(g.Assets, model.GroupAsset{Synthetic: a.Synthetic, ID: a.ID, ResourceID: a.ResourceID, Name: a.Name, Revision: a.Revision, ObservedAt: a.ObservedAt, VPCID: a.VPCID, SubnetID: a.SubnetID, SecurityGroupIDs: a.SecurityGroupIDs, References: a.References})
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = s.db.QueryContext(ctx, prefix+`, title_counts AS (
 SELECT group_key,title,COUNT(DISTINCT finding_id) count FROM page_members GROUP BY group_key,title
 ), ranked AS (SELECT group_key,title,count,ROW_NUMBER() OVER(PARTITION BY group_key ORDER BY count DESC,title) n FROM title_counts)
 SELECT group_key,title,count FROM ranked WHERE n<=5 ORDER BY group_key,n`, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var key string
		var c model.Count
		if err = rows.Scan(&key, &c.Key, &c.Count); err != nil {
			break
		}
		g := byKey[key]
		g.TopTitles = append(g.TopTitles, c)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if !f.GroupBy.IsNetwork() {
		return nil
	}
	rows, err = s.db.QueryContext(ctx, prefix+`, edge_samples AS (
 SELECT DISTINCT e.group_key,e.asset_id,json_extract(e.record,'$.revision') host_revision,e.source_asset_id,e.source_revision,e.ref
 FROM network_edges e JOIN page_members p ON p.finding_id=e.finding_id AND p.group_key=e.group_key
 ), ranked AS (SELECT *,ROW_NUMBER() OVER(PARTITION BY group_key ORDER BY asset_id,source_asset_id,ref) n FROM edge_samples)
 SELECT group_key,asset_id,host_revision,source_asset_id,source_revision,ref FROM ranked WHERE n<=5 ORDER BY group_key,n`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var key, raw string
		var edge model.GroupRelationEvidence
		if err = rows.Scan(&key, &edge.HostAssetID, &edge.HostRevision, &edge.SourceAssetID, &edge.SourceRevision, &raw); err != nil {
			return err
		}
		if err = json.Unmarshal([]byte(raw), &edge.Reference); err != nil {
			return err
		}
		g := byKey[key]
		g.RelationEvidence = append(g.RelationEvidence, edge)
	}
	return rows.Err()
}

func (s *SQLite) GroupingSummary(ctx context.Context, f model.AlertFilter) (*model.GroupingSummary, error) {
	out := &model.GroupingSummary{}
	if !f.GroupBy.UsesAssetContext() {
		return nil, nil
	}
	where, args := buildAlertWhere(f)
	args = withContextArgs(f, args)
	err := s.db.QueryRowContext(ctx, snapshotPrefix(f)+`SELECT COUNT(DISTINCT alerts.id),COUNT(DISTINCT CASE WHEN m.asset_id IS NOT NULL THEN alerts.id END),COUNT(DISTINCT CASE WHEN json_extract(m.group_key,'$.singleton') IS NOT NULL THEN alerts.id END),COUNT(*) FROM alerts JOIN context_members m ON m.finding_id=alerts.id`+where, args...).Scan(&out.FindingCount, &out.AssetContextFindingCount, &out.UngroupedFindingCount, &out.MembershipCount)
	return out, err
}

// Restrict context construction before expanding network memberships. Parameters
// are bound twice: first for eligible source rows, then for the outer query.
func contextBaseWhere(f model.AlertFilter) (string, []any) {
	f.GroupBy = ""
	f.GroupKey = nil
	return buildAlertWhere(f)
}
func withContextArgs(f model.AlertFilter, args []any) []any {
	if !f.GroupBy.UsesAssetContext() {
		return args
	}
	_, base := contextBaseWhere(f)
	return append(base, args...)
}
