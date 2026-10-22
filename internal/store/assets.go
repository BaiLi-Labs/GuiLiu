package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/google/uuid"
)

// marshalAssetStorage keeps each component's exact source bytes as a JSON
// string. encoding/json compacts RawMessage values, which would otherwise make
// the stored bytes differ from raw_hash and the /raw endpoint.
func marshalAssetStorage(a *model.Asset) (string, error) {
	base, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	var value map[string]any
	dec := json.NewDecoder(strings.NewReader(string(base)))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return "", err
	}
	if components, ok := value["components"].(map[string]any); ok {
		for key, c := range a.Components {
			if len(c.Raw) == 0 {
				continue
			}
			component, ok := components[key].(map[string]any)
			if !ok {
				continue
			}
			component["raw"] = string(c.Raw)
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func unmarshalAssetStorage(raw string, a *model.Asset) error {
	var value map[string]any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return err
	}
	raws := map[string]string{}
	if components, ok := value["components"].(map[string]any); ok {
		for key, c := range components {
			component, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := component["raw"].(string); ok {
				raws[key] = text
				// Do not re-encode raw through RawMessage here: encoding/json
				// would compact it and lose the exact source bytes.
				delete(component, "raw")
			}
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(encoded, a); err != nil {
		return err
	}
	for key, text := range raws {
		c := a.Components[key]
		c.Raw = json.RawMessage(text)
		a.Components[key] = c
	}
	return nil
}

func (s *SQLite) SaveAsset(ctx context.Context, a *model.Asset) error {
	if a.Provider == "" || a.AccountUID == "" || a.Region == "" || a.ResourceID == "" || a.AccountID == "" || a.ObservedAt.IsZero() {
		return fmt.Errorf("asset requires complete source identity and observation time")
	}
	for key, c := range a.Components {
		if len(c.Raw) > 0 {
			if !json.Valid(c.Raw) || c.ObservedAt == nil || c.ObservedAt.IsZero() {
				return fmt.Errorf("asset component requires valid JSON and observation time")
			}
			c.RawHash = fmt.Sprintf("%x", sha256.Sum256(c.Raw))
			c.RawURL = ""
			a.Components[key] = c
		}
	}
	// Canonical JSON preserves number precision while ignoring key order and
	// whitespace. Exact bytes remain in each immutable component with their hash.
	content := *a
	content.ID, content.Revision = "", 0
	content.ObservedAt, content.LastObservedAt = time.Time{}, time.Time{}
	content.Components = make(map[string]model.AssetComponent, len(a.Components))
	for key, c := range a.Components {
		c.ObservedAt, c.RawHash, c.RawURL = nil, "", ""
		content.Components[key] = c
	}
	raw, err := json.Marshal(content)
	if err != nil {
		return err
	}
	var value any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return err
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(canonical))
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var oldHash, oldRecord string
	err = tx.QueryRowContext(ctx, `SELECT id, revision, content_hash, record FROM assets WHERE provider=? AND account_uid=? AND region=? AND resource_id=?`, a.Provider, a.AccountUID, a.Region, a.ResourceID).Scan(&a.ID, &a.Revision, &oldHash, &oldRecord)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		a.ID = uuid.NewString()
		a.Revision = 0
	}
	if oldRecord != "" {
		var old model.Asset
		if err := unmarshalAssetStorage(oldRecord, &old); err != nil {
			return err
		}
		if a.ObservedAt.Before(old.LastObservedAt) {
			return fmt.Errorf("asset observation precedes current observation")
		}
	}
	a.LastObservedAt = a.ObservedAt
	if oldHash == hash {
		var old model.Asset
		if err := unmarshalAssetStorage(oldRecord, &old); err != nil {
			return err
		}
		old.LastObservedAt = a.ObservedAt
		*a = old
	} else {
		a.Revision++
	}
	stored, err := marshalAssetStorage(a)
	if err != nil {
		return err
	}
	if oldHash != hash {
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_revisions(asset_id,revision,record) VALUES(?,?,?)`, a.ID, a.Revision, stored); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO asset_revision_sequences(asset_id,revision) VALUES(?,?)`, a.ID, a.Revision); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO assets(id,account_id,provider,account_uid,region,resource_id,revision,content_hash,record) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET account_id=excluded.account_id,revision=excluded.revision,content_hash=excluded.content_hash,record=excluded.record`, a.ID, a.AccountID, a.Provider, a.AccountUID, a.Region, a.ResourceID, a.Revision, hash, stored)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLite) GetAsset(ctx context.Context, id string, revision int) (*model.Asset, error) {
	var raw string
	var err error
	if revision > 0 {
		err = s.db.QueryRowContext(ctx, `SELECT record FROM asset_revisions WHERE asset_id=? AND revision=?`, id, revision).Scan(&raw)
	} else {
		err = s.db.QueryRowContext(ctx, `SELECT record FROM assets WHERE id=?`, id).Scan(&raw)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var a model.Asset
	err = unmarshalAssetStorage(raw, &a)
	return &a, err
}

func (s *SQLite) ListAssets(ctx context.Context, f model.AssetFilter) ([]model.Asset, error) {
	clauses, args := []string{"id > ?"}, []any{f.AfterID}
	for _, field := range []struct{ name, value string }{{"provider", f.Provider}, {"account_id", f.AccountID}, {"account_uid", f.AccountUID}, {"region", f.Region}, {"resource_id", f.ResourceID}} {
		if field.value != "" {
			clauses = append(clauses, field.name+"=?")
			args = append(args, field.value)
		}
	}
	limit := f.Limit
	if f.ResourceType != "" {
		clauses = append(clauses, "json_extract(record,'$.resource_type')=?")
		args = append(args, f.ResourceType)
	}
	if limit <= 0 || limit > 101 {
		limit = 101
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT record FROM assets WHERE `+strings.Join(clauses, " AND ")+` ORDER BY id LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Asset{}
	for rows.Next() {
		var raw string
		var a model.Asset
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := unmarshalAssetStorage(raw, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLite) BeginAssetRefresh(ctx context.Context, a model.AssetRefresh, cooldown time.Duration) (bool, error) {
	r, err := s.db.ExecContext(ctx, `INSERT INTO asset_refreshes(account_id,region,resource_id,status,attempted_at) VALUES(?,?,?,'refreshing',?) ON CONFLICT(account_id,region,resource_id) DO UPDATE SET status='refreshing',source_error='null',attempted_at=excluded.attempted_at WHERE asset_refreshes.attempted_at<=?`, a.AccountID, a.Region, a.ResourceID, millis(a.AttemptedAt), millis(a.AttemptedAt.Add(-cooldown)))
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n > 0, err
}
func (s *SQLite) FinishAssetRefresh(ctx context.Context, a model.AssetRefresh) error {
	_, err := s.db.ExecContext(ctx, `UPDATE asset_refreshes SET status=?,source_error=? WHERE account_id=? AND region=? AND resource_id=? AND attempted_at=?`, a.Status, sourceErrorJSON(a.SourceError), a.AccountID, a.Region, a.ResourceID, millis(a.AttemptedAt))
	return err
}
func (s *SQLite) GetAssetRefresh(ctx context.Context, accountID, region, resourceID string) (*model.AssetRefresh, error) {
	a := &model.AssetRefresh{AccountID: accountID, Region: region, ResourceID: resourceID}
	var at int64
	var sourceError string
	err := s.db.QueryRowContext(ctx, `SELECT status,attempted_at,source_error FROM asset_refreshes WHERE account_id=? AND region=? AND resource_id=?`, accountID, region, resourceID).Scan(&a.Status, &at, &sourceError)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(sourceError), &a.SourceError); err != nil {
		return nil, err
	}
	a.AttemptedAt = fromMillis(at)
	return a, err
}
