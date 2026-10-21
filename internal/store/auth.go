package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// ------------------------------------------------------------------- users

func (s *SQLite) CreateUser(ctx context.Context, u *model.User, passwordHash string) error {
	now := time.Now().UTC()
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.Role == "" {
		u.Role = "admin"
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now
	u.PasswordChangedAt = now
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, role, disabled, created_at, updated_at, password_changed_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		u.ID, u.Username, passwordHash, u.Role, boolInt(u.Disabled),
		millis(u.CreatedAt), millis(u.UpdatedAt), millis(u.PasswordChangedAt))
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	return nil
}

func (s *SQLite) GetUser(ctx context.Context, id string) (*model.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, role, disabled, created_at, updated_at, password_changed_at
		FROM users WHERE id=?`, id)
	return scanUser(row)
}

func (s *SQLite) GetUserCredential(ctx context.Context, id string) (*model.User, string, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, role, disabled, created_at, updated_at, password_changed_at, password_hash
		FROM users WHERE id=?`, id)
	return scanUserWithHash(row)
}

func (s *SQLite) GetUserByUsername(ctx context.Context, username string) (*model.User, string, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, role, disabled, created_at, updated_at, password_changed_at, password_hash
		FROM users WHERE username=?`, username)
	return scanUserWithHash(row)
}

func (s *SQLite) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *SQLite) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, username, role, disabled, created_at, updated_at, password_changed_at
		FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *SQLite) UpdateUserPassword(ctx context.Context, id, passwordHash string) error {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET password_hash=?, password_changed_at=?, updated_at=? WHERE id=?`,
		passwordHash, millis(now), millis(now), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) SetUserDisabled(ctx context.Context, id string, disabled bool) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE users SET disabled=?, updated_at=? WHERE id=?`,
		boolInt(disabled), millis(time.Now().UTC()), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanUser(row interface{ Scan(...any) error }) (*model.User, error) {
	var u model.User
	var disabled int
	var created, updated, changed int64
	err := row.Scan(&u.ID, &u.Username, &u.Role, &disabled, &created, &updated, &changed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.Disabled = disabled != 0
	u.CreatedAt = fromMillis(created)
	u.UpdatedAt = fromMillis(updated)
	u.PasswordChangedAt = fromMillis(changed)
	return &u, nil
}

func scanUserWithHash(row interface{ Scan(...any) error }) (*model.User, string, error) {
	var u model.User
	var disabled int
	var created, updated, changed int64
	var hash string
	err := row.Scan(&u.ID, &u.Username, &u.Role, &disabled, &created, &updated, &changed, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	u.Disabled = disabled != 0
	u.CreatedAt = fromMillis(created)
	u.UpdatedAt = fromMillis(updated)
	u.PasswordChangedAt = fromMillis(changed)
	return &u, hash, nil
}

// ---------------------------------------------------------------- sessions

func (s *SQLite) CreateSession(ctx context.Context, tokenHash, userID string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)`,
		tokenHash, userID, millis(time.Now().UTC()), millis(expiresAt))
	return err
}

func (s *SQLite) GetSessionUser(ctx context.Context, tokenHash string, now time.Time) (*model.User, time.Time, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.role, u.disabled, u.created_at, u.updated_at, u.password_changed_at, s.expires_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at > ? AND u.disabled = 0`, tokenHash, millis(now))
	var u model.User
	var disabled int
	var created, updated, changed, expires int64
	err := row.Scan(&u.ID, &u.Username, &u.Role, &disabled, &created, &updated, &changed, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, ErrNotFound
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	u.Disabled = disabled != 0
	u.CreatedAt = fromMillis(created)
	u.UpdatedAt = fromMillis(updated)
	u.PasswordChangedAt = fromMillis(changed)
	return &u, fromMillis(expires), nil
}

func (s *SQLite) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *SQLite) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID)
	return err
}

func (s *SQLite) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, millis(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------- api keys

func (s *SQLite) CreateAPIKey(ctx context.Context, key *model.APIKey, keyHash string) error {
	if key.ID == "" {
		key.ID = uuid.NewString()
	}
	if key.CreatedAt.IsZero() {
		key.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO api_keys (id, user_id, name, key_hash, prefix, created_at, expires_at, revoked_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		key.ID, key.UserID, key.Name, keyHash, key.Prefix, millis(key.CreatedAt),
		millisPtr(key.ExpiresAt), millisPtr(key.RevokedAt))
	return err
}

func (s *SQLite) ListAPIKeys(ctx context.Context, userID string) ([]model.APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, prefix, created_at, last_used_at, expires_at, revoked_at
		FROM api_keys WHERE user_id=? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.APIKey
	for rows.Next() {
		var k model.APIKey
		var created, lastUsed, expires, revoked int64
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &created, &lastUsed, &expires, &revoked); err != nil {
			return nil, err
		}
		k.CreatedAt = fromMillis(created)
		k.LastUsedAt = ptrTime(lastUsed)
		k.ExpiresAt = ptrTime(expires)
		k.RevokedAt = ptrTime(revoked)
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *SQLite) RevokeAPIKey(ctx context.Context, id, userID string, revokedAt time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE api_keys SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at=0`,
		millis(revokedAt), id, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLite) RevokeUserAPIKeys(ctx context.Context, userID string, revokedAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE api_keys SET revoked_at=? WHERE user_id=? AND revoked_at=0`,
		millis(revokedAt), userID)
	return err
}

func (s *SQLite) GetUserByAPIKey(ctx context.Context, keyHash string, now time.Time) (*model.User, *model.APIKey, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT u.id, u.username, u.role, u.disabled, u.created_at, u.updated_at, u.password_changed_at, k.expires_at, k.id, k.name
		FROM api_keys k JOIN users u ON u.id = k.user_id
		WHERE k.key_hash = ? AND k.revoked_at = 0 AND (k.expires_at = 0 OR k.expires_at > ?) AND u.disabled = 0`,
		keyHash, millis(now))
	var u model.User
	var key model.APIKey
	var disabled int
	var created, updated, changed, expires int64
	err := row.Scan(&u.ID, &u.Username, &u.Role, &disabled, &created, &updated, &changed, &expires, &key.ID, &key.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	u.Disabled = disabled != 0
	u.CreatedAt = fromMillis(created)
	u.UpdatedAt = fromMillis(updated)
	u.PasswordChangedAt = fromMillis(changed)
	key.ExpiresAt = ptrTime(expires)
	return &u, &key, nil
}
