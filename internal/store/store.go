// Package store is the persistence contract. The bundled implementation is
// SQLite; the interface is deliberately free of SQL so a PostgreSQL or
// ClickHouse backend can be added without touching API or ingest code.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Store interface {
	Close() error
	Ping(ctx context.Context) error

	CreateAccount(ctx context.Context, account *model.Account) error
	// UpdateAccount persists account fields. A non-nil credential replaces the
	// encrypted blob; nil keeps the existing secret.
	UpdateAccount(ctx context.Context, account *model.Account, credential *string) error
	// UpsertAccountByName is used by declarative config bootstrap.
	UpsertAccountByName(ctx context.Context, account *model.Account) (created bool, err error)
	GetAccount(ctx context.Context, id string) (*model.Account, error)
	GetAccountByName(ctx context.Context, name string) (*model.Account, error)
	ListAccounts(ctx context.Context) ([]model.Account, error)
	DeleteAccount(ctx context.Context, id string, purgeAlerts bool) error
	AccountCredential(ctx context.Context, id string) (string, error)

	UpsertAlert(ctx context.Context, alert *model.AlertRecord) (created bool, err error)
	GetAlert(ctx context.Context, id string) (*model.AlertRecord, error)
	ListAlerts(ctx context.Context, filter model.AlertFilter) ([]model.AlertRecord, int, error)
	ListAlertGroups(ctx context.Context, filter model.AlertFilter) ([]model.AlertGroup, int, error)
	ListAlertRevisions(ctx context.Context, alertID string, limit int) ([]model.AlertRevision, error)
	UpdateAlertStatus(ctx context.Context, id string, status model.AlertStatus) error
	AlertStats(ctx context.Context, filter model.AlertFilter) (*model.AlertStats, error)

	GetSyncState(ctx context.Context, accountID string) (*model.SyncState, error)
	SaveSyncState(ctx context.Context, state *model.SyncState) error
	StartSyncRun(ctx context.Context, run *model.SyncRun) error
	FinishSyncRun(ctx context.Context, run *model.SyncRun) error
	ListSyncRuns(ctx context.Context, accountID string, limit int) ([]model.SyncRun, error)

	// Users
	CreateUser(ctx context.Context, user *model.User, passwordHash string) error
	GetUser(ctx context.Context, id string) (*model.User, error)
	GetUserCredential(ctx context.Context, id string) (*model.User, string, error)
	GetUserByUsername(ctx context.Context, username string) (*model.User, string, error)
	CountUsers(ctx context.Context) (int, error)
	ListUsers(ctx context.Context) ([]model.User, error)
	UpdateUserPassword(ctx context.Context, id, passwordHash string) error
	SetUserDisabled(ctx context.Context, id string, disabled bool) error

	// Sessions
	CreateSession(ctx context.Context, tokenHash, userID string, expiresAt time.Time) error
	GetSessionUser(ctx context.Context, tokenHash string, now time.Time) (*model.User, time.Time, error)
	DeleteSession(ctx context.Context, tokenHash string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error)

	// API keys
	CreateAPIKey(ctx context.Context, key *model.APIKey, keyHash string) error
	ListAPIKeys(ctx context.Context, userID string) ([]model.APIKey, error)
	RevokeAPIKey(ctx context.Context, id, userID string, revokedAt time.Time) error
	RevokeUserAPIKeys(ctx context.Context, userID string, revokedAt time.Time) error
	GetUserByAPIKey(ctx context.Context, keyHash string, now time.Time) (*model.User, *time.Time, error)
}
