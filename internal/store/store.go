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
	SaveAsset(ctx context.Context, asset *model.Asset) error
	GetAsset(ctx context.Context, id string, revision int) (*model.Asset, error)
	ListAssets(ctx context.Context, filter model.AssetFilter) ([]model.Asset, error)
	BeginAssetRefresh(ctx context.Context, attempt model.AssetRefresh, cooldown time.Duration) (bool, error)
	FinishAssetRefresh(ctx context.Context, attempt model.AssetRefresh) error
	GetAssetRefresh(ctx context.Context, accountID, region, resourceID string) (*model.AssetRefresh, error)

	CreateAccount(ctx context.Context, account *model.Account) error
	// UpdateAccount persists account fields. A non-nil credential replaces the
	// encrypted blob; nil keeps the existing secret.
	UpdateAccount(ctx context.Context, account *model.Account, credential *string) error
	// UpsertAccountByName is used by declarative config bootstrap.
	UpsertAccountByName(ctx context.Context, account *model.Account) (created bool, err error)
	GetAccount(ctx context.Context, id string) (*model.Account, error)
	GetAccountByName(ctx context.Context, name string) (*model.Account, error)
	ListUnconfiguredSources(ctx context.Context, provider, accountID string) ([]model.Account, error)
	ListAccounts(ctx context.Context) ([]model.Account, error)
	DeleteAccount(ctx context.Context, id string) error
	AccountCredential(ctx context.Context, id string) (string, error)

	SnapshotSequence(ctx context.Context) (int64, error)
	ListAlertChanges(ctx context.Context, cursor string, limit int, provider, accountID string) (*model.ChangePage, error)
	AlertRevisionPage(ctx context.Context, id string, beforeRevision, limit int) ([]model.AlertRevision, error)
	GetAlertAtSnapshot(ctx context.Context, id string, sequence int64) (*model.AlertRecord, error)
	GetAlertRevision(ctx context.Context, id string, revision int) (*model.AlertRecord, error)
	UpsertAlert(ctx context.Context, alert *model.AlertRecord) (created bool, err error)
	GetAlert(ctx context.Context, id string) (*model.AlertRecord, error)
	ListAlerts(ctx context.Context, filter model.AlertFilter) ([]model.AlertRecord, int, error)
	ListReplayAlerts(ctx context.Context, filter model.AlertFilter, mapperVersion, afterID string) ([]model.AlertRecord, error)
	ListAlertGroups(ctx context.Context, filter model.AlertFilter) ([]model.AlertGroup, int, error)
	ListAlertRevisions(ctx context.Context, alertID string, limit int) ([]model.AlertRevision, error)
	UpdateAlertStatus(ctx context.Context, id string, status model.AlertStatus) error
	AlertStats(ctx context.Context, filter model.AlertFilter) (*model.AlertStats, error)

	GetSyncState(ctx context.Context, accountID string) (*model.SyncState, error)
	SaveSyncState(ctx context.Context, state *model.SyncState) error
	StartSyncRun(ctx context.Context, run *model.SyncRun) error
	FinishSyncRun(ctx context.Context, run *model.SyncRun) error
	ListSyncRuns(ctx context.Context, accountID string, limit int) ([]model.SyncRun, error)
	SaveIngestFailure(ctx context.Context, failure *model.IngestFailure) error
	ListIngestFailures(ctx context.Context, accountID string, limit int) ([]model.IngestFailure, int, error)
	DeleteIngestFailure(ctx context.Context, id string) error

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
