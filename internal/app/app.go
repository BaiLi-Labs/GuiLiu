// Package app assembles the process: storage, secrets, connectors, ingest,
// REST and MCP. Keeping assembly here lets serve/mcp/sync/probe share exactly
// the same wiring.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/api"
	"github.com/BaiLi-Labs/GuiLiu/internal/asset"
	"github.com/BaiLi-Labs/GuiLiu/internal/auth"
	"github.com/BaiLi-Labs/GuiLiu/internal/config"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	_ "github.com/BaiLi-Labs/GuiLiu/internal/connector/all"
	"github.com/BaiLi-Labs/GuiLiu/internal/credential"
	"github.com/BaiLi-Labs/GuiLiu/internal/ingest"
	"github.com/BaiLi-Labs/GuiLiu/internal/mcp"
	"github.com/BaiLi-Labs/GuiLiu/internal/mock"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

type App struct {
	Config   *config.Config
	Log      *slog.Logger
	Store    *store.SQLite
	Cipher   *secret.Cipher
	Registry *connector.Registry
	Engine   *ingest.Engine
	Auth     *auth.Service
	MCP      *mcp.Server
	API      *api.Server
}

// New opens storage, loads the master key, bootstraps declarative accounts and
// builds the runtime components.
func New(cfg *config.Config, log *slog.Logger) (*App, error) {
	if log == nil {
		log = slog.Default()
	}
	st, err := store.Open(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	cipher, err := secret.Load(cfg.SecretKey, cfg.SecretKeyFile)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("load secret key: %w", err)
	}
	registry := connector.Default()
	if cfg.Mock {
		mock.Register(registry)
		cfg.Auth.DevMode = true
		cfg.Sync.Enabled = false
		log.Info("mock mode: authentication disabled, data is synthetic and in-memory")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := bootstrapAccounts(ctx, cfg, st, cipher, registry, log); err != nil {
		st.Close()
		return nil, err
	}

	engine := ingest.New(st, registry, cipher, ingest.Options{
		Enabled:         cfg.Sync.Enabled,
		Interval:        cfg.Sync.Interval.Get(),
		InitialLookback: cfg.Sync.InitialLookback.Get(),
		Overlap:         cfg.Sync.Overlap.Get(),
		MaxWindow:       cfg.Sync.MaxWindow.Get(),
		MaxPages:        cfg.Sync.MaxPages,
		PageSize:        cfg.Sync.PageSize,
		Workers:         cfg.Sync.Workers,
	}, log)

	authService := auth.New(st, auth.Config{
		DevMode:       cfg.Auth.DevMode,
		SessionTTL:    cfg.Auth.SessionTTL.Get(),
		SecureCookies: cfg.Auth.SecureCookies,
		AdminUser:     cfg.Auth.AdminUser,
	}, log)
	if cfg.Auth.DevMode {
		log.Warn("authentication is disabled (dev/mock mode); do not expose this listener")
	} else {
		created, err := authService.EnsureAdmin(ctx, cfg.Auth.AdminUser, os.Getenv("GUILIU_ADMIN_PASSWORD"))
		if err != nil {
			st.Close()
			return nil, err
		}
		if created {
			log.Warn("created initial admin user; log in and change the password", "username", cfg.Auth.AdminUser)
		}
	}
	authService.Cleanup(ctx)

	if cfg.Mock {
		if err := seedMock(ctx, st, engine, log); err != nil {
			st.Close()
			return nil, err
		}
	}

	mcpServer := mcp.New(st, registry, log, 3*cfg.Sync.Interval.Get())
	apiServer := api.New(cfg, st, engine, registry, cipher, mcpServer, authService, log)

	a := &App{
		Config:   cfg,
		Log:      log,
		Store:    st,
		Cipher:   cipher,
		Registry: registry,
		Engine:   engine,
		Auth:     authService,
		MCP:      mcpServer,
		API:      apiServer,
	}
	a.pruneAudit(ctx)
	return a, nil
}

func seedMock(ctx context.Context, st *store.SQLite, engine *ingest.Engine, log *slog.Logger) error {
	accounts, err := st.ListAccounts(ctx)
	if err != nil {
		return err
	}
	seeded := 0
	for _, acct := range accounts {
		if !mock.IsMockProvider(acct.Provider) {
			continue
		}
		run, err := engine.SyncAccount(ctx, acct, "mock-seed")
		if err != nil {
			return fmt.Errorf("seed mock data for %s: %w", acct.Name, err)
		}
		seeded++
		if acct.Provider == "tencent" && acct.AccountUID != "" && acct.Region != "" {
			if err := asset.SeedSynthetic(ctx, st, acct); err != nil {
				return err
			}
		}
		log.Info("mock data ready", "account", acct.Name, "alerts", run.Fetched)
	}
	if seeded == 0 {
		return fmt.Errorf("mock mode requires at least one mock account")
	}
	return nil
}

// Connector builds a connector for an account, decrypting its credential.
func (a *App) Connector(ctx context.Context, acct model.Account) (connector.Connector, error) {
	cred, err := credential.Load(ctx, a.Store, a.Cipher, acct.ID)
	if err != nil {
		return nil, err
	}
	return a.Registry.New(connector.AccountConfig{
		Provider:   acct.Provider,
		AccountID:  acct.ID,
		Name:       acct.Name,
		AccountUID: acct.AccountUID,
		Region:     acct.Region,
		Options:    acct.Options,
		Credential: cred,
	})
}

// Run serves HTTP until the context is canceled.
func (a *App) Run(ctx context.Context) error {
	srv := &http.Server{
		Addr:              a.Config.Listen,
		Handler:           a.API.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		a.Log.Info("guiliu listening",
			"addr", a.Config.Listen,
			"api", "/api/v1",
			"mcp", "/mcp",
			"auth_enabled", !a.Auth.DevMode(),
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	a.Engine.Run(ctx)
	maintenanceCtx, stopMaintenance := context.WithCancel(ctx)
	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-maintenanceCtx.Done():
				return
			case <-ticker.C:
				a.pruneAudit(maintenanceCtx)
			}
		}
	}()
	defer func() { stopMaintenance(); <-maintenanceDone }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		a.Engine.Wait()
		return nil
	}
}

func (a *App) Close() error { return a.Store.Close() }

func (a *App) pruneAudit(ctx context.Context) {
	days := a.Config.Audit.RetentionDays
	if days == 0 {
		days = 90
	}
	cleanup, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	n, err := a.Store.PruneAuditEvents(cleanup, time.Now().UTC().Add(-time.Duration(days)*24*time.Hour))
	if err != nil {
		a.Log.Error("audit retention cleanup failed")
	} else if n > 0 {
		a.Log.Info("expired audit events removed", "count", n)
	}
}

func bootstrapAccounts(ctx context.Context, cfg *config.Config, st *store.SQLite, cipher *secret.Cipher, registry *connector.Registry, log *slog.Logger) error {
	for _, ac := range cfg.Accounts {
		desc, ok := registry.Descriptor(ac.Provider)
		if !ok {
			return fmt.Errorf("account %q: unknown provider %q", ac.Name, ac.Provider)
		}
		existing, err := st.GetAccountByName(ctx, ac.Name)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		exists := err == nil
		cred := connector.Credential{
			AccessKeyID:        ac.AccessKeyID,
			AccessKeySecret:    ac.AccessKeySecret,
			SessionToken:       ac.SessionToken,
			ServiceAccountJSON: ac.ServiceAccountJSON,
		}
		provided := map[string]string{
			"access_key_id":        cred.AccessKeyID,
			"access_key_secret":    cred.AccessKeySecret,
			"session_token":        cred.SessionToken,
			"service_account_json": cred.ServiceAccountJSON,
		}
		if !exists {
			for _, f := range desc.Credential {
				if f.Required && strings.TrimSpace(provided[f.Name]) == "" {
					return fmt.Errorf("account %q: %s is required for first-time configuration", ac.Name, f.Name)
				}
			}
			for _, f := range desc.OptionFields {
				if f.Required && strings.TrimSpace(ac.Options[f.Name]) == "" {
					return fmt.Errorf("account %q: option %s is required for first-time configuration", ac.Name, f.Name)
				}
			}
		}

		acct := &model.Account{
			Name:       ac.Name,
			Provider:   ac.Provider,
			AccountUID: ac.AccountUID,
			Region:     ac.Region,
			Enabled:    ac.IsEnabled(),
			Options:    ac.Options,
		}
		if provided["access_key_id"] != "" || provided["access_key_secret"] != "" ||
			provided["session_token"] != "" || provided["service_account_json"] != "" {
			enc, err := credential.Encrypt(cipher, cred)
			if err != nil {
				return fmt.Errorf("account %q: encrypt credential: %w", ac.Name, err)
			}
			acct.CredentialEncrypted = enc
			acct.AccessKeyHint = credential.HintFor(cred)
			acct.CredentialSet = true
		} else if exists {
			acct.AccessKeyHint = existing.AccessKeyHint
		}
		created, err := st.UpsertAccountByName(ctx, acct)
		if err != nil {
			return fmt.Errorf("account %q: persist: %w", ac.Name, err)
		}
		if created {
			log.Info("configured account", "account", ac.Name, "provider", desc.ID)
		} else {
			log.Debug("updated account from config", "account", ac.Name, "provider", desc.ID)
		}
	}
	return nil
}
