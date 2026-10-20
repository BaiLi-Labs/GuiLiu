// Package ingest owns the reliability loop: incremental windows, pagination,
// rate limiting, retries, deduplication and per-account sync health.
package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/credential"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/normalize"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

// ErrAlreadyRunning is returned when a sync is triggered for an account that is
// already being synced.
var ErrAlreadyRunning = errors.New("sync already running for this account")

// Options are the ingest loop defaults. Account options can override window
// and page settings per account.
type Options struct {
	Enabled         bool
	Interval        time.Duration
	InitialLookback time.Duration
	Overlap         time.Duration
	MaxWindow       time.Duration
	MaxPages        int
	PageSize        int
	Workers         int
}

func (o *Options) applyDefaults() {
	if o.Interval <= 0 {
		o.Interval = 5 * time.Minute
	}
	if o.InitialLookback <= 0 {
		o.InitialLookback = 24 * time.Hour
	}
	if o.Overlap <= 0 {
		o.Overlap = 30 * time.Minute
	}
	if o.MaxWindow <= 0 {
		o.MaxWindow = 24 * time.Hour
	}
	if o.MaxPages <= 0 {
		o.MaxPages = 10
	}
	if o.PageSize <= 0 {
		o.PageSize = 100
	}
	if o.Workers <= 0 {
		o.Workers = 2
	}
}

// Engine executes connector syncs and records health.
type Engine struct {
	store    store.Store
	registry *connector.Registry
	cipher   *secret.Cipher
	opts     Options
	log      *slog.Logger
	now      func() time.Time

	mu      sync.Mutex
	running map[string]struct{}
	wg      sync.WaitGroup
}

func New(st store.Store, registry *connector.Registry, cipher *secret.Cipher, opts Options, log *slog.Logger) *Engine {
	opts.applyDefaults()
	if log == nil {
		log = slog.Default()
	}
	return &Engine{
		store:    st,
		registry: registry,
		cipher:   cipher,
		opts:     opts,
		log:      log,
		now:      func() time.Time { return time.Now().UTC() },
		running:  map[string]struct{}{},
	}
}

// Run starts the scheduled sync loop. It returns immediately; call Wait during
// shutdown to let an in-flight tick finish.
func (e *Engine) Run(ctx context.Context) {
	if !e.opts.Enabled {
		e.log.Info("scheduled sync disabled")
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
		e.SyncAll(ctx, "schedule")
		ticker := time.NewTicker(e.opts.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				e.SyncAll(ctx, "schedule")
			}
		}
	}()
}

// Wait blocks until the scheduled loop has exited.
func (e *Engine) Wait() { e.wg.Wait() }

// SyncAll syncs every enabled account with bounded concurrency.
func (e *Engine) SyncAll(ctx context.Context, trigger string) {
	accounts, err := e.store.ListAccounts(ctx)
	if err != nil {
		e.log.Error("list accounts for sync", "error", err)
		return
	}
	sem := make(chan struct{}, e.opts.Workers)
	var wg sync.WaitGroup
	for i := range accounts {
		acct := accounts[i]
		if !acct.Enabled {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if _, err := e.SyncAccount(ctx, acct, trigger); err != nil && !errors.Is(err, ErrAlreadyRunning) {
				e.log.Warn("sync account failed", "account", acct.Name, "error", err)
			}
		}()
	}
	wg.Wait()
}

// Trigger starts a sync asynchronously. It returns false if the account is
// already syncing.
func (e *Engine) Trigger(accountID, trigger string) (bool, error) {
	acct, err := e.store.GetAccount(context.Background(), accountID)
	if err != nil {
		return false, err
	}
	if !acct.Enabled {
		return false, errors.New("account is disabled")
	}
	if !e.acquire(accountID) {
		return false, ErrAlreadyRunning
	}
	go func() {
		defer e.release(accountID)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		if _, err := e.syncAccount(ctx, *acct, trigger); err != nil {
			e.log.Warn("manual sync failed", "account", acct.Name, "error", err)
		}
	}()
	return true, nil
}

// SyncAccount syncs one account synchronously.
func (e *Engine) SyncAccount(ctx context.Context, acct model.Account, trigger string) (*model.SyncRun, error) {
	if !e.acquire(acct.ID) {
		return nil, ErrAlreadyRunning
	}
	defer e.release(acct.ID)
	return e.syncAccount(ctx, acct, trigger)
}

func (e *Engine) acquire(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.running[id]; ok {
		return false
	}
	e.running[id] = struct{}{}
	return true
}

func (e *Engine) release(id string) {
	e.mu.Lock()
	delete(e.running, id)
	e.mu.Unlock()
}

func (e *Engine) syncAccount(ctx context.Context, acct model.Account, trigger string) (*model.SyncRun, error) {
	started := e.now()
	run := &model.SyncRun{
		AccountID: acct.ID,
		Provider:  acct.Provider,
		Trigger:   trigger,
		Status:    "running",
		StartedAt: started,
	}
	if err := e.store.StartSyncRun(ctx, run); err != nil {
		return nil, err
	}

	finish := func(err error, pages, fetched, created, updated, failed int, warning string) (*model.SyncRun, error) {
		ended := e.now()
		run.Pages = pages
		run.Fetched = fetched
		run.Created = created
		run.Updated = updated
		run.Failed = failed
		run.FinishedAt = &ended
		run.DurationMS = ended.Sub(started).Milliseconds()
		if err != nil {
			run.Status = "failed"
			run.Error = err.Error()
			if connector.Throttled(err) {
				run.Status = "throttled"
			}
		} else if failed > 0 || warning != "" {
			run.Status = "partial"
			run.Error = warning
		} else {
			run.Status = "success"
		}
		if ferr := e.store.FinishSyncRun(ctx, run); ferr != nil {
			e.log.Error("finish sync run", "error", ferr)
		}
		return run, err
	}

	state, err := e.store.GetSyncState(ctx, acct.ID)
	if err != nil {
		return finish(err, 0, 0, 0, 0, 0, "")
	}
	attempted := e.now()
	state.LastAttemptAt = &attempted
	if err := e.store.SaveSyncState(ctx, state); err != nil {
		return finish(err, 0, 0, 0, 0, 0, "")
	}

	conn, err := e.newConnector(ctx, acct)
	if err != nil {
		state.LastError = err.Error()
		state.LastErrorAt = &attempted
		state.ConsecutiveFailures++
		e.store.SaveSyncState(ctx, state)
		return finish(err, 0, 0, 0, 0, 0, "")
	}
	defer connector.Close(conn)

	// An interrupted window resumes from the last successfully stored page so
	// a throttled backfill does not restart from page one and burn the quota.
	start, end := e.window(acct, state)
	token := ""
	if !state.PendingEnd.IsZero() {
		start, end = state.PendingStart, state.PendingEnd
		token = state.PendingToken
	}
	if !end.After(start) {
		state.CursorEnd = end
		state.PendingStart = time.Time{}
		state.PendingEnd = time.Time{}
		state.PendingToken = ""
		state.LastSuccessAt = ptrNow(e.now())
		state.LastError = ""
		state.LastErrorAt = nil
		state.ConsecutiveFailures = 0
		state.ItemsLastRun = 0
		state.LastDurationMS = 0
		if serr := e.store.SaveSyncState(ctx, state); serr != nil {
			return finish(serr, 0, 0, 0, 0, 0, "")
		}
		return finish(nil, 0, 0, 0, 0, 0, "")
	}

	e.log.Info("sync window", "account", acct.Name, "provider", acct.Provider, "start", start, "end", end, "resume", token != "")

	pageSize := connector.OptionInt(acct.Options, "page_size", e.opts.PageSize)
	maxPages := connector.OptionInt(acct.Options, "max_pages", e.opts.MaxPages)
	pages, fetched, created, updated, failed := 0, 0, 0, 0, 0
	var firstRecordErr string

	retryPending := func() error {
		if len(state.PendingRecords) == 0 {
			return nil
		}
		pending := state.PendingRecords
		state.PendingRecords = nil
		for _, raw := range pending {
			isNew, err := e.processRecord(ctx, acct, conn, raw, end)
			if err != nil {
				failed++
				if firstRecordErr == "" {
					firstRecordErr = err.Error()
				}
				state.PendingRecords = append(state.PendingRecords, raw)
				continue
			}
			if isNew {
				created++
			} else {
				updated++
			}
		}
		if len(state.PendingRecords) > 0 {
			state.LastError = fmt.Sprintf("%d pending record(s) still failing: %s", len(state.PendingRecords), firstRecordErr)
			state.LastErrorAt = ptrNow(e.now())
			state.ConsecutiveFailures++
			if serr := e.store.SaveSyncState(ctx, state); serr != nil {
				return serr
			}
			return fmt.Errorf("%s", state.LastError)
		}
		// The page's failed records are now durable in the alert table. Keep
		// the page token so the next fetch continues after that page.
		return e.store.SaveSyncState(ctx, state)
	}

	for {
		if len(state.PendingRecords) > 0 {
			if err := retryPending(); err != nil {
				return finish(err, pages, fetched, created, updated, failed, "")
			}
			if token == "" {
				// The failed page was the last page in the window.
				break
			}
		}

		pages++
		page, err := e.fetchWithRetry(ctx, conn, connector.Query{
			Start:    start,
			End:      end,
			PageSize: pageSize,
			Token:    token,
		})
		if err != nil {
			state.LastError = err.Error()
			state.LastErrorAt = ptrNow(e.now())
			if !connector.Throttled(err) {
				state.ConsecutiveFailures++
			}
			state.LastDurationMS = e.now().Sub(started).Milliseconds()
			e.store.SaveSyncState(ctx, state)
			return finish(err, pages-1, fetched, created, updated, failed, "")
		}

		fetched += len(page.Records)
		pageFailed := make([]json.RawMessage, 0)
		for _, record := range page.Records {
			isNew, err := e.processRecord(ctx, acct, conn, record.Raw, end)
			if err != nil {
				failed++
				pageFailed = append(pageFailed, record.Raw)
				if firstRecordErr == "" {
					firstRecordErr = err.Error()
				}
				continue
			}
			if isNew {
				created++
			} else {
				updated++
			}
		}

		if len(pageFailed) > 0 {
			// Never advance the cursor over a record that was not persisted.
			// The failed raw payloads and the next page token are saved so the
			// next run retries them instead of silently skipping a window.
			state.PendingStart = start
			state.PendingEnd = end
			state.PendingToken = page.NextToken
			state.PendingRecords = pageFailed
			state.LastError = fmt.Sprintf("%d alert(s) failed to normalize/store: %s", len(pageFailed), firstRecordErr)
			state.LastErrorAt = ptrNow(e.now())
			state.LastDurationMS = e.now().Sub(started).Milliseconds()
			state.ItemsLastRun = fetched
			state.ConsecutiveFailures++
			if serr := e.store.SaveSyncState(ctx, state); serr != nil {
				return finish(serr, pages, fetched, created, updated, failed, "")
			}
			return finish(fmt.Errorf("%s", state.LastError), pages, fetched, created, updated, failed, "")
		}

		if page.NextToken == "" {
			break
		}
		// Persist progress before requesting the next page, so a throttle or a
		// crash mid-backfill is resumable.
		state.PendingStart = start
		state.PendingEnd = end
		state.PendingToken = page.NextToken
		if err := e.store.SaveSyncState(ctx, state); err != nil {
			return finish(err, pages, fetched, created, updated, failed, "")
		}
		if pages >= maxPages {
			// A page budget is a normal pause, not a failure: the pending token
			// lets the next scheduled run continue where this one stopped.
			state.LastError = ""
			state.LastErrorAt = nil
			state.ConsecutiveFailures = 0
			state.LastDurationMS = e.now().Sub(started).Milliseconds()
			if err := e.store.SaveSyncState(ctx, state); err != nil {
				return finish(err, pages, fetched, created, updated, failed, "")
			}
			warning := fmt.Sprintf("page budget %d reached for window %s..%s; progress saved, next run resumes from the stored page token",
				maxPages, start.Format(time.RFC3339), end.Format(time.RFC3339))
			return finish(nil, pages, fetched, created, updated, failed, warning)
		}
		token = page.NextToken
	}

	ended := e.now()
	state.CursorEnd = end
	state.PendingStart = time.Time{}
	state.PendingEnd = time.Time{}
	state.PendingToken = ""
	state.PendingRecords = nil
	state.LastSuccessAt = &ended
	state.LastError = ""
	state.LastErrorAt = nil
	state.LastDurationMS = ended.Sub(started).Milliseconds()
	state.ItemsLastRun = fetched
	state.ConsecutiveFailures = 0
	if err := e.store.SaveSyncState(ctx, state); err != nil {
		return finish(err, pages, fetched, created, updated, failed, "")
	}

	return finish(nil, pages, fetched, created, updated, failed, "")
}

func (e *Engine) processRecord(ctx context.Context, acct model.Account, conn connector.Connector, raw json.RawMessage, windowEnd time.Time) (bool, error) {
	alert, err := conn.Normalize(raw)
	if err != nil {
		return false, fmt.Errorf("normalize: %w", err)
	}
	rec, err := e.buildRecord(acct, conn.Info(), alert, windowEnd)
	if err != nil {
		return false, err
	}
	return e.store.UpsertAlert(ctx, rec)
}

func (e *Engine) window(acct model.Account, state *model.SyncState) (time.Time, time.Time) {
	now := e.now()
	lookback := connector.OptionDuration(acct.Options, "initial_lookback", e.opts.InitialLookback)
	overlap := connector.OptionDuration(acct.Options, "overlap", e.opts.Overlap)
	start := now.Add(-lookback)
	if !state.CursorEnd.IsZero() {
		start = state.CursorEnd.Add(-overlap)
	}
	end := now
	if e.opts.MaxWindow > 0 && end.Sub(start) > e.opts.MaxWindow {
		end = start.Add(e.opts.MaxWindow)
	}
	return start, end
}

func (e *Engine) newConnector(ctx context.Context, acct model.Account) (connector.Connector, error) {
	cred, err := credential.Load(ctx, e.store, e.cipher, acct.ID)
	if err != nil {
		return nil, err
	}
	return e.registry.New(connector.AccountConfig{
		Provider:   acct.Provider,
		AccountID:  acct.ID,
		Name:       acct.Name,
		AccountUID: acct.AccountUID,
		Region:     acct.Region,
		Options:    acct.Options,
		Credential: cred,
	})
}

func (e *Engine) buildRecord(acct model.Account, desc connector.Descriptor, alert model.Alert, windowEnd time.Time) (*model.AlertRecord, error) {
	if alert.EventTime.IsZero() {
		alert.EventTime = windowEnd
	}
	if alert.FirstSeenAt.IsZero() {
		alert.FirstSeenAt = alert.EventTime
	}
	if alert.LastSeenAt.IsZero() {
		alert.LastSeenAt = alert.EventTime
	}
	if alert.Region == "" {
		alert.Region = acct.Region
	}
	alert.MapperVersion = desc.MapperVersion

	payload, err := normalize.Build(alert, acct, normalize.Info{
		VendorName:     desc.Vendor,
		ProductName:    desc.Product,
		ProductUID:     desc.ProductUID,
		ProductVersion: desc.APIVersion,
		LogProvider:    desc.Vendor,
		MapperVersion:  desc.MapperVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("build ocsf payload: %w", err)
	}
	alert.OCSF = payload

	return &model.AlertRecord{
		AccountID:   acct.ID,
		AccountName: acct.Name,
		Provider:    acct.Provider,
		AccountUID:  acct.AccountUID,
		Alert:       alert,
		Status:      model.StatusOpen,
	}, nil
}

func (e *Engine) fetchWithRetry(ctx context.Context, conn connector.Connector, q connector.Query) (connector.Page, error) {
	const attempts = 5
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		page, err := conn.Fetch(ctx, q)
		if err == nil {
			return page, nil
		}
		lastErr = err
		if ctx.Err() != nil || !connector.Retryable(err) || attempt == attempts {
			break
		}
		delay := connector.RetryDelay(attempt)
		e.log.Warn("connector fetch failed, retrying", "provider", conn.Info().ID, "attempt", attempt, "delay", delay, "error", err)
		select {
		case <-ctx.Done():
			return connector.Page{}, ctx.Err()
		case <-time.After(delay):
		}
	}
	return connector.Page{}, lastErr
}

func ptrNow(t time.Time) *time.Time { return &t }
