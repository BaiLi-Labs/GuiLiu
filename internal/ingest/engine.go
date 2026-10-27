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

// ErrPushOnly is returned when polling is requested for a source that only
// accepts pushed records.
var ErrPushOnly = errors.New("source only accepts pushed records")

var ErrQueryOnly = errors.New("source supports explicit remote event queries only")

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
		if !acct.Enabled || !e.polls(acct.Provider) {
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
	if !e.polls(acct.Provider) {
		if d, ok := e.registry.Descriptor(acct.Provider); ok && d.QueryOnly {
			return false, ErrQueryOnly
		}
		return false, ErrPushOnly
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
	if !e.polls(acct.Provider) {
		if d, ok := e.registry.Descriptor(acct.Provider); ok && d.QueryOnly {
			return nil, ErrQueryOnly
		}
		return nil, ErrPushOnly
	}
	if !e.acquire(acct.ID) {
		return nil, ErrAlreadyRunning
	}
	defer e.release(acct.ID)
	return e.syncAccount(ctx, acct, trigger)
}

// polls reports whether the source exposes a polling API. Unknown providers
// default to polling so a misconfiguration surfaces as a real connector error.
func (e *Engine) polls(provider string) bool {
	if e.registry == nil {
		return true
	}
	desc, ok := e.registry.Descriptor(provider)
	return !ok || (!desc.PushOnly && !desc.QueryOnly)
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
			run.SourceError = connector.SourceError(err)
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
		state.LastSourceError = connector.SourceError(err)
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
		state.LastSourceError = nil
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
	fail := func(err error) (*model.SyncRun, error) {
		state.LastError = err.Error()
		state.LastSourceError = connector.SourceError(err)
		state.LastErrorAt = ptrNow(e.now())
		state.ConsecutiveFailures++
		state.LastDurationMS = e.now().Sub(started).Milliseconds()
		if saveErr := e.store.SaveSyncState(ctx, state); saveErr != nil {
			err = errors.Join(err, saveErr)
		}
		return finish(err, pages, fetched, created, updated, failed, "")
	}

	// Retry a bounded batch without preventing collection of newer alerts.
	var errRetry error
	created, updated, failed, errRetry = e.retryFailures(ctx, acct, conn)
	if errRetry != nil {
		return fail(errRetry)
	}
	resetToken := false
	for {
		page, err := e.fetchWithRetry(ctx, conn, connector.Query{
			Start: start, End: end, PageSize: pageSize, Token: token,
		})
		if err != nil {
			if token != "" && !resetToken && connector.InvalidCursor(err) {
				// Replay this fixed window, never move the time cursor past it.
				resetToken, token = true, ""
				state.PendingStart, state.PendingEnd, state.PendingToken = start, end, ""
				if err := e.store.SaveSyncState(ctx, state); err != nil {
					return fail(err)
				}
				continue
			}
			return fail(err)
		}
		pages++
		fetched += len(page.Records)
		for _, record := range page.Records {
			isNew, changed, err := e.processRecord(ctx, acct, conn, record.Raw, e.now())
			if err != nil {
				var mappingErr *mappingError
				if !errors.As(err, &mappingErr) {
					return fail(err) // Storage/cancellation errors must not advance a page.
				}
				if err := e.saveFailure(ctx, acct, conn, record.Raw, end, err); err != nil {
					return fail(err)
				}
				failed++
				continue
			}
			if isNew {
				created++
			} else if changed {
				updated++
			}
		}
		if page.NextToken == "" {
			break
		}
		if page.NextToken == token {
			return fail(errors.New("connector returned the same page token; cursor not advanced"))
		}
		state.PendingStart, state.PendingEnd, state.PendingToken = start, end, page.NextToken
		state.LastError, state.LastErrorAt, state.ConsecutiveFailures = "", nil, 0
		state.LastSourceError = nil
		state.LastDurationMS = e.now().Sub(started).Milliseconds()
		state.ItemsLastRun = fetched
		if err := e.store.SaveSyncState(ctx, state); err != nil {
			return fail(err)
		}
		if pages >= maxPages {
			return finish(nil, pages, fetched, created, updated, failed, "page budget reached; next run resumes from the saved page token")
		}
		token = page.NextToken
	}

	ended := e.now()
	if state.CoverageStart.IsZero() {
		state.CoverageStart = start
	}
	state.CursorEnd = end
	state.PendingStart, state.PendingEnd, state.PendingToken = time.Time{}, time.Time{}, ""
	state.LastSuccessAt = &ended
	state.LastError, state.LastErrorAt, state.ConsecutiveFailures = "", nil, 0
	state.LastSourceError = nil
	state.LastDurationMS = ended.Sub(started).Milliseconds()
	state.ItemsLastRun = fetched
	if err := e.store.SaveSyncState(ctx, state); err != nil {
		return fail(err)
	}
	_, remaining, err := e.store.ListIngestFailures(ctx, acct.ID, 1)
	if err != nil {
		return fail(err)
	}
	warning := ""
	if remaining > 0 {
		warning = fmt.Sprintf("%d record(s) retained for mapping retry", remaining)
	}
	return finish(nil, pages, fetched, created, updated, failed, warning)
}

// mappingError distinguishes malformed payloads from storage failures.
type mappingError struct{ error }

func (e *Engine) saveFailure(ctx context.Context, acct model.Account, conn connector.Connector, raw json.RawMessage, end time.Time, err error) error {
	return e.store.SaveIngestFailure(ctx, &model.IngestFailure{
		AccountID: acct.ID, Raw: raw, IngestedAt: e.now(),
		MapperVersion: conn.Info().MapperVersion, Error: err.Error(),
	})
}

func (e *Engine) retryFailures(ctx context.Context, acct model.Account, conn connector.Connector) (created, updated, failed int, err error) {
	items, _, err := e.store.ListIngestFailures(ctx, acct.ID, 100)
	if err != nil {
		return 0, 0, 0, err
	}
	for _, item := range items {
		isNew, changed, processErr := e.processRecord(ctx, acct, conn, item.Raw, item.IngestedAt)
		if processErr != nil {
			var mappingErr *mappingError
			if !errors.As(processErr, &mappingErr) {
				return created, updated, failed, processErr
			}
			item.Error, item.MapperVersion = processErr.Error(), conn.Info().MapperVersion
			if err := e.store.SaveIngestFailure(ctx, &item); err != nil {
				return created, updated, failed, err
			}
			failed++
			continue
		}
		if err := e.store.DeleteIngestFailure(ctx, item.ID); err != nil {
			return created, updated, failed, err
		}
		if isNew {
			created++
		} else if changed {
			updated++
		}
	}
	return created, updated, failed, nil
}

// IngestRaw normalizes and stores one raw source record. Pulling, retrying a
// failed mapping and pushing all share this function so identity, revision
// tracking and OCSF projection behave identically on every path.
func (e *Engine) IngestRaw(ctx context.Context, acct model.Account, conn connector.Connector, raw json.RawMessage, ingestedAt time.Time) (bool, bool, error) {
	alert, err := conn.Normalize(raw)
	if err != nil {
		return false, false, &mappingError{fmt.Errorf("normalize: %w", err)}
	}
	alert.Raw = append(json.RawMessage(nil), raw...)
	rec, err := e.buildRecord(acct, conn.Info(), alert, ingestedAt)
	if err != nil {
		return false, false, &mappingError{err}
	}
	created, err := e.store.UpsertAlert(ctx, rec)
	return created, rec.Changed, err
}

func (e *Engine) processRecord(ctx context.Context, acct model.Account, conn connector.Connector, raw json.RawMessage, ingestedAt time.Time) (bool, bool, error) {
	return e.IngestRaw(ctx, acct, conn, raw, ingestedAt)
}

// PushResult summarizes one pushed batch.
type PushResult struct {
	Created int
	Updated int
	Failed  int
}

// IngestPushed stores records delivered over a push transport. Malformed or
// unmappable payloads are retained in ingest_failures instead of being lost,
// exactly like a polling failure, so a later mapping fix can replay them.
// Duplicate delivery is not special-cased here: identity is the vendor alert
// id, so UpsertAlert naturally reports the second copy as unchanged.
func (e *Engine) IngestPushed(ctx context.Context, acct model.Account, conn connector.Connector, raws []connector.RawAlert, ingestedAt time.Time) (PushResult, error) {
	var result PushResult
	for _, record := range raws {
		if len(record.Raw) == 0 || !json.Valid(record.Raw) {
			result.Failed++
			if err := e.saveFailure(ctx, acct, conn, record.Raw, ingestedAt, errors.New("pushed record is not valid JSON")); err != nil {
				return result, err
			}
			continue
		}
		isNew, changed, err := e.IngestRaw(ctx, acct, conn, record.Raw, ingestedAt)
		if err != nil {
			var mappingErr *mappingError
			if !errors.As(err, &mappingErr) {
				return result, err
			}
			if err := e.saveFailure(ctx, acct, conn, record.Raw, ingestedAt, err); err != nil {
				return result, err
			}
			result.Failed++
			continue
		}
		if isNew {
			result.Created++
		} else if changed {
			result.Updated++
		}
	}
	if len(raws) > 0 {
		if err := e.markPushed(ctx, acct.ID, len(raws)); err != nil {
			return result, err
		}
	}
	return result, nil
}

// markPushed records freshness for push-only accounts. An account that has
// already completed a polling window keeps its cursor-derived health, because
// a push heartbeat must not hide a broken poller.
func (e *Engine) markPushed(ctx context.Context, accountID string, items int) error {
	state, err := e.store.GetSyncState(ctx, accountID)
	if err != nil {
		return err
	}
	if state.LastSuccessAt != nil && !state.CursorEnd.IsZero() {
		return nil
	}
	now := e.now()
	state.LastSuccessAt = &now
	state.LastAttemptAt = &now
	state.ItemsLastRun = items
	state.LastError, state.LastErrorAt, state.ConsecutiveFailures = "", nil, 0
	state.LastSourceError = nil
	return e.store.SaveSyncState(ctx, state)
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

func (e *Engine) buildRecord(acct model.Account, desc connector.Descriptor, alert model.Alert, ingestedAt time.Time) (*model.AlertRecord, error) {
	if alert.ExternalID == "" {
		return nil, errors.New("alert external id is required")
	}
	if alert.FindingKind == "" {
		alert.FindingKind = model.FindingOther
	}
	if alert.Region == "" {
		alert.Region = acct.Region
	}
	alert.MapperVersion = desc.MapperVersion
	alert.SourceAPI, alert.SourceAPIVersion = desc.SourceAPI, desc.APIVersion
	connector.ApplyProvenance(&alert, acct.Provider, acct)

	payload, err := normalize.Build(alert, acct, normalize.Info{
		VendorName:    desc.Vendor,
		ProductName:   desc.Product,
		ProductUID:    desc.ProductUID,
		LogProvider:   desc.Vendor,
		MapperVersion: desc.MapperVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("build ocsf payload: %w", err)
	}
	alert.OCSF = payload

	return &model.AlertRecord{
		IngestedAt:  ingestedAt,
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
