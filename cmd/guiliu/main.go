// Command guiliu runs the GuiLiu security data hub.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/app"
	"github.com/BaiLi-Labs/GuiLiu/internal/auth"
	"github.com/BaiLi-Labs/GuiLiu/internal/config"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/normalize"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/BaiLi-Labs/GuiLiu/internal/timeutil"
	"github.com/BaiLi-Labs/GuiLiu/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		return serve(nil)
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "mcp":
		return runMCP(args[1:])
	case "sync":
		return runSync(args[1:])
	case "probe":
		return runProbe(args[1:])
	case "accounts":
		return runAccounts(args[1:])
	case "user":
		return runUser(args[1:])
	case "version", "-v", "--version":
		fmt.Printf("guiliu %s (commit %s, built %s)\n", version.Version, version.Commit, version.BuildDate)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		if strings.HasPrefix(args[0], "-") {
			return serve(args)
		}
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Print(`GuiLiu — vendor-neutral cloud security alert hub

Usage:
  guiliu serve    [-config path]   Start REST API, Web console and MCP HTTP endpoint
  guiliu mcp      [-config path]   Run the MCP server over stdio
  guiliu sync     [-config path] [-account id|name] [-all]
  guiliu probe    [-config path] -account id|name [-since 24h] [-limit 5] [-raw] [-mapped]
  guiliu accounts [-config path]
  guiliu user list    [-config path]
  guiliu user add     [-config path] -username alice [-role admin|viewer]
  guiliu user passwd  [-config path] -username alice
  guiliu version

  Passwords for user commands are read from GUILIU_NEW_PASSWORD (not argv).

Environment:
  GUILIU_CONFIG           Config path (same as -config)
  GUILIU_LISTEN           Listen address (default 127.0.0.1:8080)
  GUILIU_DATABASE         SQLite path (default data/guiliu.db)
  GUILIU_DEV=1            Disable login (local development only)
  GUILIU_MOCK=1           Mock Tencent data, in-memory DB, no login
  GUILIU_ADMIN_PASSWORD   Initial admin password on first start
  GUILIU_ADMIN_USER       Initial admin username (default admin)
  GUILIU_SECURE_COOKIES=1 Set Secure on session cookies (HTTPS)
  GUILIU_SECRET_KEY       Base64 32-byte AES key (otherwise data/secret.key)
  GUILIU_SECRET_KEY_FILE  Path to the AES key file
  GUILIU_LOG_LEVEL        debug|info|warn|error

Docs: see README.md for account onboarding and MCP client configuration.
`)
}

func serve(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file (default: ./guiliu.json if present)")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	log := newLogger(cfg.LogLevel)
	a, err := app.New(cfg, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		return 1
	}
	defer a.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		log.Error("server stopped", "error", err)
		return 1
	}
	log.Info("shutdown complete")
	return 0
}

func runMCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	log := newLogger(cfg.LogLevel)
	a, err := app.New(cfg, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		return 1
	}
	defer a.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.MCP.ServeStdio(ctx, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mcp:", err)
		return 1
	}
	return 0
}

func runSync(args []string) int {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file")
	accountRef := fs.String("account", "", "account id or name")
	all := fs.Bool("all", false, "sync all enabled accounts")
	_ = fs.Parse(args)

	if !*all && *accountRef == "" {
		fmt.Fprintln(os.Stderr, "either -account or -all is required")
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	log := newLogger(cfg.LogLevel)
	a, err := app.New(cfg, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		return 1
	}
	defer a.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if *all {
		a.Engine.SyncAll(ctx, "cli")
		runs, err := a.Store.ListSyncRuns(ctx, "", 20)
		if err != nil {
			fmt.Fprintln(os.Stderr, "list runs:", err)
			return 1
		}
		printRuns(runs)
		return 0
	}

	acct, err := resolveAccount(ctx, a, *accountRef)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	run, err := a.Engine.SyncAccount(ctx, *acct, "cli")
	if run != nil {
		printRun(*run)
	}
	if err != nil {
		return 1
	}
	return 0
}

func runProbe(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file")
	accountRef := fs.String("account", "", "account id or name")
	sinceStr := fs.String("since", "24h", "lookback window, e.g. 24h or 7d")
	limit := fs.Int("limit", 5, "number of alerts to fetch (max 100)")
	rawOut := fs.Bool("raw", false, "print raw vendor JSON lines")
	mappedOut := fs.Bool("mapped", false, "print normalized JSON including OCSF")
	_ = fs.Parse(args)

	if *accountRef == "" {
		fmt.Fprintln(os.Stderr, "-account is required")
		return 2
	}
	if *limit < 1 {
		*limit = 1
	}
	if *limit > 100 {
		*limit = 100
	}
	since, ok := timeutil.ParseDuration(*sinceStr)
	if !ok {
		fmt.Fprintln(os.Stderr, "-since must be a positive duration like 24h or 7d")
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	log := newLogger(cfg.LogLevel)
	a, err := app.New(cfg, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		return 1
	}
	defer a.Close()

	acct, err := resolveAccount(context.Background(), a, *accountRef)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	conn, err := a.Connector(context.Background(), *acct)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connector:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	end := time.Now().UTC()
	start := end.Add(-since)
	page, err := fetchPageWithRetry(ctx, conn, connector.Query{Start: start, End: end, PageSize: *limit})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fetch:", err)
		return 1
	}
	records := page.Records
	if len(records) > *limit {
		records = records[:*limit]
	}
	if len(records) == 0 {
		fmt.Printf("no alerts in the last %s for %s (total=%d)\n", since, acct.Name, page.Total)
		return 0
	}

	if *rawOut {
		for _, rec := range records {
			fmt.Println(string(rec.Raw))
		}
		return 0
	}

	if *mappedOut {
		desc := conn.Info()
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		for _, rec := range records {
			alert, err := conn.Normalize(rec.Raw)
			if err != nil {
				fmt.Fprintln(os.Stderr, "normalize:", err)
				continue
			}
			if alert.EventTime.IsZero() {
				alert.EventTime = end
			}
			if alert.FirstSeenAt.IsZero() {
				alert.FirstSeenAt = alert.EventTime
			}
			if alert.LastSeenAt.IsZero() {
				alert.LastSeenAt = alert.EventTime
			}
			payload, err := normalize.Build(alert, *acct, normalize.Info{
				VendorName:     desc.Vendor,
				ProductName:    desc.Product,
				ProductUID:     desc.ProductUID,
				ProductVersion: desc.APIVersion,
				LogProvider:    desc.Vendor,
				MapperVersion:  desc.MapperVersion,
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "ocsf:", err)
				continue
			}
			alert.OCSF = payload
			if err := enc.Encode(alert); err != nil {
				fmt.Fprintln(os.Stderr, "encode:", err)
				return 1
			}
		}
		return 0
	}

	fmt.Printf("%s  %-8s  %-19s  %-28s  %s → %s  %s\n",
		acct.Name, conn.Info().Product, "TIME", "TITLE", "SRC", "DST", "ASSET")
	for _, rec := range records {
		alert, err := conn.Normalize(rec.Raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "normalize:", err)
			continue
		}
		if alert.EventTime.IsZero() {
			alert.EventTime = end
		}
		fmt.Printf("%s  %-8s  %-19s  %-28s  %s → %s  %s\n",
			acct.Name,
			alert.Product,
			alert.EventTime.Local().Format("2006-01-02 15:04:05"),
			truncate(alert.Title, 28),
			orDash(alert.SourceIP),
			orDash(alert.DestinationIP),
			orDash(alert.Resource.Name),
		)
	}
	fmt.Printf("\nfetched %d of %d alerts (%s .. %s)\n", len(records), page.Total, connector.FormatBeijing(start), connector.FormatBeijing(end))
	return 0
}

func runAccounts(args []string) int {
	fs := flag.NewFlagSet("accounts", flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	log := newLogger(cfg.LogLevel)
	a, err := app.New(cfg, log)
	if err != nil {
		log.Error("startup failed", "error", err)
		return 1
	}
	defer a.Close()

	ctx := context.Background()
	accounts, err := a.Store.ListAccounts(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "list accounts:", err)
		return 1
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tPROVIDER\tACCOUNT\tREGION\tENABLED\tCREDENTIAL\tLAST SUCCESS\tITEMS\tERROR")
	for i := range accounts {
		acct := &accounts[i]
		state, _ := a.Store.GetSyncState(ctx, acct.ID)
		lastSuccess := "-"
		if state.LastSuccessAt != nil {
			lastSuccess = state.LastSuccessAt.Local().Format("2006-01-02 15:04")
		}
		credState := "missing"
		if acct.CredentialSet {
			credState = "ok " + acct.AccessKeyHint
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\t%s\t%s\t%d\t%s\n",
			acct.Name, acct.Provider, acct.AccountUID, acct.Region, acct.Enabled, credState, lastSuccess, state.ItemsLastRun, truncate(state.LastError, 60))
	}
	_ = w.Flush()
	return 0
}

func runUser(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: guiliu user list|add|passwd [-config path] [-username name] [-role admin|viewer]")
		return 2
	}
	sub := args[0]
	if sub != "list" && sub != "add" && sub != "passwd" {
		fmt.Fprintf(os.Stderr, "unknown user command %q\n", sub)
		return 2
	}
	fs := flag.NewFlagSet("user "+sub, flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file")
	username := fs.String("username", "", "username")
	role := fs.String("role", "viewer", "role: admin or viewer")
	_ = fs.Parse(args[1:])

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	st, err := store.Open(cfg.Database)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open database:", err)
		return 1
	}
	defer st.Close()

	logger := newLogger(cfg.LogLevel)
	svc := auth.New(st, auth.Config{
		DevMode:       cfg.Auth.DevMode,
		SessionTTL:    cfg.Auth.SessionTTL.Get(),
		SecureCookies: cfg.Auth.SecureCookies,
		AdminUser:     cfg.Auth.AdminUser,
	}, logger)
	ctx := context.Background()

	switch sub {
	case "list":
		users, err := svc.ListUsers(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "list users:", err)
			return 1
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "USERNAME\tROLE\tDISABLED\tCREATED")
		for i := range users {
			u := &users[i]
			fmt.Fprintf(w, "%s\t%s\t%v\t%s\n", u.Username, u.Role, u.Disabled, u.CreatedAt.Local().Format("2006-01-02 15:04"))
		}
		_ = w.Flush()
		return 0
	case "add":
		if strings.TrimSpace(*username) == "" {
			fmt.Fprintln(os.Stderr, "-username is required")
			return 2
		}
		pw := os.Getenv("GUILIU_NEW_PASSWORD")
		if pw == "" {
			fmt.Fprintln(os.Stderr, "set GUILIU_NEW_PASSWORD to the new password (it is intentionally not read from argv)")
			return 2
		}
		if *role != "admin" && *role != "viewer" {
			fmt.Fprintln(os.Stderr, "-role must be admin or viewer")
			return 2
		}
		u, err := svc.CreateUser(ctx, *username, pw, *role)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create user:", err)
			return 1
		}
		fmt.Printf("created user %s (%s)\n", u.Username, u.Role)
		return 0
	case "passwd":
		if strings.TrimSpace(*username) == "" {
			fmt.Fprintln(os.Stderr, "-username is required")
			return 2
		}
		pw := os.Getenv("GUILIU_NEW_PASSWORD")
		if pw == "" {
			fmt.Fprintln(os.Stderr, "set GUILIU_NEW_PASSWORD to the new password (it is intentionally not read from argv)")
			return 2
		}
		if err := svc.ResetPassword(ctx, *username, pw); err != nil {
			fmt.Fprintln(os.Stderr, "reset password:", err)
			return 1
		}
		fmt.Printf("password updated for %s; all sessions revoked\n", *username)
		return 0
	}
	return 2
}

func resolveAccount(ctx context.Context, a *app.App, ref string) (*model.Account, error) {
	if acct, err := a.Store.GetAccount(ctx, ref); err == nil {
		return acct, nil
	}
	acct, err := a.Store.GetAccountByName(ctx, ref)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("account %q not found", ref)
		}
		return nil, err
	}
	return acct, nil
}

func printRun(run model.SyncRun) {
	end := "running"
	if run.FinishedAt != nil {
		end = run.FinishedAt.Local().Format("2006-01-02 15:04:05")
	}
	fmt.Printf("run %s account=%s status=%s pages=%d fetched=%d created=%d updated=%d failed=%d duration=%dms finished=%s\n",
		run.ID, run.AccountID, run.Status, run.Pages, run.Fetched, run.Created, run.Updated, run.Failed, run.DurationMS, end)
	if run.Error != "" {
		label := "error"
		if run.Status == "partial" || run.Status == "throttled" {
			label = "note"
		}
		fmt.Printf("%s: %s\n", label, run.Error)
	}
}

func printRuns(runs []model.SyncRun) {
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "STARTED\tACCOUNT\tTRIGGER\tSTATUS\tFETCHED\tCREATED\tUPDATED\tFAILED\tERROR")
	for i := range runs {
		r := &runs[i]
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%s\n",
			r.StartedAt.Local().Format("2006-01-02 15:04:05"), r.AccountID, r.Trigger, r.Status, r.Fetched, r.Created, r.Updated, r.Failed, truncate(r.Error, 60))
	}
	_ = w.Flush()
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n <= 1 {
		return string(runes[:n])
	}
	return string(runes[:n-1]) + "…"
}

func fetchPageWithRetry(ctx context.Context, conn connector.Connector, q connector.Query) (connector.Page, error) {
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
		fmt.Fprintf(os.Stderr, "fetch failed (attempt %d/%d), retrying in %s: %v\n", attempt, attempts, delay, err)
		select {
		case <-ctx.Done():
			return connector.Page{}, ctx.Err()
		case <-time.After(delay):
		}
	}
	return connector.Page{}, lastErr
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
