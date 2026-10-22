// Package cli implements the read-only GuiLiu query client. It is a thin
// adapter over the REST API: query semantics, validation and limits stay on the
// server, while the CLI adds agent-sized defaults, stable JSON/NDJSON output,
// deterministic pagination and shell composability.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/version"
)

type outputOptions struct {
	JSON     bool
	NDJSON   bool
	Pretty   bool
	Quiet    bool
	Describe bool
	Schema   bool
	Fields   string
}

func (o *outputOptions) validate() error {
	if o.Schema && !o.Describe {
		return usagef("--schema requires a command --describe")
	}
	if o.JSON && o.NDJSON {
		return usagef("use --json or --ndjson, not both")
	}
	if o.Pretty && !o.JSON {
		return usagef("--pretty requires --json")
	}
	if o.Fields != "" && o.JSON {
		return usagef("--fields supports table or --ndjson output; --json preserves the REST response")
	}
	return nil
}

type globalOptions struct {
	url        string
	apiKeyFile string
	timeout    time.Duration
	out        outputOptions
}

func (g *globalOptions) apiKey(stderr io.Writer) (string, error) {
	if path := strings.TrimSpace(g.apiKeyFile); path != "" {
		return readAPIKeyFile(path, stderr)
	}
	if key := strings.TrimSpace(os.Getenv("GUILIU_API_KEY")); key != "" {
		return key, nil
	}
	if path := strings.TrimSpace(os.Getenv("GUILIU_API_KEY_FILE")); path != "" {
		return readAPIKeyFile(path, stderr)
	}
	return "", nil
}

type runFunc func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error

type command struct {
	name     string
	summary  string
	usage    string
	endpoint string
	examples []string
	newRun   func(*globalOptions) (*flagSet, runFunc)
}

func registerGlobalFlags(fs *flagSet, g *globalOptions) {
	fs.String(&g.url, "url", g.url, "GuiLiu base URL (env GUILIU_URL)")
	fs.String(&g.apiKeyFile, "api-key-file", g.apiKeyFile, "Read the API key from a 0600 file (env GUILIU_API_KEY_FILE)")
	fs.Duration(&g.timeout, "timeout", g.timeout, "Per-request HTTP timeout (env GUILIU_TIMEOUT)")
	fs.Bool(&g.out.JSON, "json", g.out.JSON, "Print the exact REST JSON response (single page)")
	fs.Bool(&g.out.NDJSON, "ndjson", g.out.NDJSON, "Print one JSON record per line; combine with --all")
	fs.Bool(&g.out.Pretty, "pretty", g.out.Pretty, "Indent --json output")
	fs.Bool(&g.out.Quiet, "quiet", g.out.Quiet, "Suppress stderr metadata, including cursors and truncation notices")
	fs.Bool(&g.out.Describe, "describe", g.out.Describe, "Print command flags and response field names; add --schema for full JSON Schemas")
	fs.Bool(&g.out.Schema, "schema", g.out.Schema, "Include full response schemas with a command --describe")
	fs.String(&g.out.Fields, "fields", g.out.Fields, "Table columns or NDJSON JSON field paths, e.g. id,title,resource.id")
}

// Run executes `gl-cli query ...` and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	timeout, err := envDuration("GUILIU_TIMEOUT", defaultTimeout)
	if err != nil {
		fmt.Fprintf(stderr, "gl-cli query: %v\n", err)
		return 2
	}
	g := &globalOptions{
		url:        envOr("GUILIU_URL", defaultBaseURL),
		apiKeyFile: envOr("GUILIU_API_KEY_FILE", ""),
		timeout:    timeout,
	}

	gfs := newFlagSet("query", stderr)
	registerGlobalFlags(gfs, g)
	gfs.Usage = func() {}
	if err := gfs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printQueryUsage(stdout, gfs)
			return 0
		}
		fmt.Fprintf(stderr, "gl-cli query: %v\n\n", err)
		printQueryUsage(stderr, gfs)
		return 2
	}
	rest := gfs.Args()
	if g.out.Describe && len(rest) == 0 {
		if g.out.Schema {
			fmt.Fprintln(stderr, "--schema requires a command --describe")
			return 2
		}
		if err := describeAll(stdout, g, gfs); err != nil {
			fmt.Fprintf(stderr, "gl-cli query: %v\n", err)
			return 1
		}
		return 0
	}
	if len(rest) == 0 {
		printQueryUsage(stderr, gfs)
		return 2
	}
	if rest[0] == "help" {
		printQueryUsage(stdout, gfs)
		return 0
	}
	if rest[0] == "describe" {
		if len(rest) > 1 || g.out.Schema {
			fmt.Fprintln(stderr, "gl-cli query describe: no arguments are accepted; use <command> --describe --schema")
			return 2
		}
		if err := describeAll(stdout, g, gfs); err != nil {
			fmt.Fprintf(stderr, "gl-cli query: %v\n", err)
			return 1
		}
		return 0
	}
	cmd := findCommand(rest[0])
	if cmd == nil {
		fmt.Fprintf(stderr, "gl-cli query: unknown command %q\n\n", rest[0])
		printQueryUsage(stderr, gfs)
		return 2
	}
	fs, run := cmd.newRun(g)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	if err := fs.Parse(reorderArgs(fs, rest[1:])); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printCommandUsage(stdout, cmd, fs)
			return 0
		}
		fmt.Fprintf(stderr, "gl-cli query %s: %v\n\n", cmd.name, err)
		printCommandUsage(stderr, cmd, fs)
		return 2
	}
	if g.out.Describe {
		if err := describeCommand(stdout, g, gfs, cmd, fs); err != nil {
			fmt.Fprintf(stderr, "gl-cli query: %v\n", err)
			return 1
		}
		return 0
	}
	if err := g.out.validate(); err != nil {
		fmt.Fprintf(stderr, "gl-cli query %s: %v\n", cmd.name, err)
		return 2
	}
	if g.out.NDJSON && g.out.Fields != "" {
		if err := validateProjection(cmd.name, g.out.Fields); err != nil {
			fmt.Fprintf(stderr, "gl-cli query %s: %v\n", cmd.name, err)
			return 2
		}
	}
	key, err := g.apiKey(stderr)
	if err != nil {
		fmt.Fprintf(stderr, "gl-cli query %s: %v\n", cmd.name, err)
		return 2
	}
	c, err := newClient(config{BaseURL: g.url, APIKey: key, Timeout: g.timeout})
	if err != nil {
		fmt.Fprintf(stderr, "gl-cli query %s: %v\n", cmd.name, err)
		return 2
	}
	if err := run(context.Background(), c, &g.out, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "gl-cli query %s: %v\n", cmd.name, err)
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.Status == 401 {
			fmt.Fprintln(stderr, "hint: set GUILIU_API_KEY or pass --api-key-file; API keys are created in the GuiLiu console under API & MCP")
		}
		if isUsageError(err) {
			return 2
		}
		return 1
	}
	return 0
}

func commands() []*command {
	return []*command{
		{
			name:     "alerts",
			summary:  "List alerts with filters and bounded pagination",
			usage:    "gl-cli query alerts [flags]",
			endpoint: "GET /api/v1/alerts",
			examples: []string{
				"gl-cli query alerts --since 24h --severity high,critical --limit 20 --json",
				"gl-cli query alerts --since 7d --all --max-items 500 --ndjson | jq -c '{id,severity,title,event_time}'",
			},
			newRun: newAlertsCommand,
		},
		{
			name:     "alert",
			summary:  "Get one Finding with raw evidence; use context for asset observations",
			usage:    "gl-cli query alert <alert-id> [flags]",
			endpoint: "GET /api/v1/alerts/{id}",
			examples: []string{
				"gl-cli query alert 01JABCDEF --json",
				"gl-cli query alert 01JABCDEF --raw",
				"gl-cli query alert 01JABCDEF --revision 2 --json",
			},
			newRun: newAlertCommand,
		},
		{
			name:     "groups",
			summary:  "List exact-field alert groups without inventing verdicts",
			usage:    "gl-cli query groups [flags]",
			endpoint: "GET /api/v1/alerts/groups",
			examples: []string{
				"gl-cli query groups --group-by signature --since 24h --json",
				"gl-cli query groups --since 24h --all --ndjson",
			},
			newRun: newGroupsCommand,
		},
		{
			name:     "changes",
			summary:  "Read the persistent change log in sequence order",
			usage:    "gl-cli query changes [flags]",
			endpoint: "GET /api/v1/alerts/changes",
			examples: []string{
				"gl-cli query changes --limit 100 --json",
				"gl-cli query changes --cursor 12345 --all --max-items 5000 --ndjson",
			},
			newRun: newChangesCommand,
		},
		{
			name:     "stats",
			summary:  "Aggregate alert counts by severity, provider, status, day and asset",
			usage:    "gl-cli query stats [flags]",
			endpoint: "GET /api/v1/stats",
			examples: []string{
				"gl-cli query stats --since 7d --json",
			},
			newRun: newStatsCommand,
		},
		{
			name:     "coverage",
			summary:  "Show source scope, collection window, watermarks and limitations",
			usage:    "gl-cli query coverage [flags]",
			endpoint: "GET /api/v1/coverage",
			examples: []string{
				"gl-cli query coverage --since 7d --json",
			},
			newRun: newCoverageCommand,
		},
		{
			name:     "revisions",
			summary:  "List immutable revisions for one alert",
			usage:    "gl-cli query revisions <alert-id> [flags]",
			endpoint: "GET /api/v1/alerts/{id}/revisions",
			examples: []string{
				"gl-cli query revisions 01JABCDEF --limit 20 --json",
			},
			newRun: newRevisionsCommand,
		},
		{
			name:     "context",
			summary:  "Read current local asset context for one alert",
			usage:    "gl-cli query context <alert-id> [flags]",
			endpoint: "GET /api/v1/alerts/{id}/asset-context",
			examples: []string{
				"gl-cli query context 01JABCDEF --json",
			},
			newRun: newContextCommand,
		},
		{
			name:     "assets",
			summary:  "List locally saved control-plane assets",
			usage:    "gl-cli query assets [flags]",
			endpoint: "GET /api/v1/assets",
			examples: []string{
				"gl-cli query assets --provider tencent --limit 20 --json",
				"gl-cli query assets --all --max-items 200 --ndjson",
			},
			newRun: newAssetsCommand,
		},
		{
			name:     "asset",
			summary:  "Read one local asset observation by asset ID",
			usage:    "gl-cli query asset <asset-id> [flags]",
			endpoint: "GET /api/v1/assets/{id}",
			examples: []string{
				"gl-cli query asset 01JABCDEF --json",
			},
			newRun: newAssetCommand,
		},
		{
			name:     "lookup",
			summary:  "Follow an explicit cloud resource reference to a saved asset",
			usage:    "gl-cli query lookup --provider ... --account-uid ... --region ... --resource-type ... --resource-id ... [flags]",
			endpoint: "GET /api/v1/assets/lookup",
			examples: []string{
				"gl-cli query lookup --provider tencent --account-uid 123456789 --region ap-guangzhou --resource-type cvm --resource-id ins-abc --json",
			},
			newRun: newLookupCommand,
		},
		{
			name:     "findings",
			summary:  "List stored alerts that share an asset's exact host identity",
			usage:    "gl-cli query findings <asset-id> [flags]",
			endpoint: "GET /api/v1/assets/{id}/findings",
			examples: []string{
				"gl-cli query findings 01JABCDEF --all --ndjson",
			},
			newRun: newFindingsCommand,
		},
		{
			name:     "component",
			summary:  "Read exact source bytes for one asset component revision",
			usage:    "gl-cli query component <asset-id> --revision N --component KEY",
			endpoint: "GET /api/v1/assets/{id}/revisions/{revision}/components/{component}/raw",
			examples: []string{
				"gl-cli query component 01JABCDEF --revision 2 --component runtime | jq .",
			},
			newRun: newComponentCommand,
		},
		{
			name:     "health",
			summary:  "Show ingestion health for all accounts or one account",
			usage:    "gl-cli query health [flags]",
			endpoint: "GET /api/v1/health or GET /api/v1/accounts/{id}/health",
			examples: []string{
				"gl-cli query health --json",
				"gl-cli query health --account 01JABCDEF --json",
			},
			newRun: newHealthCommand,
		},
		{
			name:     "providers",
			summary:  "List connector capabilities, source APIs and mapper versions",
			usage:    "gl-cli query providers [flags]",
			endpoint: "GET /api/v1/providers",
			examples: []string{
				"gl-cli query providers --json",
			},
			newRun: newProvidersCommand,
		},
		{
			name:     "mapping",
			summary:  "Read the versioned field paths consumed by a connector mapper",
			usage:    "gl-cli query mapping --provider <id> [flags]",
			endpoint: "GET /api/v1/providers/{id}/mapping",
			examples: []string{
				"gl-cli query mapping --provider tencent --json",
			},
			newRun: newMappingCommand,
		},
		{
			name:     "failures",
			summary:  "List stored ingestion failures for one account",
			usage:    "gl-cli query failures --account <id> [flags]",
			endpoint: "GET /api/v1/accounts/{id}/failures",
			examples: []string{
				"gl-cli query failures --account 01JABCDEF --json",
			},
			newRun: newFailuresCommand,
		},
	}
}

// reorderArgs moves flags before positional arguments so
// `alert <id> --json` works as naturally as `alert --json <id>`. Go's flag
// package stops at the first positional argument; scanning with the registered
// definitions keeps flag values out of the positional list.
func reorderArgs(fs *flagSet, args []string) []string {
	takesValue := make(map[string]bool, len(fs.defs))
	for _, def := range fs.defs {
		if def.Type != "bool" {
			takesValue[def.Name] = true
		}
	}
	flags := make([]string, 0, len(args))
	positional := make([]string, 0, 2)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flags = append(flags, arg)
			name := strings.TrimLeft(arg, "-")
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				continue
			}
			if takesValue[name] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		positional = append(positional, arg)
	}
	return append(flags, positional...)
}

func noArgs(fs *flagSet) error {
	if fs.NArg() > 0 {
		return usagef("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	return nil
}

func findCommand(name string) *command {
	for _, cmd := range commands() {
		if cmd.name == name {
			return cmd
		}
	}
	return nil
}

func printQueryUsage(w io.Writer, fs *flagSet) {
	fmt.Fprintln(w, "GuiLiu query CLI — read-only REST client for agents and scripts")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  gl-cli query [global flags] <command> [flags]")
	fmt.Fprintln(w, "  gl-cli query describe")
	fmt.Fprintln(w, "  gl-cli query <command> --describe")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, cmd := range commands() {
		fmt.Fprintf(w, "  %-11s %s\n", cmd.name, cmd.summary)
	}
	fmt.Fprintf(w, "  %-11s %s\n", "describe", "Print machine-readable commands and flags")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Environment:")
	fmt.Fprintln(w, "  GUILIU_URL             Base URL (default "+defaultBaseURL+")")
	fmt.Fprintln(w, "  GUILIU_API_KEY         API key; never put it in argv")
	fmt.Fprintln(w, "  GUILIU_API_KEY_FILE    Read the key from a 0600 file")
	fmt.Fprintln(w, "  GUILIU_TIMEOUT         Per-request timeout (default 30s)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Global flags:")
	printFlags(w, fs)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Output: table by default; --json is the exact REST body; --ndjson is one record per line.")
	fmt.Fprintln(w, "Exit codes: 0 success, 1 API/network error, 2 usage error.")
}

func printCommandUsage(w io.Writer, cmd *command, fs *flagSet) {
	fmt.Fprintf(w, "%s\n\n", cmd.summary)
	fmt.Fprintf(w, "Endpoint: %s\n\n", cmd.endpoint)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  %s\n\n", cmd.usage)
	if len(cmd.examples) > 0 {
		fmt.Fprintln(w, "Examples:")
		for _, example := range cmd.examples {
			fmt.Fprintf(w, "  %s\n", example)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "Flags:")
	printFlags(w, fs)
}

func printFlags(w io.Writer, fs *flagSet) {
	old := fs.Output()
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(old)
}

type authInfo struct {
	Env    []string `json:"env"`
	Header string   `json:"header"`
	Note   string   `json:"note"`
}

type outputInfo struct {
	Default   string            `json:"default"`
	JSON      string            `json:"json"`
	NDJSON    string            `json:"ndjson"`
	Fields    string            `json:"fields,omitempty"`
	ExitCodes map[string]string `json:"exit_codes"`
}

type limitsInfo struct {
	AlertWindow string `json:"default_alert_window"`
	GroupWindow string `json:"default_group_window"`
	MaxRange    string `json:"max_range"`
	MaxPage     int    `json:"max_page"`
	MaxItems    int    `json:"default_max_items"`
}

type commandInfo struct {
	Name           string            `json:"name"`
	Summary        string            `json:"summary"`
	Usage          string            `json:"usage"`
	Endpoint       string            `json:"endpoint"`
	Examples       []string          `json:"examples"`
	Flags          []flagDef         `json:"flags,omitempty"`
	ResponseFields map[string]string `json:"response_fields,omitempty"`
	NDJSONFields   map[string]string `json:"ndjson_item_fields,omitempty"`
	ResponseSchema map[string]any    `json:"response_schema,omitempty"`
	NDJSONSchema   map[string]any    `json:"ndjson_item_schema,omitempty"`
}

type describeOutput struct {
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	Description string        `json:"description"`
	BaseURL     string        `json:"base_url"`
	Auth        authInfo      `json:"auth"`
	Output      outputInfo    `json:"output"`
	Limits      limitsInfo    `json:"limits"`
	GlobalFlags []flagDef     `json:"global_flags,omitempty"`
	Commands    []commandInfo `json:"commands,omitempty"`
	Command     *commandInfo  `json:"command,omitempty"`
}

func describeAll(w io.Writer, g *globalOptions, gfs *flagSet) error {
	out := describeOutput{
		Name:        "gl-cli query",
		Version:     version.Version,
		Description: "Read-only REST client for GuiLiu alerts, groups, changes, coverage, assets and ingestion health.",
		BaseURL:     g.url,
		Auth:        describeAuth(),
		Output:      describeOutputFormat(),
		Limits:      describeLimits(),
		GlobalFlags: gfs.defs,
	}
	for _, cmd := range commands() {
		fs, _ := cmd.newRun(copyGlobal(g))
		info := commandInfoFrom(cmd, fs, len(gfs.defs), false)
		info.Flags, info.Examples, info.ResponseFields, info.NDJSONFields = nil, nil, nil, nil
		out.Commands = append(out.Commands, info)
	}
	return writeDescribe(w, out)
}

func describeCommand(w io.Writer, g *globalOptions, gfs *flagSet, cmd *command, fs *flagSet) error {
	info := commandInfoFrom(cmd, fs, len(gfs.defs), g.out.Schema)
	out := describeOutput{
		Name:        "gl-cli query",
		Version:     version.Version,
		Description: "Read-only REST client for GuiLiu alerts, groups, changes, coverage, assets and ingestion health.",
		BaseURL:     g.url,
		Auth:        describeAuth(),
		Output:      describeOutputFormat(),
		Limits:      describeLimits(),
		GlobalFlags: gfs.defs,
		Command:     &info,
	}
	return writeDescribe(w, out)
}

func commandInfoFrom(cmd *command, fs *flagSet, globalCount int, schema bool) commandInfo {
	flags := []flagDef{}
	if globalCount < len(fs.defs) {
		flags = append(flags, fs.defs[globalCount:]...)
	}
	info := commandInfo{
		Name:           cmd.name,
		Summary:        cmd.summary,
		Usage:          cmd.usage,
		Endpoint:       cmd.endpoint,
		Examples:       cmd.examples,
		Flags:          flags,
		ResponseFields: compactFields(responseSchema(cmd.name)),
		NDJSONFields:   compactFields(ndjsonSchema(cmd.name)),
	}
	if schema {
		info.ResponseSchema, info.NDJSONSchema = responseSchema(cmd.name), ndjsonSchema(cmd.name)
	}
	return info
}

func describeAuth() authInfo {
	return authInfo{
		Env:    []string{"GUILIU_URL", "GUILIU_API_KEY", "GUILIU_API_KEY_FILE"},
		Header: "Authorization: Bearer <API_KEY>",
		Note:   "The CLI sends X-Guiliu-Client: cli, so access audit records surface=cli. Keys inherit their owner's role and can read every account in the instance.",
	}
}

func describeOutputFormat() outputInfo {
	return outputInfo{
		Default: "table",
		JSON:    "Exact REST response body; one page only, because --all is rejected with --json.",
		NDJSON:  "One JSON record per line; pagination metadata and the next cursor go to stderr. Combine with --all for batches.",
		Fields:  "Table columns or NDJSON JSON field paths. NDJSON preserves nested objects and exact JSON numbers; absent optional fields become null. Arrays/maps/raw payloads can be selected whole, not traversed. --json always preserves the full REST response.",
		ExitCodes: map[string]string{
			"0": "success, including an empty result",
			"1": "API or network error",
			"2": "usage or local validation error",
		},
	}
}

func describeLimits() limitsInfo {
	return limitsInfo{
		AlertWindow: "7d",
		GroupWindow: "24h",
		MaxRange:    "90d",
		MaxPage:     query.AgentMaxPageSize,
		MaxItems:    query.AgentDefaultMaxItems,
	}
}

func writeDescribe(w io.Writer, value describeOutput) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

// copyGlobal gives each command a private copy while preserving flags that were
// already set before the command name.
func copyGlobal(g *globalOptions) *globalOptions {
	copied := *g
	return &copied
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration such as 30s", key)
	}
	return d, nil
}
