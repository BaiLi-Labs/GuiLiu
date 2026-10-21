package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
)

type providersResponse struct {
	Providers []connector.Descriptor `json:"providers"`
}

func newProvidersCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("providers", io.Discard)
	registerGlobalFlags(fs, g)
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		body, err := c.get(ctx, "/providers", url.Values{})
		if err != nil {
			return err
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		page, err := decode[providersResponse](body)
		if err != nil {
			return err
		}
		if out.NDJSON {
			return emitNDJSON(stdout, page.Providers)
		}
		columns, err := selectColumns(providerColumns(), []string{"id", "name", "vendor", "product", "mapper_version", "api_version"}, out.Fields)
		if err != nil {
			return err
		}
		if len(page.Providers) == 0 {
			if !out.Quiet {
				fmt.Fprintln(stderr, "0 provider(s)")
			}
			return nil
		}
		if err := renderTable(stdout, columns, page.Providers); err != nil {
			return err
		}
		if !out.Quiet {
			fmt.Fprintf(stderr, "%d provider(s)\n", len(page.Providers))
		}
		return nil
	}
}

func providerColumns() []column[connector.Descriptor] {
	return []column[connector.Descriptor]{
		{key: "id", header: "ID", value: func(d connector.Descriptor) string { return d.ID }},
		{key: "name", header: "NAME", max: 28, value: func(d connector.Descriptor) string { return d.Name }},
		{key: "vendor", header: "VENDOR", max: 24, value: func(d connector.Descriptor) string { return d.Vendor }},
		{key: "product", header: "PRODUCT", max: 28, value: func(d connector.Descriptor) string { return d.Product }},
		{key: "mapper_version", header: "MAPPER", value: func(d connector.Descriptor) string { return d.MapperVersion }},
		{key: "api_version", header: "API_VERSION", value: func(d connector.Descriptor) string { return d.APIVersion }},
		{key: "source_api", header: "SOURCE_API", max: 40, value: func(d connector.Descriptor) string { return d.SourceAPI }},
		{key: "product_uid", header: "PRODUCT_UID", value: func(d connector.Descriptor) string { return d.ProductUID }},
		{key: "docs_url", header: "DOCS", max: 48, value: func(d connector.Descriptor) string { return d.DocsURL }},
	}
}

type mappingResponse struct {
	Provider      string                  `json:"provider"`
	MapperVersion string                  `json:"mapper_version"`
	Fields        []connector.MappingSpec `json:"fields"`
}

func newMappingCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("mapping", io.Discard)
	registerGlobalFlags(fs, g)
	var provider string
	fs.String(&provider, "provider", "", "Provider ID (required)")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		if strings.TrimSpace(provider) == "" {
			return usagef("--provider is required")
		}
		body, err := c.get(ctx, "/providers/"+url.PathEscape(provider)+"/mapping", url.Values{})
		if err != nil {
			return err
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		page, err := decode[mappingResponse](body)
		if err != nil {
			return err
		}
		if out.NDJSON {
			return emitNDJSON(stdout, page.Fields)
		}
		columns, err := selectColumns(mappingColumns(), []string{"field", "source_paths", "transform"}, out.Fields)
		if err != nil {
			return err
		}
		if len(page.Fields) > 0 {
			if err := renderTable(stdout, columns, page.Fields); err != nil {
				return err
			}
		}
		if !out.Quiet {
			fmt.Fprintf(stderr, "%d field(s), provider %s, mapper %s\n", len(page.Fields), page.Provider, page.MapperVersion)
		}
		return nil
	}
}

func mappingColumns() []column[connector.MappingSpec] {
	return []column[connector.MappingSpec]{
		{key: "field", header: "FIELD", value: func(m connector.MappingSpec) string { return m.Field }},
		{key: "source_paths", header: "SOURCE_PATHS", max: 72, value: func(m connector.MappingSpec) string { return strings.Join(m.Paths, ", ") }},
		{key: "transform", header: "TRANSFORM", max: 40, value: func(m connector.MappingSpec) string { return m.Transform }},
	}
}

type failureRecord struct {
	ID            string          `json:"id"`
	AccountID     string          `json:"account_id"`
	Raw           json.RawMessage `json:"raw"`
	Error         string          `json:"error"`
	Attempts      int             `json:"attempts"`
	MapperVersion string          `json:"mapper_version"`
	CreatedAt     string          `json:"created_at"`
	LastAttemptAt string          `json:"last_attempt_at"`
}

type failuresResponse struct {
	Failures []failureRecord `json:"failures"`
	Total    int             `json:"total"`
	Limit    int             `json:"limit"`
}

func newFailuresCommand(g *globalOptions) (*flagSet, runFunc) {
	fs := newFlagSet("failures", io.Discard)
	registerGlobalFlags(fs, g)
	var account string
	fs.String(&account, "account", "", "Configured account ID (required)")
	return fs, func(ctx context.Context, c *client, out *outputOptions, stdout, stderr io.Writer) error {
		if err := noArgs(fs); err != nil {
			return err
		}
		if strings.TrimSpace(account) == "" {
			return usagef("--account is required")
		}
		body, err := c.get(ctx, "/accounts/"+url.PathEscape(account)+"/failures", url.Values{})
		if err != nil {
			return err
		}
		if out.JSON {
			return emitJSON(stdout, body, out.Pretty)
		}
		page, err := decode[failuresResponse](body)
		if err != nil {
			return err
		}
		if out.NDJSON {
			if err := emitNDJSON(stdout, page.Failures); err != nil {
				return err
			}
		} else {
			columns, err := selectColumns(failureColumns(), []string{"id", "attempts", "mapper_version", "created_at", "last_attempt_at", "error"}, out.Fields)
			if err != nil {
				return err
			}
			if len(page.Failures) > 0 {
				if err := renderTable(stdout, columns, page.Failures); err != nil {
					return err
				}
			}
		}
		if out.Quiet {
			return nil
		}
		fmt.Fprintf(stderr, "%d failure(s)", len(page.Failures))
		if page.Total > 0 {
			fmt.Fprintf(stderr, " of %d", page.Total)
		}
		if page.Limit > 0 {
			fmt.Fprintf(stderr, ", limit %d", page.Limit)
		}
		fmt.Fprintln(stderr)
		return nil
	}
}

func failureColumns() []column[failureRecord] {
	return []column[failureRecord]{
		{key: "id", header: "ID", value: func(f failureRecord) string { return f.ID }},
		{key: "account_id", header: "ACCOUNT", value: func(f failureRecord) string { return f.AccountID }},
		{key: "attempts", header: "ATTEMPTS", value: func(f failureRecord) string { return strconv.Itoa(f.Attempts) }},
		{key: "mapper_version", header: "MAPPER", value: func(f failureRecord) string { return f.MapperVersion }},
		{key: "created_at", header: "CREATED", value: func(f failureRecord) string { return shortTime(f.CreatedAt) }},
		{key: "last_attempt_at", header: "LAST_ATTEMPT", value: func(f failureRecord) string { return shortTime(f.LastAttemptAt) }},
		{key: "error", header: "ERROR", max: 72, value: func(f failureRecord) string { return f.Error }},
	}
}
