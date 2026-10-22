// Package mcp exposes the read-only GuiLiu data API to AI agents using the
// Model Context Protocol. It is a thin adapter over the same store and filters
// used by the REST API: agents never receive cloud credentials or SQL access.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/BaiLi-Labs/GuiLiu/internal/audit"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/BaiLi-Labs/GuiLiu/internal/version"
)

const (
	latestProtocol = "2025-06-18"
)

var supportedProtocols = map[string]bool{
	"2025-06-18": true,
	"2025-03-26": true,
	"2024-11-05": true,
}

// Server implements the MCP JSON-RPC surface over stdio and Streamable HTTP.
type Server struct {
	store    store.Store
	registry *connector.Registry
	log      *slog.Logger
	tools    map[string]Tool
	order    []string
	maxAge   time.Duration
}

// New builds an MCP server with the read-only tool set.
func New(st store.Store, registry *connector.Registry, log *slog.Logger, maxAge ...time.Duration) *Server {
	if log == nil {
		log = slog.Default()
	}
	age := 15 * time.Minute
	if len(maxAge) > 0 && maxAge[0] > 0 {
		age = maxAge[0]
	}
	s := &Server{store: st, registry: registry, log: log, tools: map[string]Tool{}, maxAge: age}
	s.registerTools()
	return s
}

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return e.Message }

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// Handle processes one JSON-RPC message. A nil response means the message was a
// notification and must not be answered.
func (s *Server) Handle(ctx context.Context, req *Request) (response *Response) {
	surface := "mcp_stdio"
	if audit.FromContext(ctx) != nil {
		surface = "mcp_http"
	}
	operation := req.Method
	switch operation {
	case "initialize", "notifications/initialized", "notifications/cancelled", "ping", "tools/list", "tools/call":
	default:
		operation = "unknown_method"
	}
	ctx, span, err := audit.Begin(ctx, s.store, s.log, model.AuditEvent{Surface: surface, Operation: operation})
	if err != nil {
		return s.errResponse(req.ID, codeInternalError, "access audit unavailable; operation was not started")
	}
	defer func() {
		outcome, code := "success", ""
		if recover() != nil {
			response = s.errResponse(req.ID, codeInternalError, "internal tool error")
			code = "panic"
		}
		if response != nil && response.Error != nil {
			outcome = "error"
			span.Event.Summary["rpc_error_code"] = response.Error.Code
			if code == "" {
				code = "rpc_error"
			}
		}
		if response != nil {
			if result, ok := response.Result.(map[string]any); ok && result["isError"] == true {
				outcome = "error"
				code = "tool_error"
			}
		}
		if ctx.Err() != nil && outcome == "success" {
			outcome = "cancelled"
			code = "request_cancelled"
		}
		span.Finish(ctx, outcome, code)
	}()
	return s.handle(ctx, req)
}

func (s *Server) handle(ctx context.Context, req *Request) *Response {
	if req.JSONRPC != "" && req.JSONRPC != "2.0" {
		return s.errResponse(req.ID, codeInvalidRequest, "unsupported jsonrpc version")
	}
	if req.Method == "" {
		return s.errResponse(req.ID, codeInvalidRequest, "method is required")
	}

	switch req.Method {
	case "initialize":
		return s.result(req.ID, s.initialize(req.Params))
	case "notifications/initialized", "notifications/cancelled":
		return nil
	case "ping":
		return s.result(req.ID, map[string]any{})
	case "tools/list":
		return s.result(req.ID, map[string]any{"tools": s.listTools()})
	case "tools/call":
		return s.callTool(ctx, req)
	default:
		if strings.HasPrefix(req.Method, "notifications/") {
			return nil
		}
		return s.errResponse(req.ID, codeMethodNotFound, "method not found: "+req.Method)
	}
}

func (s *Server) initialize(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	protocol := latestProtocol
	if supportedProtocols[p.ProtocolVersion] {
		protocol = p.ProtocolVersion
	}
	return map[string]any{
		"protocolVersion": protocol,
		"capabilities": map[string]any{
			"tools": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    "guiliu",
			"version": version.Version,
		},
		"instructions": "GuiLiu provides read-only access to saved security facts and source evidence. Queries do not refresh cloud APIs. Coverage describes collection state, not data usability or security conclusions. Asset observations describe saved configuration, not event-time state. Use tool descriptions for query defaults and continuation contracts.",
	}
}

func (s *Server) callTool(ctx context.Context, req *Request) *Response {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.UseNumber()
	if err := dec.Decode(&params); err != nil {
		return s.errResponse(req.ID, codeInvalidParams, "invalid tools/call params: "+err.Error())
	}
	if span := audit.FromContext(ctx); span != nil {
		span.Event.Tool = audit.Text(params.Name)
		span.Event.Parameters = audit.Parameters(params.Arguments)
	}
	tool, ok := s.tools[params.Name]
	if !ok {
		return s.errResponse(req.ID, codeInvalidParams, "unknown tool: "+params.Name)
	}
	if params.Arguments == nil {
		params.Arguments = map[string]any{}
	}
	if span := audit.FromContext(ctx); span != nil {
		span.Event.Tool = tool.Name
		span.Event.Parameters = audit.Parameters(params.Arguments)
	}
	err := validateToolArgs(tool.InputSchema, params.Arguments)
	var result any
	if err == nil {
		result, err = tool.Handler(ctx, params.Arguments)
	}
	if err != nil {
		s.log.Debug("mcp tool failed", "tool", tool.Name)
		return s.result(req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
			"isError": true,
		})
	}
	if span := audit.FromContext(ctx); span != nil {
		span.Event.Summary = audit.Summary(result)
	}
	text, err := marshalResult(result)
	if err != nil {
		return s.errResponse(req.ID, codeInternalError, "encode result: "+err.Error())
	}
	return s.result(req.ID, map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": false,
	})
}

func (s *Server) result(id json.RawMessage, result any) *Response {
	return &Response{JSONRPC: "2.0", ID: id, Result: result}
}

func (s *Server) errResponse(id json.RawMessage, code int, msg string) *Response {
	return &Response{JSONRPC: "2.0", ID: id, Error: &RPCError{Code: code, Message: msg}}
}

func marshalResult(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

// ServeStdio runs the newline-delimited JSON-RPC transport.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.auditParseError(ctx, "mcp_stdio")
			_ = enc.Encode(s.errResponse(nil, codeParseError, "parse error: "+err.Error()))
			continue
		}
		resp := s.Handle(ctx, &req)
		if resp == nil {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// ServeHTTP implements the Streamable HTTP transport with JSON responses.
// Server-sent events are intentionally not used: every tool is short-lived.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		body := http.MaxBytesReader(w, r.Body, 4<<20)
		var req Request
		dec := json.NewDecoder(body)
		if err := dec.Decode(&req); err != nil {
			s.auditParseError(r.Context(), "mcp_http")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(s.errResponse(nil, codeParseError, "parse error: "+err.Error()))
			return
		}
		resp := s.Handle(r.Context(), &req)
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", uuid.NewString())
		}
		if resp == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	case http.MethodGet:
		w.Header().Set("Allow", "POST, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	case http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) auditParseError(ctx context.Context, surface string) {
	ctx, span, err := audit.Begin(ctx, s.store, s.log, model.AuditEvent{Surface: surface, Operation: "parse_error"})
	if err == nil {
		span.Finish(ctx, "error", "parse_error")
	}
}

// Tool is one MCP tool definition and handler.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Handler     func(ctx context.Context, args map[string]any) (any, error)
}

func (s *Server) register(t Tool) {
	if props, ok := t.InputSchema["properties"].(map[string]any); ok {
		if t.Name == "get_alert_statistics" {
			props["top_by"] = strProp("Comma-separated exact-value dimensions: " + model.StatsDimensions + "; defaults to title,source_ip,source_country")
			props["top_n"] = intProp("Maximum values per distribution", model.StatsDefaultTopN, 1, model.StatsMaxTopN)
		}
		switch t.Name {
		case "list_alerts", "list_alert_groups", "get_alert_group", "search_alerts_by_ip", "search_alerts_by_asset", "get_alert_statistics", "get_data_coverage":
			for key, value := range findingFilterProps() {
				if t.Name == "search_alerts_by_asset" && key == "resource" {
					continue
				}
				props[key] = value
			}
			switch t.Name {
			case "list_alerts", "get_alert_group", "search_alerts_by_ip", "search_alerts_by_asset":
				props["after_id"] = strProp("Omit for the first page with sort=id; then copy next_cursor. Reuse snapshot_sequence, absolute start/end, filters and sort=id. Forces ID sort when supplied.")
				props["sort"] = strProp("Defaults to event_time; accepts event_time, severity, last_seen, first_seen or id. Use id from page one for cursor traversal; invalid values fail.")
				props["offset"] = intProp("Offset for the same snapshot and filters; use after_id for deep ID traversal", 0, 0, int(^uint(0)>>1))
			}
			if t.Name == "list_alert_groups" || t.Name == "get_alert_group" {
				props["asset_snapshot_sequence"] = map[string]any{"type": "integer", "minimum": 0, "description": "Omit on a new group list to pin saved assets; required when expanding asset/network groups. Copy asset_snapshot_sequence with snapshot_sequence and absolute start/end; invalid values fail."}
				props["group_by"] = groupByProp()
				if t.Name == "list_alert_groups" {
					props["group_by"].(map[string]any)["default"] = "asset"
				}
			}
			window := "7d"
			if t.Name == "list_alert_groups" || t.Name == "get_alert_group" {
				window = "24h"
			}
			for key, value := range windowProps(window) {
				props[key] = value
			}
		case "get_alert", "get_alert_evidence", "get_alert_asset_context":
			props["snapshot_sequence"] = map[string]any{"type": "integer", "minimum": 0, "description": findingSnapshotNote}
			props["revision"] = map[string]any{"type": "integer", "minimum": 1, "description": findingRevisionNote}
		}

	}

	s.tools[t.Name] = t
	s.order = append(s.order, t.Name)
}

func (s *Server) listTools() []map[string]any {
	out := make([]map[string]any, 0, len(s.order))
	for _, name := range s.order {
		t := s.tools[name]
		out = append(out, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		})
	}
	return out
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func strProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func intProp(desc string, def, min, max int) map[string]any {
	return map[string]any{
		"type":        "integer",
		"description": fmt.Sprintf("%s. Defaults to %d; range %d..%d inclusive; invalid values fail.", desc, def, min, max),
		"default":     def,
		"minimum":     min,
		"maximum":     max,
	}
}

func groupByProp() map[string]any {
	return map[string]any{
		"type":        "string",
		"description": "Exact-field grouping: asset, name_asset (exact source title and asset), vpc, subnet, security_group, nic, type_asset, signature or source. Network groups describe the primary host’s explicitly observed resource references, not traffic paths or effective policies. Reuse both snapshot_sequence and asset_snapshot_sequence and the absolute window. Group memberships overlap; never sum them as unique Findings.",
		"enum":        []string{"asset", "name_asset", "vpc", "subnet", "security_group", "nic", "type_asset", "signature", "source"},
	}
}

func groupKeyProp() map[string]any {
	return map[string]any{
		"type":                 "object",
		"description":          "Required object copied verbatim from groups[].key in list_alert_groups; not a string or an inferred identity",
		"additionalProperties": map[string]any{"type": "string"},
	}
}

func severityProp() map[string]any {
	return map[string]any{
		"type":        "string",
		"description": "Optional comma-separated source-mapped display severities; omit for all. Accepts unknown, informational, low, medium, high, critical, fatal. Unknown names fail; no platform risk judgment",
	}
}

func statusProp() map[string]any {
	return map[string]any{
		"type":        "string",
		"description": "Optional comma-separated local annotations: open, acknowledged, suppressed, closed; omit for all. Unknown names fail. These are independent of vendor_status",
	}
}

func timeProps() map[string]any {
	return map[string]any{
		"start": strProp("Start time (RFC3339 or YYYY-MM-DD)"),
		"end":   strProp("End time (RFC3339 or YYYY-MM-DD)"),
		"since": strProp("Relative window instead of start, e.g. 24h or 7d"),
	}
}

func mergeProps(base map[string]any, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

const findingSnapshotNote = "Omit for the latest saved projection; copy snapshot_sequence to read a pinned Finding snapshot. Nonnegative integer; mutually exclusive with revision; invalid values fail."
const findingRevisionNote = "Omit for the latest saved projection; supply a positive exact Finding revision from changes/revisions. Mutually exclusive with snapshot_sequence; invalid values fail."
const nativeResourceNote = "Optional native resource ID (exact) or source resource name (literal substring); not GuiLiu asset_id. Scope with provider/account_id. IP/name search hits do not establish identity."
const keywordNote = "Optional literal substring across source title, description, alert type and resource name; no query language or boolean operators. Omit for all."

func findingFilterProps() map[string]any {
	return map[string]any{
		"provider":   strProp("Optional provider ID; omit for all configured providers"),
		"account_id": strProp("Optional GuiLiu source connection ID; not the native cloud account_uid; omit for all connections"),
		"severity":   severityProp(), "status": statusProp(), "keyword": strProp(keywordNote),
		"resource":          strProp(nativeResourceNote),
		"ip":                strProp("Optional exact IPv4/IPv6 match in source, destination or typed observables. Invalid IP fails; a match is not an asset identity link."),
		"time_field":        map[string]any{"type": "string", "default": "event_time", "enum": []string{"event_time", "source_updated_at", "ingested_at"}, "description": "Timestamp filtered by start/end; defaults to event_time. Missing times do not match a bounded query; invalid values fail."},
		"vendor_title":      strProp("Optional exact source title; whitespace and case are preserved. Not a rule ID."),
		"rule_id":           strProp("Optional exact native rule ID; use provider/product scope when comparing records"),
		"finding_kind":      map[string]any{"type": "string", "enum": []string{"detection", "vulnerability", "compliance", "incident", "other"}, "description": "Optional source-derived Finding kind; omit for all; invalid values fail."},
		"vendor_status":     strProp("Optional exact source status; independent of local annotation status"),
		"observable_type":   map[string]any{"type": "integer", "minimum": 0, "maximum": 999, "description": "Optional OCSF observable type ID, 0..999; use with observable_value; invalid values fail."},
		"observable_value":  strProp("Optional exact typed observable value; use observable_type to constrain type. Search hits do not merge object identities."),
		"snapshot_sequence": map[string]any{"type": "integer", "minimum": 0, "description": "Omit to pin the latest saved Finding projection; reuse the returned snapshot_sequence, absolute start/end, filters and sort for subsequent queries. Invalid snapshots fail."},
	}
}
func windowProps(window string) map[string]any {
	return map[string]any{
		"start": strProp("Optional inclusive RFC3339 or YYYY-MM-DD (UTC) start; mutually exclusive with since. Without either, defaults to end minus " + window + ". Invalid/reversed windows or ranges over 90d fail."),
		"end":   strProp("Optional inclusive RFC3339 or YYYY-MM-DD (UTC) end; defaults to current UTC time. Reuse returned window.start/end for continuation."),
		"since": strProp("Optional lookback relative to current UTC time, e.g. 24h or 7d; mutually exclusive with start. Maximum resolved range 90d; invalid ranges fail. Use absolute start/end for repeatable queries."),
	}
}
