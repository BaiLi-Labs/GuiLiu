// Package mcp exposes the read-only GuiLiu data API to AI agents using the
// Model Context Protocol. It is a thin adapter over the same store and filters
// used by the REST API: agents never receive cloud credentials or SQL access.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
		"instructions": "GuiLiu is a read-only, vendor-neutral security data hub. " +
			"Use list_alerts/search_alerts_by_ip/search_alerts_by_asset to query normalized cloud alerts, " +
			"list_alert_groups/get_alert_group to browse exact-field groups while preserving original alerts, " +
			"get_alert for full OCSF payload and raw vendor evidence, get_alert_asset_context for current local CVM metadata, get_asset_by_reference to follow scoped references to local security groups, VPCs and subnets, list_asset_findings for exact host matches, get_asset_component for asset evidence, and get_connector_health to check ingestion freshness. " +
			"All tools are read-only and scoped to the configured accounts.",
	}
}

func (s *Server) callTool(ctx context.Context, req *Request) *Response {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
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
	result, err := tool.Handler(ctx, params.Arguments)
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
		if t.Name == "get_alert_statistics" || t.Name == "get_data_coverage" {
			for _, key := range []string{"keyword", "ip", "resource", "severity", "status"} {
				props[key] = strProp("Same filter as list_alerts")
			}
		}
		switch t.Name {
		case "list_alerts", "list_alert_groups", "get_alert_group", "search_alerts_by_ip", "search_alerts_by_asset", "get_alert_statistics", "get_data_coverage":
			for key, value := range map[string]any{"time_field": strProp("Timestamp used by start/end: event_time (default), source_updated_at or ingested_at"),
				"vendor_title": strProp("Exact source-reported finding title; a statistical field, not a rule ID"), "asset_snapshot_sequence": map[string]any{"type": "integer", "minimum": 0, "description": "Reuse the returned asset watermark for stable network group membership"}, "rule_id": strProp("Exact native rule ID, scoped by provider and product"), "finding_kind": strProp("detection, vulnerability, compliance, incident or other"), "vendor_status": strProp("Exact source status; independent of local annotation status"), "observable_type": map[string]any{"type": "integer", "minimum": 0, "description": "OCSF observable type ID"}, "observable_value": strProp("Exact typed observable value: IP, domain, hash, account, user or resource"), "snapshot_sequence": map[string]any{"type": "integer", "minimum": 0, "description": "Reuse the returned snapshot sequence for stable paging and group expansion"}, "after_id": strProp("Continue an ID-sorted snapshot using next_cursor")} {
				props[key] = value
			}
			props["offset"] = map[string]any{"type": "integer", "minimum": 0, "description": "Page offset; prefer ID cursor for deep traversal"}
		case "get_alert", "get_alert_evidence":
			props["snapshot_sequence"] = map[string]any{"type": "integer", "minimum": 0, "description": "Read the detail from a pinned snapshot"}
			props["revision"] = map[string]any{"type": "integer", "minimum": 1, "description": "Exact revision from a change feed entry"}
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
		"description": desc,
		"default":     def,
		"minimum":     min,
		"maximum":     max,
	}
}

func groupByProp() map[string]any {
	return map[string]any{
		"type":        "string",
		"description": "Exact-field grouping: asset (default), name_asset (exact source title and asset), vpc, subnet, security_group, nic, type_asset, signature or source. Network groups describe the primary host’s explicitly observed resource references, not traffic paths or effective policies. Reuse both snapshot_sequence and asset_snapshot_sequence and the absolute window. Group memberships overlap; never sum them as unique Findings.",
		"enum":        []string{"asset", "name_asset", "vpc", "subnet", "security_group", "nic", "type_asset", "signature", "source"},
	}
}

func groupKeyProp() map[string]any {
	return map[string]any{
		"type":                 "object",
		"description":          "Group key returned by list_alert_groups",
		"additionalProperties": map[string]any{"type": "string"},
	}
}

func severityProp() map[string]any {
	return map[string]any{
		"type":        "string",
		"description": "Comma-separated severities: informational, low, medium, high, critical",
	}
}

func statusProp() map[string]any {
	return map[string]any{
		"type":        "string",
		"description": "Comma-separated platform statuses: open, acknowledged, suppressed, closed",
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
