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

	"github.com/google/uuid"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
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
}

// New builds an MCP server with the read-only tool set.
func New(st store.Store, registry *connector.Registry, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{store: st, registry: registry, log: log, tools: map[string]Tool{}}
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
func (s *Server) Handle(ctx context.Context, req *Request) *Response {
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
			"get_alert for full OCSF payload and raw vendor evidence, and get_connector_health to check ingestion freshness. " +
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
	tool, ok := s.tools[params.Name]
	if !ok {
		return s.errResponse(req.ID, codeInvalidParams, "unknown tool: "+params.Name)
	}
	if params.Arguments == nil {
		params.Arguments = map[string]any{}
	}
	result, err := tool.Handler(ctx, params.Arguments)
	if err != nil {
		s.log.Debug("mcp tool failed", "tool", params.Name, "error", err)
		return s.result(req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
			"isError": true,
		})
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

// Tool is one MCP tool definition and handler.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Handler     func(ctx context.Context, args map[string]any) (any, error)
}

func (s *Server) register(t Tool) {
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
