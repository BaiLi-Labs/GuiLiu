// Package intake owns the push path: authenticated receive, transport decoding
// and durable hand-off to the same normalization and storage pipeline the
// polling engine uses. It contains no vendor-specific field mapping.
package intake

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/credential"
	"github.com/BaiLi-Labs/GuiLiu/internal/ingest"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/pushwire"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

// Options bounds one inbound payload and the syslog worker pool.
type Options struct {
	MaxBodyBytes  int64
	SyslogListen  string
	SyslogNet     string
	SyslogWorkers int
	QueueSize     int
}

func (o *Options) applyDefaults() {
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = 8 << 20
	}
	if o.SyslogWorkers <= 0 {
		o.SyslogWorkers = 4
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 1024
	}
	if strings.TrimSpace(o.SyslogNet) == "" {
		o.SyslogNet = "both"
	}
}

// Server receives pushed records for configured accounts.
type Server struct {
	store    store.Store
	engine   *ingest.Engine
	registry *connector.Registry
	cipher   *secret.Cipher
	log      *slog.Logger
	opts     Options
	now      func() time.Time
}

func New(st store.Store, engine *ingest.Engine, registry *connector.Registry, cipher *secret.Cipher, opts Options, log *slog.Logger) *Server {
	opts.applyDefaults()
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		store:    st,
		engine:   engine,
		registry: registry,
		cipher:   cipher,
		log:      log,
		opts:     opts,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// HashToken is the only representation of a push token that may be persisted.
// The plaintext lives in configuration, never in the database.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func tokenFromRequest(r *http.Request) string {
	if h := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return strings.TrimSpace(r.Header.Get("X-Guiliu-Push-Token"))
}

// Webhook handles POST /ingest/{account}. A 2xx response means the payload has
// already been normalized and committed (or retained for mapping retry); it is
// never sent before durability, because appliances retry on failure.
func (s *Server) Webhook(w http.ResponseWriter, r *http.Request) {
	started := s.now()
	name := strings.TrimSpace(r.PathValue("account"))
	acct, pusher, ok := s.authorize(w, r, name, tokenFromRequest(r))
	if !ok {
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, s.opts.MaxBodyBytes+1))
	if err != nil {
		writePushError(w, http.StatusBadRequest, "invalid_body", "cannot read request body")
		return
	}
	if int64(len(body)) > s.opts.MaxBodyBytes {
		writePushError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "payload exceeds the configured limit")
		return
	}

	raws, err := pusher.DecodePush(connector.PushRequest{
		Format:     connector.PushWebhook,
		Body:       body,
		Header:     r.Header,
		RemoteAddr: r.RemoteAddr,
		ReceivedAt: started,
	})
	if err != nil {
		s.log.Warn("push decode failed", "account", acct.Name, "provider", acct.Provider, "error", err)
		writePushError(w, http.StatusBadRequest, "decode_failed", "payload could not be decoded: "+err.Error())
		return
	}

	result, err := s.engine.IngestPushed(r.Context(), *acct, pusher, raws, started)
	if err != nil {
		s.log.Error("push ingest failed", "account", acct.Name, "provider", acct.Provider, "error", err)
		writePushError(w, http.StatusInternalServerError, "ingest_failed", "records were not persisted")
		return
	}
	s.log.Info("push accepted", "account", acct.Name, "provider", acct.Provider, "records", len(raws),
		"created", result.Created, "updated", result.Updated, "failed", result.Failed)
	writeJSON(w, http.StatusOK, map[string]any{
		"accepted": len(raws),
		"created":  result.Created,
		"updated":  result.Updated,
		"failed":   result.Failed,
	})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, name, token string) (*model.Account, connector.Pusher, bool) {
	if name == "" || token == "" {
		writePushError(w, http.StatusUnauthorized, "unauthorized", "a push token is required")
		return nil, nil, false
	}
	acct, err := s.store.GetAccountByName(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		writePushError(w, http.StatusUnauthorized, "unauthorized", "invalid account or push token")
		return nil, nil, false
	}
	if err != nil {
		writePushError(w, http.StatusInternalServerError, "storage_error", "cannot load the account")
		return nil, nil, false
	}
	expected := strings.TrimSpace(acct.Options["push_token_sha256"])
	if expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(HashToken(token))) != 1 {
		writePushError(w, http.StatusUnauthorized, "unauthorized", "invalid account or push token")
		return nil, nil, false
	}
	if !acct.Enabled {
		writePushError(w, http.StatusForbidden, "account_disabled", "the account is disabled")
		return nil, nil, false
	}
	pusher, err := s.pusherFor(r.Context(), acct)
	if err != nil {
		s.log.Error("build push connector", "account", acct.Name, "provider", acct.Provider, "error", err)
		writePushError(w, http.StatusUnprocessableEntity, "connector_unavailable", "the connector cannot be constructed")
		return nil, nil, false
	}
	return acct, pusher, true
}

// pusherFor builds a connector without requiring a credential: a push-only
// account has nothing to authenticate against the product.
func (s *Server) pusherFor(ctx context.Context, acct *model.Account) (connector.Pusher, error) {
	cred := connector.Credential{}
	if acct.CredentialSet {
		loaded, err := credential.Load(ctx, s.store, s.cipher, acct.ID)
		if err != nil {
			return nil, err
		}
		cred = loaded
	}
	c, err := s.registry.New(connector.AccountConfig{
		Provider:   acct.Provider,
		AccountID:  acct.ID,
		Name:       acct.Name,
		AccountUID: acct.AccountUID,
		Region:     acct.Region,
		Options:    acct.Options,
		Credential: cred,
	})
	if err != nil {
		return nil, err
	}
	pusher, ok := connector.AsPusher(c)
	if !ok {
		return nil, fmt.Errorf("provider %s does not accept pushed records", acct.Provider)
	}
	return pusher, nil
}

// SyslogConfig describes the syslog listeners.
type SyslogConfig struct {
	Listen string
	Net    string
}

// RunSyslog serves syslog until the context is canceled. TCP and UDP share the
// same address when Net is "both"; devices commonly emit over UDP.
func (s *Server) RunSyslog(ctx context.Context, cfg SyslogConfig) error {
	addr := strings.TrimSpace(cfg.Listen)
	if addr == "" {
		addr = strings.TrimSpace(s.opts.SyslogListen)
	}
	if addr == "" {
		return nil
	}
	netMode := strings.ToLower(strings.TrimSpace(cfg.Net))
	if netMode == "" {
		netMode = s.opts.SyslogNet
	}
	queue := make(chan syslogJob, s.opts.QueueSize)
	var closers []io.Closer
	workersDone := make(chan struct{})
	for i := 0; i < s.opts.SyslogWorkers; i++ {
		go s.syslogWorker(ctx, queue, workersDone)
	}
	start := func(network string) (net.Listener, error) {
		ln, err := net.Listen(network, addr)
		if err != nil {
			return nil, err
		}
		closers = append(closers, ln)
		go s.serveSyslog(ctx, ln, queue)
		return ln, nil
	}
	if netMode == "tcp" || netMode == "both" {
		if _, err := start("tcp"); err != nil {
			s.log.Error("syslog tcp listen failed", "addr", addr, "error", err)
			if netMode == "tcp" {
				return err
			}
		}
	}
	if netMode == "udp" || netMode == "both" {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			s.log.Error("syslog udp listen failed", "addr", addr, "error", err)
		} else {
			closers = append(closers, pc)
			go s.serveSyslogUDP(ctx, pc, queue)
		}
	}
	if len(closers) == 0 {
		return fmt.Errorf("no syslog listener could be started on %s", addr)
	}
	s.log.Info("syslog intake listening", "addr", addr, "net", netMode)
	<-ctx.Done()
	for _, c := range closers {
		_ = c.Close()
	}
	close(queue)
	for i := 0; i < s.opts.SyslogWorkers; i++ {
		<-workersDone
	}
	return nil
}

type syslogJob struct {
	raw        []byte
	remote     string
	receivedAt time.Time
}

func (s *Server) serveSyslog(ctx context.Context, ln net.Listener, queue chan<- syslogJob) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Warn("syslog accept failed", "error", err)
			continue
		}
		go s.readSyslogConn(conn, queue)
	}
}

func (s *Server) readSyslogConn(conn net.Conn, queue chan<- syslogJob) {
	defer conn.Close()
	reader := bufio.NewReaderSize(conn, 64<<10)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			s.enqueue(queue, line, conn.RemoteAddr().String())
		}
		if err != nil {
			return
		}
	}
}

func (s *Server) serveSyslogUDP(ctx context.Context, pc net.PacketConn, queue chan<- syslogJob) {
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		payload := append([]byte(nil), buf[:n]...)
		remote := ""
		if addr != nil {
			remote = addr.String()
		}
		s.enqueue(queue, payload, remote)
	}
}

func (s *Server) enqueue(queue chan<- syslogJob, raw []byte, remote string) {
	job := syslogJob{raw: raw, remote: remote, receivedAt: s.now()}
	select {
	case queue <- job:
	default:
		s.log.Warn("syslog queue full; dropping frame", "remote", remote)
	}
}

func (s *Server) syslogWorker(ctx context.Context, queue <-chan syslogJob, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	for job := range queue {
		if err := s.handleSyslog(ctx, job); err != nil {
			s.log.Warn("syslog frame rejected", "remote", job.remote, "error", err)
		}
	}
}

func (s *Server) handleSyslog(ctx context.Context, job syslogJob) error {
	env, err := pushwire.DecodeSyslog(job.raw)
	if err != nil {
		return err
	}
	acct, err := s.matchSyslogAccount(ctx, job.remote)
	if err != nil {
		return err
	}
	pusher, err := s.pusherFor(ctx, acct)
	if err != nil {
		return err
	}
	body, err := env.Marshal()
	if err != nil {
		return err
	}
	raws, err := pusher.DecodePush(connector.PushRequest{
		Format:     connector.PushSyslog,
		Body:       body,
		RemoteAddr: job.remote,
		ReceivedAt: job.receivedAt,
	})
	if err != nil {
		return err
	}
	result, err := s.engine.IngestPushed(ctx, *acct, pusher, raws, job.receivedAt)
	if err != nil {
		return err
	}
	s.log.Info("syslog accepted", "account", acct.Name, "provider", acct.Provider, "records", len(raws),
		"created", result.Created, "updated", result.Updated, "failed", result.Failed)
	return nil
}

// matchSyslogAccount maps a peer address to exactly one enabled push account.
// Accounts declare options.syslog_cidrs (comma separated IP or CIDR). When no
// account declares any range and exactly one push account exists, that account
// is the unambiguous destination.
func (s *Server) matchSyslogAccount(ctx context.Context, remote string) (*model.Account, error) {
	ip := remoteIP(remote)
	if ip == nil {
		return nil, fmt.Errorf("syslog frame has no usable peer address")
	}
	accounts, err := s.store.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	var candidates []*model.Account
	anyRange := false
	for i := range accounts {
		acct := &accounts[i]
		if !acct.Enabled {
			continue
		}
		desc, ok := s.registry.Descriptor(acct.Provider)
		if !ok || !supportsSyslog(desc) {
			continue
		}
		ranges := strings.TrimSpace(acct.Options["syslog_cidrs"])
		if ranges == "" {
			candidates = append(candidates, acct)
			continue
		}
		anyRange = true
		for _, entry := range strings.Split(ranges, ",") {
			if cidrContains(strings.TrimSpace(entry), ip) {
				return acct, nil
			}
		}
	}
	if !anyRange && len(candidates) == 1 {
		return candidates[0], nil
	}
	return nil, fmt.Errorf("no push account matches peer %s", ip)
}

func cidrContains(entry string, ip net.IP) bool {
	if entry == "" {
		return false
	}
	if !strings.Contains(entry, "/") {
		if parsed := net.ParseIP(entry); parsed != nil {
			return parsed.Equal(ip)
		}
		return false
	}
	_, network, err := net.ParseCIDR(entry)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

func remoteIP(remote string) net.IP {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	return net.ParseIP(strings.Trim(host, "[]"))
}

func supportsSyslog(desc connector.Descriptor) bool {
	for _, format := range desc.PushFormats {
		if format == connector.PushSyslog {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writePushError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
