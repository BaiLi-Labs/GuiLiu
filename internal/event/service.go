// Package event provides the shared, bounded remote event access contract used
// by REST, MCP and the query CLI. It never stores events as Findings.
package event

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/audit"
	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/credential"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/query"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"golang.org/x/time/rate"
)

const MaxPageSize = 200

var fieldName = regexp.MustCompile(`^[A-Za-z@][A-Za-z0-9_.@-]{0,255}$`)

func ValidField(name string) bool { return fieldName.MatchString(name) }

type Service struct {
	store    store.Store
	registry *connector.Registry
	cipher   *secret.Cipher
	mu       sync.Mutex
	limits   map[string]*rate.Limiter
}

func New(st store.Store, registry *connector.Registry, cipher *secret.Cipher) *Service {
	return &Service{store: st, registry: registry, cipher: cipher, limits: map[string]*rate.Limiter{}}
}

type continuation struct {
	Version    int               `json:"v"`
	ConfigHash string            `json:"config_hash"`
	Query      model.EventSearch `json:"query"`
	Token      json.RawMessage   `json:"token"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

func invalid(message string) error {
	return &connector.Error{Kind: connector.KindConfig, Code: "invalid_event_query", Message: message}
}

// Normalize resolves relative time once, validates every common filter and
// refuses unsupported/ambiguous inputs before an upstream request is made.
func Normalize(q model.EventSearch, now time.Time) (model.EventSearch, error) {
	if q.AccountID == "" {
		return q, invalid("account_id is required")
	}
	if q.Limit == 0 {
		q.Limit = 20
	}
	if q.Limit < 1 || q.Limit > MaxPageSize {
		return q, invalid("limit must be between 1 and 200")
	}
	if q.IP != "" && net.ParseIP(q.IP) == nil {
		return q, invalid("ip must be an IPv4 or IPv6 address")
	}
	if len(q.Keyword) > 2048 || len(q.Host) > 1024 || len(q.User) > 1024 {
		return q, invalid("event filter exceeds the size limit")
	}
	if len(q.Filters) > 16 {
		return q, invalid("at most 16 source field filters are allowed")
	}
	for name, value := range q.Filters {
		if !ValidField(name) || len(value) > 2048 {
			return q, invalid("invalid source field filter")
		}
	}
	if q.GroupBy != "" && !ValidField(q.GroupBy) {
		return q, invalid("group_by must be one source field name")
	}
	if q.TopN != 0 && q.GroupBy == "" {
		return q, invalid("top_n requires group_by")
	}
	if q.TopN == 0 && q.GroupBy != "" {
		q.TopN = 10
	}
	if q.TopN < 0 || q.TopN > 50 {
		return q, invalid("top_n must be between 1 and 50")
	}
	start, end, err := query.ResolveWindow(q.Start, q.End, q.Since, 24*time.Hour, now)
	if err != nil {
		return q, invalid(err.Error())
	}
	q.Start, q.End, q.Since, q.Cursor = start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano), "", ""
	return q, nil
}

func (s *Service) source(ctx context.Context, id string) (connector.Connector, connector.EventSource, string, error) {
	if id == "" {
		return nil, nil, "", invalid("account_id is required")
	}
	acct, err := s.store.GetAccount(ctx, id)
	if err != nil {
		return nil, nil, "", err
	}
	if !acct.Enabled {
		return nil, nil, "", invalid("source connection is disabled")
	}
	desc, ok := s.registry.Descriptor(acct.Provider)
	if !ok || !desc.QueryOnly {
		return nil, nil, "", invalid("source does not support remote event queries")
	}
	cred, err := credential.Load(ctx, s.store, s.cipher, id)
	if err != nil {
		return nil, nil, "", connector.ConfigError(acct.Provider, "cannot load source credential")
	}
	cfg := connector.AccountConfig{Provider: acct.Provider, AccountID: acct.ID, Name: acct.Name, AccountUID: acct.AccountUID, Region: acct.Region, Options: acct.Options, Credential: cred}
	conn, err := s.registry.New(cfg)
	if err != nil {
		return nil, nil, "", err
	}
	source, ok := conn.(connector.EventSource)
	if !ok {
		connector.Close(conn)
		return nil, nil, "", invalid("source does not implement remote event queries")
	}
	raw, _ := json.Marshal(cfg)
	hash := fmt.Sprintf("%x", sha256.Sum256(raw))
	s.mu.Lock()
	limiter := s.limits[id]
	if limiter == nil {
		limiter = rate.NewLimiter(2, 2)
		s.limits[id] = limiter
	}
	s.mu.Unlock()
	if err := limiter.Wait(ctx); err != nil {
		connector.Close(conn)
		return nil, nil, "", &connector.Error{Provider: acct.Provider, Kind: connector.KindThrottled, Code: "query_budget", Message: "remote query budget exhausted"}
	}
	return conn, source, hash, nil
}

func (s *Service) Search(ctx context.Context, request model.EventSearch) (*model.EventPage, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var token json.RawMessage
	var previous continuation
	if request.Cursor != "" {
		// A continuation already contains the exact query and time window.
		other := request
		other.Cursor, other.AccountID = "", ""
		raw, _ := json.Marshal(other)
		if string(raw) != `{"account_id":""}` {
			return nil, invalid("continuation accepts only account_id and cursor; filters are pinned in the cursor")
		}
		if len(request.Cursor) > 131072 {
			return nil, invalid("invalid event cursor")
		}
		plain, err := s.cipher.Decrypt(request.Cursor)
		if err != nil || json.Unmarshal([]byte(plain), &previous) != nil || previous.Version != 1 || !previous.ExpiresAt.After(time.Now()) || previous.Query.AccountID != request.AccountID {
			return nil, invalid("event cursor is invalid or expired; start a new query")
		}
		request, token = previous.Query, previous.Token
	}
	q, err := Normalize(request, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if span := audit.FromContext(ctx); span != nil {
		span.Event.EffectiveQuery = audit.Parameters(q)
	}
	conn, source, hash, err := s.source(ctx, q.AccountID)
	if err != nil {
		return nil, err
	}
	defer connector.Close(conn)
	if previous.Version != 0 && hash != previous.ConfigHash {
		return nil, invalid("source configuration changed; start a new query")
	}
	page, err := source.SearchEvents(ctx, q, token)
	if err != nil {
		return nil, err
	}
	page.Query = q
	if page.HasMore {
		if len(page.Continuation) == 0 {
			return nil, errors.New("source omitted its event continuation")
		}
		raw, err := json.Marshal(continuation{Version: 1, ConfigHash: hash, Query: q, Token: page.Continuation, ExpiresAt: time.Now().UTC().Add(90 * time.Second)})
		if err != nil {
			return nil, err
		}
		page.NextCursor, err = s.cipher.Encrypt(string(raw))
		if err != nil {
			return nil, err
		}
	}
	return page, nil
}

func (s *Service) Fields(ctx context.Context, accountID string) (*model.EventFields, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, source, _, err := s.source(ctx, accountID)
	if err != nil {
		return nil, err
	}
	defer connector.Close(conn)
	return source.EventFields(ctx)
}

func (s *Service) Evidence(ctx context.Context, ref model.EventReference) (*model.EventEvidence, error) {
	if ref.Index == "" || ref.ID == "" || len(ref.Index) > 1024 || len(ref.ID) > 2048 || len(ref.Routing) > 2048 || strings.ContainsAny(ref.Index, "*,/?#") {
		return nil, invalid("an exact source index and document id are required")
	}
	if ref.RawHash != "" {
		if len(ref.RawHash) != 64 || strings.Trim(ref.RawHash, "0123456789abcdef") != "" {
			return nil, invalid("raw_hash must be a lowercase SHA-256 digest")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, source, _, err := s.source(ctx, ref.AccountID)
	if err != nil {
		return nil, err
	}
	defer connector.Close(conn)
	return source.EventEvidence(ctx, ref)
}
