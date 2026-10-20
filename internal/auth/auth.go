// Package auth implements operator authentication: Argon2id passwords,
// database-backed sessions, revocable API keys and login throttling.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/password"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

const (
	// CookieName is the browser session cookie.
	CookieName = "guiliu_session"
	// SessionPrefix marks opaque browser/API session tokens.
	SessionPrefix = "gls_"
	// APIKeyPrefix marks long-lived automation keys.
	APIKeyPrefix = "glk_"

	minPasswordLength = 12
	maxPasswordLength = 256
	defaultSessionTTL = 12 * time.Hour
	defaultAPIKeyTTL  = 90 * 24 * time.Hour
	maxAPIKeyTTL      = 365 * 24 * time.Hour
)

var (
	ErrInvalidCredentials  = errors.New("invalid username or password")
	ErrTooManyAttempts     = errors.New("too many login attempts, try again later")
	ErrUnauthorized        = errors.New("authentication required")
	ErrAuthDisabled        = errors.New("authentication is disabled in dev mode")
	ErrAdminPasswordNeeded = errors.New("no users configured: set GUILIU_ADMIN_PASSWORD for the first start, or run `guiliu user add`")
	ErrWeakPassword        = fmt.Errorf("password must be between %d and %d characters", minPasswordLength, maxPasswordLength)
	ErrInvalidUsername     = errors.New("username must be 3-64 chars: lowercase letters, digits, dot, dash or underscore")
	ErrConflict            = store.ErrConflict
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// Config controls authentication behavior.
type Config struct {
	DevMode       bool
	SessionTTL    time.Duration
	SecureCookies bool
	AdminUser     string
}

// Principal is the authenticated caller attached to a request context.
type Principal struct {
	User      model.User
	Kind      string // session | api_key | dev
	ExpiresAt time.Time
	TokenHash string
}

// IsAdmin reports whether the caller may mutate accounts or alert state.
func (p *Principal) IsAdmin() bool {
	return p != nil && (p.Kind == "dev" || p.User.Role == "admin")
}

type principalKey struct{}

func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok
}

// Service is the authentication entry point used by the API and CLI.
type Service struct {
	store    store.Store
	cfg      Config
	log      *slog.Logger
	now      func() time.Time
	limiter  *loginLimiter
	loginSem chan struct{}
}

func New(st store.Store, cfg Config, log *slog.Logger) *Service {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = defaultSessionTTL
	}
	if cfg.AdminUser == "" {
		cfg.AdminUser = "admin"
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		store:    st,
		cfg:      cfg,
		log:      log,
		now:      func() time.Time { return time.Now().UTC() },
		limiter:  newLoginLimiter(10, 15*time.Minute),
		loginSem: make(chan struct{}, 4),
	}
}

func (s *Service) DevMode() bool             { return s.cfg.DevMode }
func (s *Service) SessionTTL() time.Duration { return s.cfg.SessionTTL }
func (s *Service) SecureCookies() bool       { return s.cfg.SecureCookies }

func (s *Service) DevPrincipal() *Principal {
	return &Principal{
		User: model.User{Username: "dev", Role: "admin"},
		Kind: "dev",
	}
}

// EnsureAdmin creates the first administrator when the user table is empty.
func (s *Service) EnsureAdmin(ctx context.Context, username, pw string) (bool, error) {
	n, err := s.store.CountUsers(ctx)
	if err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	if username == "" {
		username = s.cfg.AdminUser
	}
	if pw == "" {
		return false, ErrAdminPasswordNeeded
	}
	if _, err := s.CreateUser(ctx, username, pw, "admin"); err != nil {
		return false, err
	}
	return true, nil
}

// CreateUser is used by the trusted local CLI.
func (s *Service) CreateUser(ctx context.Context, username, pw, role string) (*model.User, error) {
	username = normalizeUsername(username)
	if !usernamePattern.MatchString(username) {
		return nil, ErrInvalidUsername
	}
	if role == "" {
		role = "viewer"
	}
	if role != "admin" && role != "viewer" {
		return nil, errors.New("role must be admin or viewer")
	}
	if err := ValidatePassword(pw); err != nil {
		return nil, err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return nil, err
	}
	u := &model.User{Username: username, Role: role}
	if err := s.store.CreateUser(ctx, u, hash); err != nil {
		return nil, err
	}
	return u, nil
}

// ResetPassword is a trusted local admin operation.
func (s *Service) ResetPassword(ctx context.Context, username, pw string) error {
	u, _, err := s.store.GetUserByUsername(ctx, normalizeUsername(username))
	if err != nil {
		return err
	}
	if err := ValidatePassword(pw); err != nil {
		return err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return err
	}
	if err := s.store.UpdateUserPassword(ctx, u.ID, hash); err != nil {
		return err
	}
	return s.store.DeleteUserSessions(ctx, u.ID)
}

func (s *Service) ListUsers(ctx context.Context) ([]model.User, error) {
	return s.store.ListUsers(ctx)
}

// Login validates credentials and creates a session.
func (s *Service) Login(ctx context.Context, username, pw string) (*Principal, string, time.Time, error) {
	if s.cfg.DevMode {
		return nil, "", time.Time{}, ErrAuthDisabled
	}
	select {
	case s.loginSem <- struct{}{}:
		defer func() { <-s.loginSem }()
	case <-ctx.Done():
		return nil, "", time.Time{}, ctx.Err()
	}
	username = normalizeUsername(username)
	now := s.now()
	if !s.limiter.Allow(username, now) {
		return nil, "", time.Time{}, ErrTooManyAttempts
	}
	user, hash, err := s.store.GetUserByUsername(ctx, username)
	if errors.Is(err, store.ErrNotFound) {
		// Equalize timing for unknown users.
		_, _ = password.Verify(pw, dummyHash())
		s.limiter.Fail(username, now)
		return nil, "", time.Time{}, ErrInvalidCredentials
	}
	if err != nil {
		return nil, "", time.Time{}, err
	}
	ok, err := password.Verify(pw, hash)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok || user.Disabled {
		s.limiter.Fail(username, now)
		return nil, "", time.Time{}, ErrInvalidCredentials
	}
	s.limiter.Reset(username)
	raw, tokenHash, err := newToken(SessionPrefix)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	expires := now.Add(s.cfg.SessionTTL)
	if err := s.store.CreateSession(ctx, tokenHash, user.ID, expires); err != nil {
		return nil, "", time.Time{}, err
	}
	return &Principal{User: *user, Kind: "session", ExpiresAt: expires, TokenHash: tokenHash}, raw, expires, nil
}

// Authenticate resolves a session or API key token.
func (s *Service) Authenticate(ctx context.Context, token string) (*Principal, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, ErrUnauthorized
	}
	now := s.now()
	switch {
	case strings.HasPrefix(token, SessionPrefix):
		hash := hashToken(token)
		user, expires, err := s.store.GetSessionUser(ctx, hash, now)
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrUnauthorized
		}
		if err != nil {
			return nil, err
		}
		return &Principal{User: *user, Kind: "session", ExpiresAt: expires, TokenHash: hash}, nil
	case strings.HasPrefix(token, APIKeyPrefix):
		hash := hashToken(token)
		user, expires, err := s.store.GetUserByAPIKey(ctx, hash, now)
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrUnauthorized
		}
		if err != nil {
			return nil, err
		}
		p := &Principal{User: *user, Kind: "api_key", TokenHash: hash}
		if expires != nil {
			p.ExpiresAt = *expires
		}
		return p, nil
	default:
		return nil, ErrUnauthorized
	}
}

// Logout revokes a session. API keys are not revoked by logout.
func (s *Service) Logout(ctx context.Context, token string) error {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, SessionPrefix) {
		return nil
	}
	return s.store.DeleteSession(ctx, hashToken(token))
}

// ChangePassword verifies the current password, updates it and revokes every
// session of the user (forcing a fresh login).
func (s *Service) ChangePassword(ctx context.Context, userID, current, next string) error {
	_, hash, err := s.store.GetUserCredential(ctx, userID)
	if err != nil {
		return err
	}
	ok, err := password.Verify(current, hash)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCredentials
	}
	if err := ValidatePassword(next); err != nil {
		return err
	}
	if current == next {
		return errors.New("new password must be different from the current password")
	}
	newHash, err := password.Hash(next)
	if err != nil {
		return err
	}
	if err := s.store.UpdateUserPassword(ctx, userID, newHash); err != nil {
		return err
	}
	if err := s.store.DeleteUserSessions(ctx, userID); err != nil {
		return err
	}
	return s.store.RevokeUserAPIKeys(ctx, userID, s.now())
}

// CreateAPIKey returns the raw key exactly once.
func (s *Service) CreateAPIKey(ctx context.Context, userID, name string, ttl time.Duration) (string, *model.APIKey, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "mcp"
	}
	if len([]rune(name)) > 64 {
		return "", nil, errors.New("key name must be at most 64 characters")
	}
	if ttl <= 0 {
		ttl = defaultAPIKeyTTL
	}
	if ttl > maxAPIKeyTTL {
		ttl = maxAPIKeyTTL
	}
	raw, tokenHash, err := newToken(APIKeyPrefix)
	if err != nil {
		return "", nil, err
	}
	now := s.now()
	expires := now.Add(ttl)
	key := &model.APIKey{
		ID:        uuid.NewString(),
		UserID:    userID,
		Name:      name,
		Prefix:    raw[:12] + "…",
		CreatedAt: now,
		ExpiresAt: &expires,
	}
	if err := s.store.CreateAPIKey(ctx, key, tokenHash); err != nil {
		return "", nil, err
	}
	return raw, key, nil
}

func (s *Service) ListAPIKeys(ctx context.Context, userID string) ([]model.APIKey, error) {
	return s.store.ListAPIKeys(ctx, userID)
}

func (s *Service) RevokeAPIKey(ctx context.Context, userID, keyID string) error {
	return s.store.RevokeAPIKey(ctx, keyID, userID, s.now())
}

// Cleanup removes expired sessions; call at startup and periodically.
func (s *Service) Cleanup(ctx context.Context) {
	if n, err := s.store.DeleteExpiredSessions(ctx, s.now()); err == nil && n > 0 {
		s.log.Info("removed expired sessions", "count", n)
	}
	s.limiter.Cleanup(s.now())
}

// ValidatePassword enforces the password policy for new passwords.
func ValidatePassword(pw string) error {
	n := len([]rune(pw))
	if n < minPasswordLength || n > maxPasswordLength {
		return ErrWeakPassword
	}
	return nil
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func newToken(prefix string) (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw := prefix + base64.RawURLEncoding.EncodeToString(buf)
	return raw, hashToken(raw), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

var (
	dummyOnce  sync.Once
	dummyValue string
)

func dummyHash() string {
	dummyOnce.Do(func() {
		dummyValue, _ = password.Hash("gui-liu-dummy-password-for-timing")
	})
	return dummyValue
}

// loginLimiter is an in-memory, per-username failure counter. It resets after
// the window, so a restart only clears temporary throttling.
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
	max      int
	window   time.Duration
}

type loginAttempt struct {
	count int
	reset time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{attempts: map[string]*loginAttempt{}, max: max, window: window}
}

func (l *loginLimiter) Allow(username string, now time.Time) bool {
	if username == "" {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[username]
	if a == nil {
		return true
	}
	if now.After(a.reset) {
		delete(l.attempts, username)
		return true
	}
	return a.count < l.max
}

func (l *loginLimiter) Fail(username string, now time.Time) {
	if username == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[username]
	if a == nil || now.After(a.reset) {
		l.attempts[username] = &loginAttempt{count: 1, reset: now.Add(l.window)}
		return
	}
	a.count++
}

func (l *loginLimiter) Reset(username string) {
	l.mu.Lock()
	delete(l.attempts, username)
	l.mu.Unlock()
}

func (l *loginLimiter) Cleanup(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, a := range l.attempts {
		if now.After(a.reset) {
			delete(l.attempts, k)
		}
	}
}
