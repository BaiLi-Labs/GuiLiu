package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, Config{SessionTTL: time.Hour, AdminUser: "admin"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestEnsureAdminAndLogin(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.EnsureAdmin(ctx, "admin", ""); !errors.Is(err, ErrAdminPasswordNeeded) {
		t.Fatalf("expected admin password error, got %v", err)
	}
	created, err := s.EnsureAdmin(ctx, "admin", "correct-horse-battery")
	if err != nil || !created {
		t.Fatalf("ensure admin: %v, %v", created, err)
	}
	if created, err := s.EnsureAdmin(ctx, "admin", "another-password-123"); err != nil || created {
		t.Fatalf("second ensure admin: %v, %v", created, err)
	}

	if _, _, _, err := s.Login(ctx, "admin", "wrong-password-123"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password err = %v", err)
	}
	p, token, expires, err := s.Login(ctx, "admin", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || p.User.Username != "admin" || expires.Before(time.Now()) {
		t.Fatalf("login = %+v %q %s", p, token, expires)
	}
	got, err := s.Authenticate(ctx, token)
	if err != nil || got.User.ID != p.User.ID || got.Kind != "session" {
		t.Fatalf("authenticate = %+v, %v", got, err)
	}
	if err := s.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("after logout err = %v", err)
	}
}

func TestLoginThrottle(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.EnsureAdmin(ctx, "admin", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, _, _, err := s.Login(ctx, "admin", "wrong-password-123"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d err = %v", i, err)
		}
	}
	if _, _, _, err := s.Login(ctx, "admin", "correct-horse-battery"); !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("expected throttle, got %v", err)
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.EnsureAdmin(ctx, "admin", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	p, _, _, err := s.Login(ctx, "admin", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	raw, key, err := s.CreateAPIKey(ctx, p.User.ID, "mcp", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || key.Prefix == "" || key.ExpiresAt == nil {
		t.Fatalf("key = %+v", key)
	}
	got, err := s.Authenticate(ctx, raw)
	if err != nil || got.Kind != "api_key" || got.User.ID != p.User.ID {
		t.Fatalf("api key auth = %+v, %v", got, err)
	}
	keys, err := s.ListAPIKeys(ctx, p.User.ID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys = %+v, %v", keys, err)
	}
	if err := s.RevokeAPIKey(ctx, p.User.ID, key.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, raw); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked key err = %v", err)
	}
}

func TestChangePasswordRevokesSessions(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.EnsureAdmin(ctx, "admin", "correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	p, token, _, err := s.Login(ctx, "admin", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := s.CreateAPIKey(ctx, p.User.ID, "before-password-change", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ChangePassword(ctx, p.User.ID, "correct-horse-battery", "new-correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old session err = %v", err)
	}
	if _, err := s.Authenticate(ctx, raw); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old api key err = %v", err)
	}
	if _, _, _, err := s.Login(ctx, "admin", "correct-horse-battery"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password err = %v", err)
	}
	if _, _, _, err := s.Login(ctx, "admin", "new-correct-horse-battery"); err != nil {
		t.Fatalf("new password err = %v", err)
	}
}

func TestCreateUserValidation(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.CreateUser(ctx, "A", "short", "viewer"); err == nil {
		t.Fatal("expected invalid username/password error")
	}
	if _, err := s.CreateUser(ctx, "alice", "long-enough-password", "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "alice", "long-enough-password", "viewer"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate err = %v", err)
	}
}
