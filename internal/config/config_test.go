package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadExpandsOnlyBracedEnv(t *testing.T) {
	for _, key := range []string{
		"GUILIU_LISTEN", "GUILIU_DATABASE", "GUILIU_SECRET_KEY", "GUILIU_SECRET_KEY_FILE",
		"GUILIU_LOG_LEVEL", "GUILIU_SYNC_ENABLED", "GUILIU_DEV", "GUILIU_MOCK",
		"GUILIU_SECURE_COOKIES", "GUILIU_ADMIN_USER", "GUILIU_SESSION_TTL",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("GUILIU_TEST_LEVEL", "debug")
	t.Setenv("GUILIU_TEST_KEY", "secret-key")
	dir := t.TempDir()
	path := filepath.Join(dir, "guiliu.json")
	content := `{
	  "log_level": "${GUILIU_TEST_LEVEL}",
	  "database": "` + filepath.Join(dir, "data.db") + `",
	  "secret_key_file": "` + filepath.Join(dir, "secret.key") + `",
	  "accounts": [{
	    "name": "test-$literal",
	    "provider": "tencent",
	    "access_key_id": "AKID$NOT_EXPANDED",
	    "access_key_secret": "${GUILIU_TEST_KEY}"
	  }]
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("log level = %q", cfg.LogLevel)
	}
	if cfg.Accounts[0].Name != "test-$literal" {
		t.Fatalf("literal dollar was expanded: %q", cfg.Accounts[0].Name)
	}
	if cfg.Accounts[0].AccessKeyID != "AKID$NOT_EXPANDED" {
		t.Fatalf("credential was expanded: %q", cfg.Accounts[0].AccessKeyID)
	}
	if cfg.Accounts[0].AccessKeySecret != "secret-key" {
		t.Fatalf("secret = %q", cfg.Accounts[0].AccessKeySecret)
	}
	if cfg.Sync.Interval.Get() != 5*time.Minute {
		t.Fatalf("default interval = %s", cfg.Sync.Interval.Get())
	}
}

func TestValidateAllowsSingleTokenCredential(t *testing.T) {
	// Several vendors authenticate with one API token, and push-only accounts
	// have no product credential at all. Required fields are enforced by the
	// connector descriptor during bootstrap, not here.
	cfg := Default()
	cfg.Accounts = []AccountConfig{{Name: "x", Provider: "safeline-ce", AccessKeyID: "only-token"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("single-token credentials must be allowed: %v", err)
	}
}
