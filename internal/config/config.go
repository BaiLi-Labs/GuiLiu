// Package config loads GuiLiu's JSON configuration. Every string is
// environment-expanded before parsing, so credentials can stay in the
// environment: "access_key_secret": "${TENCENT_SECRET_KEY}".
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Duration is a JSON-friendly time.Duration ("5m", "168h").
type Duration time.Duration

func (d Duration) Get() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration must be a string like \"5m\"")
	}
	*d = Duration(time.Duration(n))
	return nil
}

type Config struct {
	Listen        string          `json:"listen"`
	Database      string          `json:"database"`
	SecretKey     string          `json:"secret_key"`
	SecretKeyFile string          `json:"secret_key_file"`
	LogLevel      string          `json:"log_level"`
	Mock          bool            `json:"mock"`
	Auth          AuthConfig      `json:"auth"`
	Audit         AuditConfig     `json:"audit"`
	Sync          SyncConfig      `json:"sync"`
	Intake        IntakeConfig    `json:"intake"`
	Accounts      []AccountConfig `json:"accounts"`
}

// IntakeConfig controls the push receive path. Webhook ingest shares the main
// listener at POST /ingest/{account}; syslog needs its own listener because the
// protocol is not HTTP.
type IntakeConfig struct {
	SyslogListen  string `json:"syslog_listen"`
	SyslogNet     string `json:"syslog_net"`
	SyslogWorkers int    `json:"syslog_workers"`
	MaxBodyBytes  int64  `json:"max_body_bytes"`
}

type AuditConfig struct {
	RetentionDays int `json:"retention_days"`
}

type AuthConfig struct {
	DevMode       bool     `json:"dev_mode"`
	SessionTTL    Duration `json:"session_ttl"`
	SecureCookies bool     `json:"secure_cookies"`
	AdminUser     string   `json:"admin_user"`
}

type SyncConfig struct {
	Enabled         bool     `json:"enabled"`
	Interval        Duration `json:"interval"`
	InitialLookback Duration `json:"initial_lookback"`
	Overlap         Duration `json:"overlap"`
	MaxWindow       Duration `json:"max_window"`
	MaxPages        int      `json:"max_pages"`
	PageSize        int      `json:"page_size"`
	Workers         int      `json:"workers"`
}

// AccountConfig enables declarative (IaC) account onboarding.
type AccountConfig struct {
	Name               string            `json:"name"`
	Provider           string            `json:"provider"`
	AccountUID         string            `json:"account_uid"`
	Region             string            `json:"region"`
	AccessKeyID        string            `json:"access_key_id"`
	AccessKeySecret    string            `json:"access_key_secret"`
	SessionToken       string            `json:"session_token"`
	ServiceAccountJSON string            `json:"service_account_json"`
	Enabled            *bool             `json:"enabled"`
	Options            map[string]string `json:"options"`
	// PushToken enables the push receive path for this account. Only its
	// SHA-256 is persisted; the plaintext stays in configuration.
	PushToken string `json:"push_token"`
}

func (a AccountConfig) IsEnabled() bool {
	return a.Enabled == nil || *a.Enabled
}

func Default() *Config {
	return &Config{
		Listen:        "127.0.0.1:8080",
		Database:      "data/guiliu.db",
		SecretKeyFile: "data/secret.key",
		LogLevel:      "info",
		Audit:         AuditConfig{RetentionDays: 90},
		Auth: AuthConfig{
			SessionTTL: Duration(12 * time.Hour),
			AdminUser:  "admin",
		},
		Sync: SyncConfig{
			Enabled:         true,
			Interval:        Duration(5 * time.Minute),
			InitialLookback: Duration(24 * time.Hour),
			Overlap:         Duration(30 * time.Minute),
			MaxWindow:       Duration(24 * time.Hour),
			MaxPages:        10,
			PageSize:        100,
			Workers:         2,
		},
	}
}

// Load reads path (or ./guiliu.json when path is empty), expands environment
// variables and validates the result.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		if v := os.Getenv("GUILIU_CONFIG"); v != "" {
			path = v
		} else if _, err := os.Stat("guiliu.json"); err == nil {
			path = "guiliu.json"
		}
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		dec := json.NewDecoder(strings.NewReader(expandEnv(string(data))))
		dec.DisallowUnknownFields()
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
	}
	applyEnv(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

var envPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv only substitutes ${VAR}. os.ExpandEnv would also rewrite literal
// dollar signs inside credentials, which silently corrupts secrets.
func expandEnv(s string) string {
	return envPattern.ReplaceAllStringFunc(s, func(match string) string {
		name := match[2 : len(match)-1]
		return os.Getenv(name)
	})
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("GUILIU_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("GUILIU_DATABASE"); v != "" {
		cfg.Database = v
	}
	if v := os.Getenv("GUILIU_SECRET_KEY"); v != "" {
		cfg.SecretKey = v
	}
	if v := os.Getenv("GUILIU_SECRET_KEY_FILE"); v != "" {
		cfg.SecretKeyFile = v
	}
	if v := os.Getenv("GUILIU_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("GUILIU_SYNC_ENABLED"); v != "" {
		cfg.Sync.Enabled = envBool(v)
	}
	if v := os.Getenv("GUILIU_DEV"); v != "" {
		cfg.Auth.DevMode = envBool(v)
	}
	if v := os.Getenv("GUILIU_MOCK"); v != "" {
		cfg.Mock = envBool(v)
	}
	if v := os.Getenv("GUILIU_SECURE_COOKIES"); v != "" {
		cfg.Auth.SecureCookies = envBool(v)
	}
	if v := os.Getenv("GUILIU_ADMIN_USER"); v != "" {
		cfg.Auth.AdminUser = v
	}
	if v := os.Getenv("GUILIU_SESSION_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Auth.SessionTTL = Duration(d)
		}
	}
}

func envBool(v string) bool {
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

func (c *Config) Validate() error {
	if c.Audit.RetentionDays < 1 || c.Audit.RetentionDays > 3650 {
		return fmt.Errorf("audit.retention_days must be between 1 and 3650")
	}
	if strings.TrimSpace(c.Listen) == "" {
		return fmt.Errorf("listen address is required")
	}
	if strings.TrimSpace(c.Database) == "" {
		return fmt.Errorf("database path is required")
	}
	if c.SecretKey == "" && strings.TrimSpace(c.SecretKeyFile) == "" {
		return fmt.Errorf("secret_key or secret_key_file is required")
	}
	if c.Auth.SessionTTL.Get() < 5*time.Minute {
		return fmt.Errorf("auth.session_ttl must be at least 5m")
	}
	if strings.TrimSpace(c.Auth.AdminUser) == "" {
		return fmt.Errorf("auth.admin_user is required")
	}
	if c.Sync.Interval.Get() < 10*time.Second {
		return fmt.Errorf("sync.interval must be at least 10s")
	}
	if c.Sync.InitialLookback.Get() <= 0 {
		return fmt.Errorf("sync.initial_lookback must be positive")
	}
	if c.Sync.Overlap.Get() <= 0 {
		return fmt.Errorf("sync.overlap must be positive")
	}
	if c.Sync.Workers < 1 {
		return fmt.Errorf("sync.workers must be at least 1")
	}
	switch strings.ToLower(strings.TrimSpace(c.Intake.SyslogNet)) {
	case "", "tcp", "udp", "both":
	default:
		return fmt.Errorf("intake.syslog_net must be one of tcp, udp, both")
	}
	if c.Intake.MaxBodyBytes < 0 {
		return fmt.Errorf("intake.max_body_bytes must not be negative")
	}
	seen := map[string]struct{}{}
	for i, a := range c.Accounts {
		if strings.TrimSpace(a.Name) == "" {
			return fmt.Errorf("accounts[%d].name is required", i)
		}
		if strings.TrimSpace(a.Provider) == "" {
			return fmt.Errorf("accounts[%d].provider is required", i)
		}
		if _, ok := seen[a.Name]; ok {
			return fmt.Errorf("duplicate account name %q", a.Name)
		}
		seen[a.Name] = struct{}{}
		// Credentials are not paired here: many vendors authenticate with a
		// single API token, and push-only accounts have no product credential
		// at all. Each connector validates its own required fields, and
		// bootstrap applies the descriptor's required credential list.
	}
	return nil
}
