// Package connector defines the plugin contract every cloud provider
// implements. A connector only does two things: fetch raw vendor alerts and
// normalize one raw alert into the vendor-neutral model + OCSF payload.
package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// Credential is the provider credential bundle. Most clouds use AK/SK;
// GCP uses a service account JSON document.
type Credential struct {
	AccessKeyID        string `json:"access_key_id,omitempty"`
	AccessKeySecret    string `json:"access_key_secret,omitempty"`
	SessionToken       string `json:"session_token,omitempty"`
	ServiceAccountJSON string `json:"service_account_json,omitempty"`
}

// AccountConfig is the immutable runtime configuration handed to a factory.
type AccountConfig struct {
	Provider   string
	AccountID  string
	Name       string
	AccountUID string
	Region     string
	Options    map[string]string
	Credential Credential
}

// CredentialField describes one input the console must collect.
type CredentialField struct {
	Name      string `json:"name"`
	Label     string `json:"label"`
	Secret    bool   `json:"secret"`
	Required  bool   `json:"required"`
	Multiline bool   `json:"multiline,omitempty"`
	Help      string `json:"help,omitempty"`
}

// OptionField describes a non-secret provider setting (project ID, workspace,
// GCP parent, ...) that the console should collect into account options.
type OptionField struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	Required    bool   `json:"required"`
	Help        string `json:"help,omitempty"`
}

// Product describes a sub-product aggregated by the connector.
type Product struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

// Descriptor is the static identity and capability declaration of a connector.
type Descriptor struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Vendor        string            `json:"vendor"`
	Product       string            `json:"product"`
	ProductUID    string            `json:"product_uid"`
	APIVersion    string            `json:"api_version"`
	DocsURL       string            `json:"docs_url,omitempty"`
	MapperVersion string            `json:"mapper_version"`
	Credential    []CredentialField `json:"credential_fields"`
	OptionFields  []OptionField     `json:"option_fields,omitempty"`
	Products      []Product         `json:"products"`
}

// Query is one page request over a fixed time window. Token is opaque to the
// engine; each connector decides how to encode its page cursor.
type Query struct {
	Start    time.Time
	End      time.Time
	PageSize int
	Token    string
}

// RawAlert is the untouched vendor payload. Normalization is a pure function of
// this value, which is what makes re-normalizing history possible.
type RawAlert struct {
	Raw json.RawMessage
}

// Page is a single page of raw alerts.
type Page struct {
	Records   []RawAlert
	NextToken string
	Total     int
}

// Connector is the plugin interface. Implementations must be safe for
// concurrent use after construction.
type Connector interface {
	Info() Descriptor
	Check(ctx context.Context) error
	Fetch(ctx context.Context, q Query) (Page, error)
	Normalize(raw json.RawMessage) (model.Alert, error)
}

// Factory builds a connector from an account configuration.
type Factory func(cfg AccountConfig) (Connector, error)

// ErrorKind classifies failures so the ingest engine can decide whether a
// retry is useful and surface an actionable message to operators.
type ErrorKind string

const (
	KindAuth      ErrorKind = "auth"
	KindThrottled ErrorKind = "throttled"
	KindTransient ErrorKind = "transient"
	KindPermanent ErrorKind = "permanent"
	KindConfig    ErrorKind = "config"
)

// Error is a classified connector failure.
type Error struct {
	Provider string
	Kind     ErrorKind
	Code     string
	Message  string
	Err      error
}

func (e *Error) Error() string {
	parts := []string{}
	if e.Provider != "" {
		parts = append(parts, e.Provider)
	}
	if e.Code != "" {
		parts = append(parts, e.Code)
	}
	msg := e.Message
	if msg == "" && e.Err != nil {
		msg = e.Err.Error()
	}
	if msg != "" {
		parts = append(parts, msg)
	}
	if len(parts) == 0 {
		return "connector error"
	}
	return strings.Join(parts, ": ")
}

func (e *Error) Unwrap() error { return e.Err }

// Retryable reports whether the engine should retry.
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Kind == KindThrottled || ce.Kind == KindTransient
	}
	var ne net.Error
	return errors.As(err, &ne)
}

// AuthError reports whether the failure is an authentication/authorization
// problem that needs operator action.
func AuthError(err error) bool {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Kind == KindAuth
	}
	return false
}

// Throttled reports whether the vendor rejected the request due to a rate or
// quota limit.
func Throttled(err error) bool {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Kind == KindThrottled
	}
	return false
}

// Classify wraps an SDK error. Cloud SDKs expose wildly different error types,
// so classification is based on the canonical error codes and substrings they
// all include.
func Classify(provider string, err error) error {
	if err == nil {
		return nil
	}
	var existing *Error
	if errors.As(err, &existing) {
		return err
	}
	msg := err.Error()
	lower := strings.ToLower(msg)

	kind := KindPermanent
	code := ""
	switch {
	case containsAny(lower, "requestlimitexceeded", "throttling", "too many requests", "limit exceeded", "qps", "flowcontrol", "resourceexhausted", "resource exhausted", "slowdown", "rate exceeded"):
		kind, code = KindThrottled, "throttled"
	case containsAny(lower, "authfailure", "unauthorized", "invalidaccesskey", "signature", "forbidden", "access denied", "permission", "not authorized", "unauthenticated", "invalidclienttokenid", "expiredtoken", "unrecognizedclient"):
		kind, code = KindAuth, "auth"
	case containsAny(lower, "timeout", "timed out", "deadline exceeded", "connection reset", "connection refused", "temporarily unavailable", "unavailable", "eof", "server error", "internal error"):
		kind, code = KindTransient, "transient"
	}
	var ne net.Error
	if errors.As(err, &ne) {
		kind, code = KindTransient, "network"
	}

	return &Error{Provider: provider, Kind: kind, Code: code, Err: err}
}

// ConfigError builds a configuration error.
func ConfigError(provider, msg string) error {
	return &Error{Provider: provider, Kind: KindConfig, Code: "config", Message: msg}
}

// Close releases optional connector resources (for example a GCP gRPC client).
func Close(c Connector) error {
	if c == nil {
		return nil
	}
	if closer, ok := c.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// Registry holds connector factories. Connectors self-register from init().
type Registry struct {
	mu      sync.RWMutex
	entries map[string]entry
}

type entry struct {
	descriptor Descriptor
	factory    Factory
}

func NewRegistry() *Registry {
	return &Registry{entries: map[string]entry{}}
}

var defaultRegistry = NewRegistry()

// Default returns the process-wide registry populated by connector packages.
func Default() *Registry { return defaultRegistry }

// Register adds a connector to the package registry. It panics on invalid or
// duplicate registrations because those are programming errors.
func Register(d Descriptor, f Factory) {
	if err := defaultRegistry.Register(d, f); err != nil {
		panic(err)
	}
}

func (r *Registry) Register(d Descriptor, f Factory) error {
	if d.ID == "" {
		return fmt.Errorf("connector descriptor missing id")
	}
	if f == nil {
		return fmt.Errorf("connector %s missing factory", d.ID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[d.ID]; ok {
		return fmt.Errorf("connector %s already registered", d.ID)
	}
	r.entries[d.ID] = entry{descriptor: d, factory: f}
	return nil
}

func (r *Registry) New(cfg AccountConfig) (Connector, error) {
	r.mu.RLock()
	e, ok := r.entries[cfg.Provider]
	r.mu.RUnlock()
	if !ok {
		return nil, ConfigError(cfg.Provider, "unknown provider")
	}
	return e.factory(cfg)
}

func (r *Registry) Descriptor(provider string) (Descriptor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[provider]
	if !ok {
		return Descriptor{}, false
	}
	return e.descriptor, true
}

func (r *Registry) List() []Descriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Descriptor, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e.descriptor)
	}
	return out
}
