package model

import "time"

// User is an authenticated operator. Password hashes are kept out of this
// struct so they can never leak through JSON.
type User struct {
	ID                string    `json:"id"`
	Username          string    `json:"username"`
	Role              string    `json:"role"`
	Disabled          bool      `json:"disabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	PasswordChangedAt time.Time `json:"password_changed_at,omitempty"`
}

// APIKey is a long-lived credential for MCP clients and automation. The raw
// key is returned exactly once at creation; only its hash is persisted.
type APIKey struct {
	ID         string     `json:"id"`
	UserID     string     `json:"-"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}
