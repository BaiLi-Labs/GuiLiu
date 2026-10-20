// Package credential centralizes AK/SK encryption so the API, ingest engine
// and CLI never handle plaintext storage differently.
package credential

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

// Encrypt serializes and encrypts a credential pair.
func Encrypt(c *secret.Cipher, cred connector.Credential) (string, error) {
	raw, err := json.Marshal(cred)
	if err != nil {
		return "", err
	}
	return c.Encrypt(string(raw))
}

// Load decrypts the credential of an account.
func Load(ctx context.Context, st store.Store, c *secret.Cipher, accountID string) (connector.Credential, error) {
	var cred connector.Credential
	blob, err := st.AccountCredential(ctx, accountID)
	if err != nil {
		return cred, err
	}
	if blob == "" {
		return cred, errors.New("account has no credential configured")
	}
	plain, err := c.Decrypt(blob)
	if err != nil {
		return cred, err
	}
	if err := json.Unmarshal([]byte(plain), &cred); err != nil {
		return cred, err
	}
	return cred, nil
}

// Hint returns a display-safe suffix of an access key id.
func Hint(accessKeyID string) string {
	if len(accessKeyID) <= 4 {
		return "****"
	}
	return "****" + accessKeyID[len(accessKeyID)-4:]
}
