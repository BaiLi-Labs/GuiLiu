// Package secret encrypts connector credentials at rest with AES-256-GCM.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Cipher encrypts and decrypts credential blobs.
type Cipher struct {
	aead cipher.AEAD
}

// Load resolves the master key from (in order) an explicit base64 key, a key
// file, or a newly generated key file. Generating a local key keeps the
// quickstart zero-config while still avoiding plaintext secrets on disk.
func Load(keyBase64, keyFile string) (*Cipher, error) {
	key, err := resolveKey(keyBase64, keyFile)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

func resolveKey(keyBase64, keyFile string) ([]byte, error) {
	if strings.TrimSpace(keyBase64) != "" {
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyBase64))
		if err != nil || len(key) != 32 {
			return nil, errors.New("GUILIU_SECRET_KEY must be base64 of exactly 32 bytes")
		}
		return key, nil
	}
	if keyFile == "" {
		return nil, errors.New("no secret key configured")
	}
	data, err := os.ReadFile(keyFile)
	if err == nil {
		key, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if decErr != nil || len(key) != 32 {
			return nil, fmt.Errorf("secret key file %s is invalid", keyFile)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read secret key file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return nil, fmt.Errorf("create secret key directory: %w", err)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(keyFile, []byte(encoded+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("write secret key file: %w", err)
	}
	return key, nil
}

// Encrypt returns base64(nonce || ciphertext).
func (c *Cipher) Encrypt(plain string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nil, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// Decrypt reverses Encrypt.
func (c *Cipher) Decrypt(encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("credential is not valid base64: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("credential blob is truncated")
	}
	plain, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", errors.New("cannot decrypt credential: the secret key changed or the database was copied from another instance")
	}
	return string(plain), nil
}
