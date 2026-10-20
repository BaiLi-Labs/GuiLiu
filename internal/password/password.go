// Package password implements Argon2id password hashing with PHC-encoded
// strings, so hashes are portable and self-describing.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	memory      = 64 * 1024 // 64 MiB
	iterations  = 3
	parallelism = 2
	saltLength  = 16
	keyLength   = 32
)

// ErrInvalidHash is returned when a stored hash is malformed.
var ErrInvalidHash = errors.New("invalid password hash")

// Hash returns an Argon2id PHC string.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, keyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, iterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify checks a password against a PHC string. A mismatch returns false, nil.
func Verify(password, encoded string) (bool, error) {
	params, salt, expected, err := parse(encoded)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
}

func parse(encoded string) (params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return params{}, nil, nil, ErrInvalidHash
	}
	if parts[2] != "v=19" {
		return params{}, nil, nil, ErrInvalidHash
	}
	var memory uint32
	var iterations uint32
	var parallelism uint8
	for _, part := range strings.Split(parts[3], ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			return params{}, nil, nil, ErrInvalidHash
		}
		switch kv[0] {
		case "m":
			n, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return params{}, nil, nil, ErrInvalidHash
			}
			memory = uint32(n)
		case "t":
			n, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				return params{}, nil, nil, ErrInvalidHash
			}
			iterations = uint32(n)
		case "p":
			n, err := strconv.ParseUint(kv[1], 10, 8)
			if err != nil {
				return params{}, nil, nil, ErrInvalidHash
			}
			parallelism = uint8(n)
		}
	}
	// Bound parameters so a corrupted hash cannot allocate unbounded memory.
	if memory < 8*1024 || memory > 256*1024 || iterations < 1 || iterations > 10 || parallelism < 1 || parallelism > 16 {
		return params{}, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return params{}, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return params{}, nil, nil, ErrInvalidHash
	}
	return params{memory: memory, iterations: iterations, parallelism: parallelism}, salt, key, nil
}
