package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// Beijing is the timezone used by the Chinese cloud security APIs for their
// request timestamp formats.
var Beijing = time.FixedZone("UTC+8", 8*3600)

var vendorTimeLayouts = []string{
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05.000",
	"2006-01-02T15:04:05",
	"2006-01-02T15:04:05.000",
	time.RFC3339,
	time.RFC3339Nano,
	"2006/01/02 15:04:05",
	"2006-01-02",
}

// FormatBeijing renders a timestamp in the format used by Aliyun SAS and
// Tencent CSIP query parameters.
func FormatBeijing(t time.Time) string {
	return t.In(Beijing).Format("2006-01-02 15:04:05")
}

// ParseVendorTime accepts the common vendor layouts, interpreting zone-less
// values as Beijing time.
func ParseVendorTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range vendorTimeLayouts {
		if t, err := time.ParseInLocation(layout, s, Beijing); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// HashRaw returns a short stable id for payloads without a vendor id.
func HashRaw(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// Truncate limits a string to max bytes without splitting a UTF-8 rune.
func Truncate(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	cut := max
	for cut > 0 && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut], true
}

// Str dereferences a nullable SDK string.
func Str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Uint64 dereferences a nullable SDK unsigned integer.
func Uint64(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

// Int64 dereferences a nullable SDK integer.
func Int64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// Int32 dereferences a nullable SDK 32-bit integer.
func Int32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

// Bool dereferences a nullable SDK boolean.
func Bool(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

// FirstNonEmpty returns the first non-empty string.
func FirstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// JoinNonEmpty joins the non-empty parts with sep.
func JoinNonEmpty(sep string, values ...string) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, sep)
}

// NamedResource builds the primary resource and records where its display name
// came from. vendorName must be a human-readable name the source declares for
// that exact asset. fallbacks are identifiers (domain, IP, native ID); they are
// used only when no name is declared, and the result says so. Mappers must not
// pass titles, alert text or locally derived labels as vendorName.
func NamedResource(id, typ, vendorName string, fallbacks ...string) model.Resource {
	resource := model.Resource{ID: id, Type: typ}
	if name := strings.TrimSpace(vendorName); name != "" {
		resource.Name, resource.Source = name, model.ResourceSourceVendorDeclared
		return resource
	}
	for _, fallback := range fallbacks {
		if name := strings.TrimSpace(fallback); name != "" {
			resource.Name, resource.Source = name, model.ResourceSourceIdentifierFallback
			return resource
		}
	}
	return resource
}

// RetryDelay returns the backoff before retry attempt n (1-based), capped at
// 8s with jitter. Cloud security APIs tend to throttle in sliding windows.
func RetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := time.Duration(1<<uint(attempt-1)) * time.Second
	if delay > 8*time.Second {
		delay = 8 * time.Second
	}
	return delay + time.Duration(rand.Intn(500))*time.Millisecond
}

// OptionInt reads an integer account option with a default.
func OptionInt(options map[string]string, key string, def int) int {
	v, ok := options[key]
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// OptionFloat reads a float account option with a default.
func OptionFloat(options map[string]string, key string, def float64) float64 {
	v, ok := options[key]
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil || f <= 0 {
		return def
	}
	return f
}

// OptionDuration reads a duration account option with a default.
func OptionDuration(options map[string]string, key string, def time.Duration) time.Duration {
	v, ok := options[key]
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		return def
	}
	return d
}
