package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/version"
)

const (
	defaultBaseURL     = "http://127.0.0.1:8080"
	defaultTimeout     = 30 * time.Second
	defaultMaxResponse = 64 << 20
	clientHeader       = "cli"
)

type config struct {
	BaseURL string
	APIKey  string
	Timeout time.Duration
}

type client struct {
	base    *url.URL
	apiKey  string
	http    *http.Client
	version string
}

func newClient(cfg config) (*client, error) {
	raw := strings.TrimSpace(cfg.BaseURL)
	if raw == "" {
		raw = defaultBaseURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid --url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("--url must use http or https")
	}
	if u.Host == "" {
		return nil, errors.New("--url must include a host")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("--url must not include a query or fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(u.Path, "/api/v1") {
		u.Path += "/api/v1"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &client{
		base:    u,
		apiKey:  strings.TrimSpace(cfg.APIKey),
		http:    &http.Client{Timeout: timeout},
		version: version.Version,
	}, nil
}

type apiError struct {
	Status    int
	Code      string
	Message   string
	RequestID string
}

func (e *apiError) Error() string {
	message := e.Message
	if e.Code != "" {
		message = e.Code + ": " + message
	}
	if e.RequestID != "" {
		return fmt.Sprintf("HTTP %d %s (request %s)", e.Status, message, e.RequestID)
	}
	return fmt.Sprintf("HTTP %d %s", e.Status, message)
}

func (c *client) get(ctx context.Context, path string, params url.Values) ([]byte, error) {
	return c.send(ctx, http.MethodGet, path, params, nil)
}

func (c *client) post(ctx context.Context, path string, value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return c.send(ctx, http.MethodPost, path, url.Values{}, body)
}

func (c *client) send(ctx context.Context, method, path string, params url.Values, payload []byte) ([]byte, error) {
	u := *c.base
	u.Path = strings.TrimRight(c.base.Path, "/") + path
	u.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Guiliu-Client", clientHeader)
	req.Header.Set("User-Agent", "guiliu-cli/"+c.version)
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxResponse+1))
	if err != nil {
		return nil, err
	}
	if len(body) > defaultMaxResponse {
		return nil, fmt.Errorf("response exceeds %d bytes; narrow the query", defaultMaxResponse)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, decodeAPIError(resp.StatusCode, resp.Header.Get("X-Request-ID"), body)
	}
	return body, nil
}

func decodeAPIError(status int, requestID string, body []byte) error {
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Error.Message != "" {
		return &apiError{Status: status, Code: payload.Error.Code, Message: payload.Error.Message, RequestID: requestID}
	}
	message := strings.TrimSpace(string(body))
	if len(message) > 200 {
		message = message[:200] + "…"
	}
	if message == "" {
		message = http.StatusText(status)
	}
	return &apiError{Status: status, Message: message, RequestID: requestID}
}

func decode[T any](body []byte) (T, error) {
	var value T
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return value, fmt.Errorf("decode response: %w", err)
	}
	if len(bytes.TrimSpace(body[dec.InputOffset():])) > 0 {
		return value, fmt.Errorf("decode response: unexpected trailing data")
	}
	return value, nil
}

func emitJSON(w io.Writer, body []byte, pretty bool) error {
	if pretty {
		var buf bytes.Buffer
		if err := json.Indent(&buf, bytes.TrimSpace(body), "", "  "); err != nil {
			return fmt.Errorf("format JSON: %w", err)
		}
		body = append(buf.Bytes(), '\n')
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		body = append(body, '\n')
	}
	_, err := w.Write(body)
	return err
}

func emitNDJSON[T any](w io.Writer, items []T, fields string) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, item := range items {
		var output any = item
		if fields != "" {
			data, err := json.Marshal(item)
			if err != nil {
				return err
			}
			output, err = projectJSON(data, fields)
			if err != nil {
				return err
			}
		}
		if err := enc.Encode(output); err != nil {
			return err
		}
	}
	return nil
}

func emitRaw(w io.Writer, body []byte) error {
	if _, err := w.Write(body); err != nil {
		return err
	}
	if len(body) == 0 || body[len(body)-1] != '\n' {
		_, err := w.Write([]byte("\n"))
		return err
	}
	return nil
}

type usageError struct {
	message string
}

func (e *usageError) Error() string { return e.message }

func usagef(format string, args ...any) error {
	return &usageError{message: fmt.Sprintf(format, args...)}
}

func isUsageError(err error) bool {
	var target *usageError
	return errors.As(err, &target)
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func readAPIKeyFile(path string, stderr io.Writer) (string, error) {
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(stderr, "warning: %s is readable by other users; use chmod 600\n", path)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read API key file: %w", err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", errors.New("API key file is empty")
	}
	return key, nil
}
