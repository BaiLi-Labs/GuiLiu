package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
)

const maxResponse = 8 << 20

func (c *Connector) request(ctx context.Context, method, path string, body any, output any) error {
	return c.requestQuery(ctx, method, path, nil, body, output)
}

func (c *Connector) openPIT(ctx context.Context, output any) error {
	return c.requestQuery(ctx, http.MethodPost, c.scopePath("_pit"), url.Values{"keep_alive": {"2m"}}, nil, output)
}

func (c *Connector) requestQuery(ctx context.Context, method, path string, params url.Values, body any, output any) error {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + "/" + path
	u.RawPath = ""
	u.RawQuery = params.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
	if err != nil {
		return c.failure(connector.KindConfig, "request", "cannot construct Elasticsearch request", 0)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	switch c.auth {
	case "basic":
		req.SetBasicAuth(c.cfg.Credential.AccessKeyID, c.cfg.Credential.AccessKeySecret)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+c.cfg.Credential.AccessKeySecret)
	default:
		req.Header.Set("Authorization", "ApiKey "+c.cfg.Credential.AccessKeySecret)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return c.failure(connector.KindTransient, "transport", "Elasticsearch request failed; check connectivity and trusted certificates", 0)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		kind, code, message := connector.KindPermanent, "query_rejected", "Elasticsearch rejected the query; check field types, configured scope and Elasticsearch 7.12+ PIT support"
		switch resp.StatusCode {
		case 401:
			kind, code, message = connector.KindAuth, "authentication_failed", "Elasticsearch authentication failed"
		case 403:
			kind, code, message = connector.KindPermission, "permission_denied", "Elasticsearch denied access to the configured indices or metadata"
		case 404:
			kind, code, message = connector.KindNotFound, "source_not_found", "Elasticsearch index, document or query snapshot is unavailable; check scope or start a new query"
		case 429:
			kind, code, message = connector.KindThrottled, "rate_limited", "Elasticsearch is throttling requests"
		default:
			if resp.StatusCode >= 500 {
				kind, code, message = connector.KindTransient, "source_unavailable", "Elasticsearch is unavailable"
			}
		}
		// Upstream error bodies can contain credentials, queries and log text.
		return c.failure(kind, code, message, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return c.failure(connector.KindTransient, "response_read", "cannot read Elasticsearch response", 0)
	}
	if len(raw) > maxResponse {
		return c.failure(connector.KindPermanent, "response_limit", "Elasticsearch response exceeds 8 MiB; narrow the query or page size", 0)
	}
	if output == nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(output) != nil {
		return c.failure(connector.KindPermanent, "invalid_response", "Elasticsearch returned an invalid response", 0)
	}
	var trailing any
	if !errors.Is(dec.Decode(&trailing), io.EOF) {
		return c.failure(connector.KindPermanent, "invalid_response", "Elasticsearch returned trailing response data", 0)
	}
	return nil
}
