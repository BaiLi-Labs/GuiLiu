package elasticsearch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

type searchResponse struct {
	PIT      string `json:"pit_id"`
	TimedOut bool   `json:"timed_out"`
	Shards   struct {
		Failed int `json:"failed"`
	} `json:"_shards"`
	Hits *struct {
		Total   json.RawMessage `json:"total"`
		Records []hit           `json:"hits"`
	} `json:"hits"`
	Aggregations *struct {
		Groups *struct {
			Buckets []struct {
				Key   any   `json:"key"`
				Count int64 `json:"doc_count"`
			} `json:"buckets"`
			Other int64 `json:"sum_other_doc_count"`
			Error int64 `json:"doc_count_error_upper_bound"`
		} `json:"groups"`
	} `json:"aggregations"`
}

type pageToken struct {
	PIT   string            `json:"pit"`
	After []json.RawMessage `json:"after"`
}

func (c *Connector) filters(q model.EventSearch) ([]any, error) {
	start, err := time.Parse(time.RFC3339Nano, q.Start)
	if err != nil {
		return nil, connector.ConfigError(descriptor.ID, "invalid query start")
	}
	end, err := time.Parse(time.RFC3339Nano, q.End)
	if err != nil {
		return nil, connector.ConfigError(descriptor.ID, "invalid query end")
	}
	var lo, hi any = start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano)
	if c.format == "epoch_millis" {
		lo, hi = start.UnixMilli(), end.UnixMilli()
	}
	if c.format == "epoch_seconds" {
		lo, hi = start.Unix(), end.Unix()
	}
	filters := []any{map[string]any{"range": map[string]any{c.mapping["event_time"]: map[string]any{"gte": lo, "lte": hi}}}}
	if q.Keyword != "" {
		path := c.mapping["message"]
		if path == "" {
			return nil, connector.ConfigError(descriptor.ID, "keyword requires a message field mapping")
		}
		filters = append(filters, map[string]any{"match_phrase": map[string]any{path: q.Keyword}})
	}
	for _, exact := range []struct{ key, value string }{{"host_names", q.Host}, {"users", q.User}} {
		if exact.value == "" {
			continue
		}
		path := c.mapping[exact.key]
		if path == "" {
			return nil, connector.ConfigError(descriptor.ID, "requested filter has no configured field mapping")
		}
		filters = append(filters, map[string]any{"term": map[string]any{path: exact.value}})
	}
	if q.IP != "" {
		should := []any{}
		for _, key := range []string{"source_ips", "destination_ips"} {
			if path := c.mapping[key]; path != "" {
				should = append(should, map[string]any{"term": map[string]any{path: q.IP}})
			}
		}
		if len(should) == 0 {
			return nil, connector.ConfigError(descriptor.ID, "ip filter has no configured IP field mapping")
		}
		filters = append(filters, map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}})
	}
	keys := make([]string, 0, len(q.Filters))
	for key := range q.Filters {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		filters = append(filters, map[string]any{"term": map[string]any{key: q.Filters[key]}})
	}
	return filters, nil
}

func (c *Connector) closePIT(id string) {
	if id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.request(ctx, http.MethodDelete, "_pit", map[string]any{"id": id}, nil)
}

func (c *Connector) SearchEvents(ctx context.Context, q model.EventSearch, token json.RawMessage) (*model.EventPage, error) {
	filters, err := c.filters(q)
	if err != nil {
		return nil, err
	}
	if q.Limit < 1 || q.Limit > 200 {
		return nil, connector.ConfigError(descriptor.ID, "invalid event page size")
	}
	var cursor pageToken
	if len(token) > 0 {
		if json.Unmarshal(token, &cursor) != nil || cursor.PIT == "" || len(cursor.After) == 0 {
			return nil, connector.ConfigError(descriptor.ID, "invalid source cursor")
		}
	} else {
		var pit struct {
			ID string `json:"id"`
		}
		// keep_alive is an API query parameter, not a JSON body option.
		if err := c.openPIT(ctx, &pit); err != nil {
			return nil, err
		}
		if pit.ID == "" {
			return nil, c.failure(connector.KindPermanent, "invalid_response", "Elasticsearch did not return a point-in-time id; Elasticsearch 7.12+ is required", 0)
		}
		cursor.PIT = pit.ID
	}
	keep := false
	defer func() {
		if !keep {
			c.closePIT(cursor.PIT)
		}
	}()
	body := map[string]any{
		"size": q.Limit + 1, "query": map[string]any{"bool": map[string]any{"filter": filters}},
		"pit": map[string]any{"id": cursor.PIT, "keep_alive": "2m"}, "sort": []any{map[string]any{c.mapping["event_time"]: "asc"}, map[string]any{"_shard_doc": "asc"}},
		"timeout": "10s", "track_total_hits": 10000, "_source": true, "stored_fields": []string{"_routing"},
	}
	if len(cursor.After) > 0 {
		body["search_after"] = cursor.After
	}
	if c.format == "date" {
		// Normalize date/date_nanos sort values across a mixed index scope.
		body["sort"] = []any{map[string]any{c.mapping["event_time"]: map[string]any{"order": "asc", "format": "strict_date_optional_time_nanos", "numeric_type": "date_nanos"}}, map[string]any{"_shard_doc": "asc"}}
	}
	if q.GroupBy != "" {
		body["aggs"] = map[string]any{"groups": map[string]any{"terms": map[string]any{"field": q.GroupBy, "size": q.TopN, "show_term_doc_count_error": true}}}
	}
	var response searchResponse
	if err := c.request(ctx, http.MethodPost, "_search", body, &response); err != nil {
		return nil, err
	}
	if response.PIT != "" {
		cursor.PIT = response.PIT
	}
	if response.Hits == nil {
		return nil, c.failure(connector.KindPermanent, "invalid_response", "Elasticsearch omitted search hits", 0)
	}
	page := &model.EventPage{Events: []model.Event{}, AccountID: c.cfg.AccountID, Provider: descriptor.ID, Indices: c.indices, MapperVersion: mapperVersion, FieldMapping: c.mapping, ObservedAt: time.Now().UTC(),
		Coverage: model.EventQueryCoverage{ExecutionComplete: !response.TimedOut && response.Shards.Failed == 0, Consistency: "point_in_time", TimedOut: response.TimedOut, FailedShards: response.Shards.Failed,
			Limitations: []string{"remote_query_only", "upstream_permissions_and_retention", "not_proof_of_event_delivery", "no_local_revision_or_change_feed", "remote_evidence_can_change_or_expire", "keyword_uses_source_match_phrase_analyzer", "exact_filters_use_source_term_semantics"}}}
	if c.base.Scheme == "http" {
		page.Coverage.Limitations = append(page.Coverage.Limitations, "upstream_transport_unencrypted")
	}
	if json.Unmarshal(response.Hits.Total, &page.Total) != nil {
		if json.Unmarshal(response.Hits.Total, &page.Total.Value) != nil {
			return nil, c.failure(connector.KindPermanent, "invalid_response", "Elasticsearch omitted the total hit count", 0)
		}
		page.Total.Relation = "eq"
	}
	if page.Total.Relation != "eq" && page.Total.Relation != "gte" {
		return nil, c.failure(connector.KindPermanent, "invalid_response", "Elasticsearch returned an unknown hit count relation", 0)
	}
	records := response.Hits.Records
	page.HasMore = len(records) > q.Limit && page.Coverage.ExecutionComplete
	if len(records) > q.Limit {
		records = records[:q.Limit]
	}
	for _, h := range records {
		event, err := c.normalize(h)
		if err != nil {
			return nil, err
		}
		page.Events = append(page.Events, event)
	}
	if page.HasMore {
		cursor.After = records[len(records)-1].Sort
		if len(cursor.After) != 2 {
			return nil, c.failure(connector.KindPermanent, "invalid_response", "Elasticsearch omitted stable sort values", 0)
		}
		page.Continuation, _ = json.Marshal(cursor)
	}
	if !page.Coverage.ExecutionComplete {
		page.Coverage.Limitations = append(page.Coverage.Limitations, "partial_results_not_pageable")
	}
	if q.GroupBy != "" {
		if response.Aggregations == nil || response.Aggregations.Groups == nil {
			return nil, c.failure(connector.KindPermanent, "invalid_response", "Elasticsearch omitted the requested aggregation", 0)
		}
		g := response.Aggregations.Groups
		page.Aggregation = &model.EventAggregation{Field: q.GroupBy, Buckets: []model.EventBucket{}, OtherDocumentCount: g.Other, DocumentCountErrorBound: g.Error}
		for _, bucket := range g.Buckets {
			page.Aggregation.Buckets = append(page.Aggregation.Buckets, model.EventBucket{Value: fmt.Sprint(bucket.Key), Count: bucket.Count})
		}
	}
	keep = page.HasMore
	return page, nil
}

func (c *Connector) EventEvidence(ctx context.Context, ref model.EventReference) (*model.EventEvidence, error) {
	filters := []any{map[string]any{"term": map[string]any{"_index": ref.Index}}, map[string]any{"ids": map[string]any{"values": []string{ref.ID}}}}
	if ref.Routing != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"_routing": ref.Routing}})
	}
	var response searchResponse
	// Always search THROUGH the configured scope, even when an alias points to
	// a differently named backing index. A caller cannot expand alias filters.
	if err := c.request(ctx, http.MethodPost, c.scopePath("_search"), map[string]any{"size": 2, "query": map[string]any{"bool": map[string]any{"filter": filters}}, "_source": true, "stored_fields": []string{"_routing"}, "timeout": "10s"}, &response); err != nil {
		return nil, err
	}
	if response.TimedOut || response.Shards.Failed > 0 {
		return nil, c.failure(connector.KindTransient, "partial_search", "event evidence query was incomplete", 0)
	}
	if response.Hits == nil {
		return nil, c.failure(connector.KindPermanent, "invalid_response", "Elasticsearch omitted search hits", 0)
	}
	if len(response.Hits.Records) == 0 {
		return nil, c.failure(connector.KindNotFound, "event_not_found", "event is no longer available in the configured source scope", 404)
	}
	if len(response.Hits.Records) > 1 {
		return nil, c.failure(connector.KindPermanent, "ambiguous_event", "document id is ambiguous; include routing from the event reference", 0)
	}
	h := response.Hits.Records[0]
	e, err := c.normalize(h)
	if err != nil {
		return nil, err
	}
	return &model.EventEvidence{Event: e, Raw: h.Source, RawHash: e.Evidence.RawHash, Changed: ref.RawHash != "" && ref.RawHash != e.Evidence.RawHash, HashCompared: ref.RawHash != "", ObservedAt: time.Now().UTC(), Representation: "elasticsearch_source_json; SHA-256 over canonical JSON", Limitations: []string{"current_upstream_representation", "not_immutable_local_evidence", "not_original_event_bytes"}}, nil
}

func (c *Connector) EventFields(ctx context.Context) (*model.EventFields, error) {
	var response struct {
		Fields map[string]map[string]struct {
			Searchable      bool     `json:"searchable"`
			Aggregatable    bool     `json:"aggregatable"`
			NonSearchable   []string `json:"non_searchable_indices"`
			NonAggregatable []string `json:"non_aggregatable_indices"`
		} `json:"fields"`
	}
	if err := c.request(ctx, http.MethodPost, c.scopePath("_field_caps"), map[string]any{"fields": []string{"*"}}, &response); err != nil {
		return nil, err
	}
	if response.Fields == nil {
		return nil, c.failure(connector.KindPermanent, "invalid_response", "Elasticsearch omitted field capabilities", 0)
	}
	result := &model.EventFields{AccountID: c.cfg.AccountID, Provider: descriptor.ID, Indices: c.indices, Mapping: c.mapping, MapperVersion: mapperVersion, Fields: []model.EventField{}, Limitations: []string{"metadata_requires_view_index_metadata", "field_capabilities_are_current_not_pit_versioned", "term_filters_require_exact_source_field_semantics"}}
	names := make([]string, 0, len(response.Fields))
	for name := range response.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > 500 {
		names = names[:500]
		result.Truncated = true
	}
	for _, name := range names {
		f := model.EventField{Name: name, Types: []string{}, Searchable: true, Aggregatable: true}
		for typ, caps := range response.Fields[name] {
			f.Types = append(f.Types, typ)
			f.Searchable = f.Searchable && caps.Searchable && len(caps.NonSearchable) == 0
			f.Aggregatable = f.Aggregatable && caps.Aggregatable && len(caps.NonAggregatable) == 0
		}
		sort.Strings(f.Types)
		f.Conflicting = len(f.Types) > 1
		result.Fields = append(result.Fields, f)
	}
	return result, nil
}
