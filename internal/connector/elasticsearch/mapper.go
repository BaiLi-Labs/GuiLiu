package elasticsearch

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

type hit struct {
	Index   string              `json:"_index"`
	ID      string              `json:"_id"`
	Routing string              `json:"_routing"`
	Source  json.RawMessage     `json:"_source"`
	Sort    []json.RawMessage   `json:"sort"`
	Fields  map[string][]string `json:"fields"`
}

func sourceObject(raw json.RawMessage) (map[string]any, error) {
	var obj map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&obj); err != nil || obj == nil {
		return nil, fmt.Errorf("source is not a JSON object")
	}
	return obj, nil
}

func sourceHash(obj map[string]any) string {
	canonical, _ := json.Marshal(obj)
	return fmt.Sprintf("%x", sha256.Sum256(canonical))
}

// Prefer a literal dotted key, then traverse nested objects and arrays. Both
// flattened ECS documents and object-based documents retain the same paths.
func lookup(value any, path string) any {
	if obj, ok := value.(map[string]any); ok {
		if v, exists := obj[path]; exists {
			return v
		}
		parts := strings.SplitN(path, ".", 2)
		if len(parts) == 1 {
			return obj[path]
		}
		return lookup(obj[parts[0]], parts[1])
	}
	if list, ok := value.([]any); ok {
		out := []any{}
		for _, item := range list {
			if v := lookup(item, path); v != nil {
				out = append(out, v)
			}
		}
		return out
	}
	return nil
}

func values(v any) ([]string, bool) {
	out := []string{}
	valid := true
	var add func(any)
	add = func(v any) {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case json.Number:
			out = append(out, x.String())
		case []any:
			for _, item := range x {
				add(item)
			}
		case nil:
		default:
			valid = false
		}
	}
	add(v)
	return out, valid
}

func (c *Connector) normalize(h hit) (model.Event, error) {
	obj, err := sourceObject(h.Source)
	if err != nil || h.ID == "" || h.Index == "" {
		return model.Event{}, c.failure(connector.KindPermanent, "source_unavailable", "source document identity or _source is missing; enable source retrieval for this dataset", 0)
	}
	if h.Routing == "" && len(h.Fields["_routing"]) > 0 {
		h.Routing = h.Fields["_routing"][0]
	}
	identity, _ := json.Marshal([]string{c.cfg.AccountID, h.Index, h.ID, h.Routing})
	e := model.Event{ID: fmt.Sprintf("ese_%x", sha256.Sum256(identity)), Provider: descriptor.ID, AccountID: c.cfg.AccountID, FieldSources: map[string]string{},
		Evidence: model.EventReference{AccountID: c.cfg.AccountID, Index: h.Index, ID: h.ID, Routing: h.Routing, RawHash: sourceHash(obj)}}
	read := func(field string) []string {
		path := c.mapping[field]
		if path == "" {
			return nil
		}
		v := lookup(obj, path)
		if v == nil {
			return nil
		}
		list, valid := values(v)
		if !valid {
			e.MappingWarnings = append(e.MappingWarnings, field+":unsupported_source_type")
		}
		if len(list) > 64 {
			list = list[:64]
			e.MappingWarnings = append(e.MappingWarnings, field+":values_truncated")
		}
		for i, value := range list {
			if len(value) > 4096 {
				list[i] = string([]rune(value)[:min(len([]rune(value)), 1024)])
				e.MappingWarnings = append(e.MappingWarnings, field+":text_truncated")
			}
		}
		if len(list) > 0 {
			e.FieldSources[field] = path
		}
		return list
	}
	if ts := read("event_time"); len(ts) == 1 {
		if at, err := c.parseTime(ts[0]); err == nil {
			e.EventTime = &at
		} else {
			e.MappingWarnings = append(e.MappingWarnings, "event_time:invalid_timestamp")
		}
	} else if len(ts) > 1 {
		e.MappingWarnings = append(e.MappingWarnings, "event_time:multiple_timestamps")
	} else {
		e.MappingWarnings = append(e.MappingWarnings, "event_time:missing")
	}
	e.Message = strings.Join(read("message"), "\n")
	if len(e.Message) > 8192 {
		e.Message = string([]rune(e.Message)[:min(len([]rune(e.Message)), 2048)])
		e.MappingWarnings = append(e.MappingWarnings, "message:summary_truncated")
	}
	e.HostIDs, e.HostNames, e.Users = read("host_ids"), read("host_names"), read("users")
	e.Actions, e.Categories, e.Datasets = read("actions"), read("categories"), read("datasets")
	e.SourceSeverity = strings.Join(read("source_severity"), ",")
	ips := func(field string) []string {
		out := []string{}
		for _, value := range read(field) {
			if net.ParseIP(value) == nil {
				e.MappingWarnings = append(e.MappingWarnings, field+":invalid_ip")
				continue
			}
			out = append(out, value)
		}
		return out
	}
	e.SourceIPs, e.DestinationIPs = ips("source_ips"), ips("destination_ips")
	return e, nil
}

func (c *Connector) parseTime(value string) (time.Time, error) {
	if c.format == "date" {
		if at, err := time.Parse(time.RFC3339Nano, value); err == nil {
			return at.UTC(), nil
		}
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	at := time.UnixMilli(n)
	if c.format == "epoch_seconds" {
		at = time.Unix(n, 0)
	}
	if at.Year() < 1 || at.Year() > 9999 {
		return time.Time{}, fmt.Errorf("timestamp out of range")
	}
	return at.UTC(), nil
}
