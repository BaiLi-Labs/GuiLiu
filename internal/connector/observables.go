package connector

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// ObservableCollector captures field locations at extraction time. Identical
// values in unrelated fields never establish provenance. Repeated occurrences
// of the same typed role merge their explicitly supplied source locations.
type ObservableCollector struct {
	raw    any
	prefix string
	items  []model.Observable
	index  map[string]int
}

func NewObservableCollector(raw json.RawMessage) *ObservableCollector {
	c := &ObservableCollector{index: map[string]int{}}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	_ = decoder.Decode(&c.raw)
	c.prefix = sourceObjectPrefix(c.raw)
	return c
}

// Add paths are relative to the vendor finding object inside its API envelope.
func (c *ObservableCollector) Add(name string, typeID int, value string, paths ...string) {
	resolved := make([]string, len(paths))
	for i, path := range paths {
		resolved[i] = c.prefix + path
	}
	c.AddRoot(name, typeID, value, resolved...)
}

// AddRoot addresses envelope context, such as GCP ListFindingsResult.resource.
func (c *ObservableCollector) AddRoot(name string, typeID int, value string, paths ...string) {
	if value == "" {
		return
	}
	key := fmt.Sprintf("%d\x00%s\x00%s", typeID, name, value)
	i, ok := c.index[key]
	if !ok {
		i = len(c.items)
		c.index[key] = i
		c.items = append(c.items, model.Observable{Name: name, TypeID: typeID, Value: value})
	}
	for _, path := range paths {
		for _, concrete := range expandPointer(c.raw, strings.Split(strings.TrimPrefix(path, "/"), "/"), "") {
			leaf := pointerValue(c.raw, concrete)
			var text string
			switch v := leaf.(type) {
			case string:
				text = v
			case json.Number:
				text = v.String()
			}
			if text != value {
				continue
			}
			found := false
			for _, existing := range c.items[i].SourcePaths {
				found = found || existing == concrete
			}
			if !found {
				c.items[i].SourcePaths = append(c.items[i].SourcePaths, concrete)
			}
		}
	}
	sort.Strings(c.items[i].SourcePaths)
}

func (c *ObservableCollector) Values() []model.Observable { return c.items }

func sourceObjectPrefix(raw any) string {
	if m, ok := raw.(map[string]any); ok {
		if m["finding"] != nil {
			return "/finding"
		}
		if m["data_object"] != nil {
			return "/data_object"
		}
	}
	return ""
}

func pointerValue(raw any, pointer string) any {
	value := raw
	for _, part := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch v := value.(type) {
		case map[string]any:
			value = v[part]
		case []any:
			i, err := strconv.Atoi(part)
			if err != nil || i < 0 || i >= len(v) {
				return nil
			}
			value = v[i]
		default:
			return nil
		}
	}
	return value
}
