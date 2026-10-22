package model

import (
	"fmt"
	"strings"
)

const StatsDefaultTopN = 20
const StatsMaxTopN = 100
const StatsDimensions = "title,source_ip,destination_ip,source_country,severity,severity_day,provider,alert_type,rule_id"

type StatsOptions struct {
	TopBy []string
	TopN  int
}

func (o StatsOptions) Normalize() (StatsOptions, error) {
	if o.TopN == 0 {
		o.TopN = StatsDefaultTopN
	}
	if o.TopN < 1 || o.TopN > StatsMaxTopN {
		return o, fmt.Errorf("top_n must be between 1 and %d", StatsMaxTopN)
	}
	if len(o.TopBy) == 0 {
		o.TopBy = []string{"title", "source_ip", "source_country"}
	}
	seen := map[string]bool{}
	keys := []string{}
	for _, key := range o.TopBy {
		key = strings.TrimSpace(key)
		valid := false
		for _, candidate := range strings.Split(StatsDimensions, ",") {
			if key == candidate {
				valid = true
				break
			}
		}
		if !valid {
			return o, fmt.Errorf("unknown top_by %q; use %s", key, StatsDimensions)
		}
		if !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	o.TopBy = keys
	return o, nil
}

type DistributionCount struct {
	Key      string `json:"key"`
	Severity string `json:"severity,omitempty"`
	Count    int    `json:"count"`
}

// Every count refers to stored Findings at the requested snapshot, not attacks.
type FieldDistribution struct {
	DistinctCount int                 `json:"distinct_count"`
	MissingCount  int                 `json:"missing_count"`
	Top           []DistributionCount `json:"top"`
	TopN          int                 `json:"top_n"`
	OtherCount    int                 `json:"other_count"`
	HasMore       bool                `json:"has_more"`
}
