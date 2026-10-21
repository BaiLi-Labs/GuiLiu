package query

import (
	"errors"
	"fmt"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/timeutil"
)

// Agent-facing query bounds. The raw REST API accepts explicit ranges; MCP
// tools and the query CLI apply the same bounded defaults so an agent cannot
// accidentally request an unbounded history.
const (
	AgentMaxRange    = 90 * 24 * time.Hour
	AgentAlertWindow = 7 * 24 * time.Hour
	AgentGroupWindow = 24 * time.Hour
)

// ResolveWindow converts start/end/since into absolute bounds. A relative
// "since" is resolved against now once, so callers can reuse the returned
// bounds for stable pagination. At most one of start and since may be set.
func ResolveWindow(startRaw, endRaw, sinceRaw string, defaultWindow time.Duration, now time.Time) (*time.Time, *time.Time, error) {
	if defaultWindow <= 0 {
		defaultWindow = AgentAlertWindow
	}
	now = now.UTC()
	var start, end *time.Time
	if startRaw != "" {
		t, ok := timeutil.Parse(startRaw)
		if !ok {
			return nil, nil, fmt.Errorf("invalid start %q", startRaw)
		}
		start = &t
	}
	if endRaw != "" {
		t, ok := timeutil.Parse(endRaw)
		if !ok {
			return nil, nil, fmt.Errorf("invalid end %q", endRaw)
		}
		end = &t
	}
	if sinceRaw != "" {
		if start != nil {
			return nil, nil, errors.New("use start or since, not both")
		}
		d, ok := timeutil.ParseDuration(sinceRaw)
		if !ok {
			return nil, nil, fmt.Errorf("invalid since %q", sinceRaw)
		}
		t := now.Add(-d)
		start = &t
		if end == nil {
			e := now
			end = &e
		}
	}
	if start != nil && end == nil {
		e := now
		end = &e
	}
	if end == nil {
		e := now
		end = &e
	}
	if start == nil {
		s := end.Add(-defaultWindow)
		start = &s
	}
	if end.Before(*start) {
		return nil, nil, errors.New("end must be after start")
	}
	if end.Sub(*start) > AgentMaxRange {
		return nil, nil, fmt.Errorf("time range exceeds %s; narrow the query", AgentMaxRange)
	}
	return start, end, nil
}
