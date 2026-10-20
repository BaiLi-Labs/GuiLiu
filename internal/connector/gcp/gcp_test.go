package gcp

import (
	"strings"
	"testing"
	"time"
)

func TestFindingFilterIncludesInactiveFindings(t *testing.T) {
	start := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	filter := findingFilter(start, end)
	if strings.Contains(filter, "state") {
		t.Fatalf("filter must not drop non-ACTIVE findings: %s", filter)
	}
	if !strings.Contains(filter, `event_time >= "2026-10-20T00:00:00Z"`) ||
		!strings.Contains(filter, `event_time < "2026-10-20T01:00:00Z"`) {
		t.Fatalf("unexpected time filter: %s", filter)
	}
}
