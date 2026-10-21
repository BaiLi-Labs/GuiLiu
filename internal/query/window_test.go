package query

import (
	"strings"
	"testing"
	"time"
)

func TestResolveWindowAgentDefaultsAndBounds(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

	start, end, err := ResolveWindow("", "", "", AgentAlertWindow, now)
	if err != nil {
		t.Fatal(err)
	}
	if !end.Equal(now) || !start.Equal(now.Add(-7*24*time.Hour)) {
		t.Fatalf("default window: %s .. %s", start, end)
	}

	start, end, err = ResolveWindow("", "", "24h", AgentAlertWindow, now)
	if err != nil {
		t.Fatal(err)
	}
	if !start.Equal(now.Add(-24*time.Hour)) || !end.Equal(now) {
		t.Fatalf("since window: %s .. %s", start, end)
	}

	start, end, err = ResolveWindow("2026-10-20", "", "", AgentAlertWindow, now)
	if err != nil {
		t.Fatal(err)
	}
	if !start.Equal(time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)) || !end.Equal(now) {
		t.Fatalf("start-only window: %s .. %s", start, end)
	}

	start, end, err = ResolveWindow("", "2026-10-21", "", AgentAlertWindow, now)
	if err != nil {
		t.Fatal(err)
	}
	if !end.Equal(time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)) || !start.Equal(end.Add(-AgentAlertWindow)) {
		t.Fatalf("end-only window: %s .. %s", start, end)
	}
}

func TestResolveWindowRejectsInvalidRanges(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, start, end, since, want string
	}{
		{"start and since", "2026-10-20", "", "24h", "use start or since"},
		{"backwards", "2026-10-21", "2026-10-20", "", "end must be after start"},
		{"too wide", "2026-01-01", "2026-10-21", "", "time range exceeds"},
		{"bad start", "nope", "", "", "invalid start"},
		{"bad since", "", "", "nope", "invalid since"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ResolveWindow(tc.start, tc.end, tc.since, AgentAlertWindow, now)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
