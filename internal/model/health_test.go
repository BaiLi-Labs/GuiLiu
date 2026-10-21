package model

import (
	"testing"
	"time"
)

func TestSyncHealth(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-24 * time.Hour)
	for _, tc := range []struct {
		name  string
		state SyncState
		want  string
	}{
		{"new", SyncState{}, "never_synced"},
		{"fresh", SyncState{CursorEnd: now, LastSuccessAt: &now}, "healthy"},
		{"stopped", SyncState{CursorEnd: now, LastSuccessAt: &old}, "stale"},
		{"behind", SyncState{CursorEnd: old, LastSuccessAt: &now}, "stale"},
		{"throttled", SyncState{CursorEnd: now, LastSuccessAt: &now, LastError: "throttled"}, "failed"},
		{"backfill", SyncState{PendingEnd: now}, "pending"},
		{"mapping failures", SyncState{CursorEnd: now, LastSuccessAt: &now, FailedRecords: 1}, "partial"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.state.Health(now, 15*time.Minute); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}
