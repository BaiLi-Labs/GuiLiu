package asset

import "testing"

// The four outcomes must stay distinguishable for an agent: a local scope
// rejection and a missing client are not source facts, while an authorized
// empty read is one.
func TestRefreshStatusesAreDistinct(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrNotVisible, "not_found_or_not_visible"},
		{ErrScopeMismatch, "scope_mismatch"},
		{ErrNotRequested, "not_requested"},
	}
	for _, c := range cases {
		if got := errorCode(c.err, "azure"); got != c.want {
			t.Fatalf("errorCode(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}
