package query

import "testing"

func TestStatsOptionsBoundDimensionsAndResultSize(t *testing.T) {
	for _, tc := range []struct{ keys, n string }{{"title,", "20"}, {"source_ip;DROP TABLE alerts", "1"}, {"title", "0"}, {"title", "101"}, {"title", "1.5"}} {
		if _, err := ParseStatsOptions(tc.keys, tc.n); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
	o, err := ParseStatsOptions("title,title, source_ip", "2")
	if err != nil || len(o.TopBy) != 2 || o.TopN != 2 {
		t.Fatalf("%+v %v", o, err)
	}
}
