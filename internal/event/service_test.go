package event

import (
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestNormalizeBoundariesAndPinnedTime(t *testing.T) {
	now := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	q, err := Normalize(model.EventSearch{AccountID: "source"}, now)
	if err != nil || q.Start != "2026-10-26T00:00:00Z" || q.End != "2026-10-27T00:00:00Z" || q.Limit != 20 {
		t.Fatalf("defaults: %+v %v", q, err)
	}
	for _, bad := range []model.EventSearch{
		{}, {AccountID: "source", Limit: 201}, {AccountID: "source", IP: "not-an-ip"},
		{AccountID: "source", Since: "91d"}, {AccountID: "source", Start: "2026-10-27", Since: "1h"},
		{AccountID: "source", Filters: map[string]string{"_index": "other"}},
		{AccountID: "source", Filters: map[string]string{"message;script": "bad"}},
		{AccountID: "source", TopN: 5}, {AccountID: "source", GroupBy: "source.ip", TopN: 51},
	} {
		if _, err := Normalize(bad, now); err == nil {
			t.Errorf("accepted invalid query: %+v", bad)
		}
	}
}
