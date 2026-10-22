package query

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// Shared REST/MCP/CLI validation. The bounded allowlist never accepts SQL.
func ParseStatsOptions(topBy, topN string) (model.StatsOptions, error) {
	o := model.StatsOptions{}
	if topBy != "" {
		o.TopBy = strings.Split(topBy, ",")
	}
	if topN != "" {
		n, err := strconv.Atoi(topN)
		if err != nil || n < 1 {
			return o, fmt.Errorf("top_n must be between 1 and %d", model.StatsMaxTopN)
		}
		o.TopN = n
	}
	return o.Normalize()
}
