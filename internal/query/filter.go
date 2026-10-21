package query

import (
	"fmt"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func ValidateFilter(f model.AlertFilter) error {
	switch f.FindingKind {
	case "", model.FindingDetection, model.FindingVulnerability, model.FindingCompliance, model.FindingIncident, model.FindingOther:
	default:
		return fmt.Errorf("unknown finding_kind %q", f.FindingKind)
	}
	switch f.Sort {
	case "", "id", "event_time", "severity", "severity_id", "last_seen", "last_seen_at", "first_seen", "first_seen_at":
	default:
		return fmt.Errorf("unknown sort %q", f.Sort)
	}
	switch f.TimeField {
	case "", "event_time", "source_updated_at", "ingested_at":
	default:
		return fmt.Errorf("unknown time_field %q", f.TimeField)
	}
	if f.ObservableType != nil && f.ObservableValue == "" {
		return fmt.Errorf("observable_value is required with observable_type")
	}
	if f.AfterID != "" && f.Offset != 0 {
		return fmt.Errorf("after_id and offset cannot be combined")
	}
	if len(f.GroupKey) > 0 && f.GroupBy == "" {
		return fmt.Errorf("group_by is required with group_key")
	}
	if len(f.GroupKey) > 0 && f.GroupKey["singleton"] == "" {
		required := map[model.AlertGroupBy][]string{
			model.GroupByTypeAsset: {"provider", "account_id", "region", "product", "alert_type", "resource_id"},
			model.GroupBySignature: {"provider", "account_id", "account_uid", "region", "product", "rule_id", "resource_id", "source_ip"},
			model.GroupByAsset:     {"provider", "account_id", "region", "resource_id"}, model.GroupBySource: {"source_ip", "alert_type"},
		}
		for _, key := range required[f.GroupBy] {
			if _, ok := f.GroupKey[key]; !ok {
				return fmt.Errorf("group_key missing %s", key)
			}
		}
	}
	return nil
}
