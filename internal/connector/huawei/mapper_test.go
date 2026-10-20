package huawei

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNormalizeHuaweiAlert(t *testing.T) {
	raw := json.RawMessage(`{
	  "id": "huawei-1",
	  "title": "SSH 暴力破解",
	  "description": "短时间内大量 SSH 登录失败",
	  "severity": "High",
	  "handle_status": "Open",
	  "create_time": "2026-10-20T10:00:00.000+08:00",
	  "first_observed_time": "2026-10-20T10:00:00.000+08:00",
	  "last_observed_time": "2026-10-20T10:05:00.000+08:00",
	  "region_id": "cn-north-4",
	  "domain_id": "domain-1",
	  "alert_type": {"category": "Host", "alert_type": "BruteForce"},
	  "data_source": {"product_name": "HSS"},
	  "network_list": [{"src_ip": "203.0.113.10", "src_port": 4444, "dest_ip": "10.0.0.5", "dest_port": "22"}],
	  "resource_list": [{"id": "ecs-1", "name": "web-01", "type": "ecs", "region_id": "cn-north-4"}],
	  "count": 12,
	  "confidence": 90,
	  "criticality": 80,
	  "malware": {"malware_family": "MockFamily", "malware_class": "MockClass"}
	}`)
	alert, err := (&Connector{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "huawei-1" || alert.Title != "SSH 暴力破解" {
		t.Fatalf("identity = %+v", alert)
	}
	if alert.Severity.String() != "high" || alert.OriginalSeverity != "High" {
		t.Fatalf("severity = %s / %s", alert.Severity, alert.OriginalSeverity)
	}
	if alert.VendorStatus != "unhandled" {
		t.Fatalf("status = %q", alert.VendorStatus)
	}
	if alert.SourceIP != "203.0.113.10" || alert.DestinationIP != "10.0.0.5" {
		t.Fatalf("ips = %s -> %s", alert.SourceIP, alert.DestinationIP)
	}
	if alert.Resource.ID != "ecs-1" || alert.Resource.Name != "web-01" || alert.Resource.Type != "ecs" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	if alert.CloudAccountUID != "domain-1" || alert.Region != "cn-north-4" {
		t.Fatalf("account/region = %s / %s", alert.CloudAccountUID, alert.Region)
	}
	if alert.Product != "HSS" || alert.AlertType != "Host/BruteForce" {
		t.Fatalf("product/type = %s / %s", alert.Product, alert.AlertType)
	}
	if !alert.EventTime.Equal(time.Date(2026, 10, 20, 2, 5, 0, 0, time.UTC)) {
		t.Fatalf("event time = %s", alert.EventTime)
	}
	if len(alert.Observables) < 3 || len(alert.Evidences) != 1 {
		t.Fatalf("observables/evidence = %d / %d", len(alert.Observables), len(alert.Evidences))
	}
}
