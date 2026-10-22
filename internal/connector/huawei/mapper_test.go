package huawei

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
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
	if alert.VendorStatus != "Open" {
		t.Fatalf("status = %q", alert.VendorStatus)
	}
	if alert.SourceIP != "203.0.113.10" || alert.DestinationIP != "10.0.0.5" {
		t.Fatalf("ips = %s -> %s", alert.SourceIP, alert.DestinationIP)
	}
	if alert.Resource.ID != "ecs-1" || alert.Resource.Name != "web-01" || alert.Resource.Type != "ecs" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	if alert.Resource.Source != model.ResourceSourceVendorDeclared {
		t.Fatalf("resource name must be marked as vendor declared: %+v", alert.Resource)
	}
	if alert.CloudAccountUID != "domain-1" || alert.Region != "cn-north-4" {
		t.Fatalf("account/region = %s / %s", alert.CloudAccountUID, alert.Region)
	}
	if alert.Product != "HSS" || alert.AlertType != "Host/BruteForce" {
		t.Fatalf("product/type = %s / %s", alert.Product, alert.AlertType)
	}
	if !alert.EventTime.Equal(time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("event time = %s", alert.EventTime)
	}
	if len(alert.Observables) < 3 || len(alert.Evidences) != 1 {
		t.Fatalf("observables/evidence = %d / %d", len(alert.Observables), len(alert.Evidences))
	}
}

func TestEnvelopeAndMultipleResources(t *testing.T) {
	raw := json.RawMessage(`{"id":"envelope-id","project_id":"p","workspace_id":"w","data_object":{"id":"alert-id","actor":"vendor-user","resource_list":[{"id":"one"},{"id":"two"}],"network_list":[{"src_ip":"203.0.113.1"},{"src_ip":"203.0.113.2","dest_ip":"10.0.0.1"}]}}`)
	alert, err := (&Connector{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "alert-id" || alert.Actor != "vendor-user" || len(alert.Resources) != 2 || string(alert.Raw) != string(raw) {
		t.Fatalf("alert=%+v", alert)
	}
	values := map[string]bool{}
	for _, o := range alert.Observables {
		values[o.Value] = true
	}
	if !values["two"] || !values["203.0.113.2"] {
		t.Fatalf("secondary values lost: %+v", alert.Observables)
	}
	if _, err := (&Connector{}).Normalize(json.RawMessage(`{"data_object":null}`)); err == nil {
		t.Fatal("missing data_object accepted")
	}
}
