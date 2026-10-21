package aws

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNormalizeAWSOCSFFinding(t *testing.T) {
	raw := json.RawMessage(`{
	  "class_uid": 2004,
	  "activity_name": "Create",
	  "severity_id": 4,
	  "severity": "High",
	  "time": 1792480865000,
	  "status": "New",
	  "finding_info": {
	    "uid": "aws-1",
	    "title": "GuardDuty: UnauthorizedAccess",
	    "desc": "EC2 instance queried instance metadata from an unusual location",
	    "types": ["TTPs"],
	    "created_time": 1792480000000,
	    "first_seen_time": 1792480000000,
	    "last_seen_time": 1792480865000
	  },
	  "cloud": {"provider": "AWS", "region": "us-east-1", "account": {"uid": "123456789012"}},
	  "metadata": {"product": {"vendor_name": "Amazon Web Services", "name": "GuardDuty"}, "original_time": "2026-10-20T10:01:05Z"},
	  "resources": [
	    {"uid": "arn:aws:ec2:us-east-1:123456789012:instance/i-123", "name": "i-123", "type": "Instance", "region": "us-east-1"},
	    {"uid": "secondary-resource", "name": "secondary-host", "type": "Instance"}
	  ],
	  "observables": [{"name": "src_endpoint.ip", "type_id": 2, "value": "203.0.113.9"}],
	  "evidences": [{"src_endpoint": {"ip": "203.0.113.9"}, "dst_endpoint": {"ip": "10.0.0.5"}}]
	}`)
	alert, err := (&Connector{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "aws-1" || alert.Title != "GuardDuty: UnauthorizedAccess" {
		t.Fatalf("identity = %+v", alert)
	}
	if alert.AlertType != "TTPs" {
		t.Fatalf("lifecycle activity replaced finding type: %s", alert.AlertType)
	}
	if alert.Severity.String() != "high" || alert.OriginalSeverity != "High" {
		t.Fatalf("severity = %s / %s", alert.Severity, alert.OriginalSeverity)
	}
	if alert.VendorStatus != "New" {
		t.Fatalf("status = %q", alert.VendorStatus)
	}
	if alert.SourceIP != "203.0.113.9" || alert.DestinationIP != "10.0.0.5" {
		t.Fatalf("ips = %s -> %s", alert.SourceIP, alert.DestinationIP)
	}
	if alert.Resource.ID == "" || alert.Resource.Name != "i-123" || alert.Resource.Type != "Instance" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	if len(alert.Resources) != 2 || alert.Resources[1].ID != "secondary-resource" {
		t.Fatalf("secondary resources lost: %+v", alert.Resources)
	}
	foundSecondary := false
	for _, o := range alert.Observables {
		if o.TypeID == 10 && o.Value == "secondary-resource" {
			foundSecondary = true
		}
	}
	if !foundSecondary {
		t.Fatal("secondary resource is not searchable")
	}
	if alert.CloudAccountUID != "123456789012" || alert.Region != "us-east-1" {
		t.Fatalf("account/region = %s / %s", alert.CloudAccountUID, alert.Region)
	}
	if !alert.EventTime.Equal(time.UnixMilli(1792480865000).UTC()) {
		t.Fatalf("event time = %s", alert.EventTime)
	}
	if len(alert.Observables) == 0 || len(alert.Evidences) == 0 {
		t.Fatalf("observables/evidence missing")
	}
}

func TestDatetimeFieldsAndMultipleTypes(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(`{"activity_name":"Create","time_dt":"2026-10-20T10:00:00.123Z","finding_info":{"uid":"a","created_time_dt":"2026-10-20T09:00:00.123Z","modified_time_dt":"2026-10-20T11:00:00.123Z","types":["type-a","type-b"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if alert.AlertType != "type-a, type-b" || !alert.EventTime.Equal(time.Date(2026, 10, 20, 10, 0, 0, 123000000, time.UTC)) || alert.SourceUpdatedAt.Sub(alert.SourceCreatedAt) != 2*time.Hour || !alert.LastSeenAt.IsZero() || !alert.FirstSeenAt.IsZero() {
		t.Fatalf("alert=%+v", alert)
	}
}
