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
	  "resources": [{"uid": "arn:aws:ec2:us-east-1:123456789012:instance/i-123", "name": "i-123", "type": "Instance", "region": "us-east-1"}],
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
	if alert.Severity.String() != "high" || alert.OriginalSeverity != "High" {
		t.Fatalf("severity = %s / %s", alert.Severity, alert.OriginalSeverity)
	}
	if alert.VendorStatus != "new" {
		t.Fatalf("status = %q", alert.VendorStatus)
	}
	if alert.SourceIP != "203.0.113.9" || alert.DestinationIP != "10.0.0.5" {
		t.Fatalf("ips = %s -> %s", alert.SourceIP, alert.DestinationIP)
	}
	if alert.Resource.ID == "" || alert.Resource.Name != "i-123" || alert.Resource.Type != "Instance" {
		t.Fatalf("resource = %+v", alert.Resource)
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
