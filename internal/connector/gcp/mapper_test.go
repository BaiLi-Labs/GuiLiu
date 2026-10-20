package gcp

import (
	"testing"
	"time"

	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNormalizeGCPFinding(t *testing.T) {
	finding := &securitycenterpb.Finding{
		Name:          "organizations/123/sources/456/findings/789",
		Parent:        "organizations/123/sources/456",
		CanonicalName: "organizations/123/sources/456/findings/789",
		ResourceName:  "//compute.googleapis.com/projects/proj-1/zones/us-central1-a/instances/vm-1",
		State:         securitycenterpb.Finding_ACTIVE,
		Category:      "SQL Injection",
		Description:   "A SQL injection attempt was detected",
		Severity:      securitycenterpb.Finding_HIGH,
		EventTime:     timestamppb.New(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)),
		CreateTime:    timestamppb.New(time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)),
		SourceProperties: map[string]*structpb.Value{
			"source_ip":      structpb.NewStringValue("203.0.113.10"),
			"destination_ip": structpb.NewStringValue("10.0.0.5"),
			"project_id":     structpb.NewStringValue("proj-1"),
			"source":         structpb.NewStringValue("SCC"),
		},
		Connections: []*securitycenterpb.Connection{{
			SourceIp:        "203.0.113.10",
			SourcePort:      443,
			DestinationIp:   "10.0.0.5",
			DestinationPort: 8080,
		}},
	}
	raw, err := protojson.Marshal(finding)
	if err != nil {
		t.Fatal(err)
	}
	alert, err := (&Connector{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != finding.Name || alert.Title != "SQL Injection" {
		t.Fatalf("identity = %+v", alert)
	}
	if alert.Severity.String() != "high" || alert.OriginalSeverity != "HIGH" {
		t.Fatalf("severity = %s / %s", alert.Severity, alert.OriginalSeverity)
	}
	if alert.VendorStatus != "active" {
		t.Fatalf("status = %q", alert.VendorStatus)
	}
	if alert.SourceIP != "203.0.113.10" || alert.DestinationIP != "10.0.0.5" {
		t.Fatalf("ips = %s -> %s", alert.SourceIP, alert.DestinationIP)
	}
	if alert.Resource.Name != "vm-1" || alert.Resource.Type != "instances" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	if alert.CloudAccountUID != "proj-1" || alert.Region != "us-central1-a" {
		t.Fatalf("account/region = %s / %s", alert.CloudAccountUID, alert.Region)
	}
	if !alert.EventTime.Equal(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("event time = %s", alert.EventTime)
	}
	if len(alert.Observables) == 0 || len(alert.Evidences) != 1 {
		t.Fatalf("observables/evidence missing")
	}
}
