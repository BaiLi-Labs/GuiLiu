package azure

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestNormalizeAlert(t *testing.T) {
	raw, err := os.ReadFile("testdata/alert.json")
	if err != nil {
		t.Fatal(err)
	}
	alert, err := normalizeAlert(raw)
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "2512345678901234567_abc123" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.Title != "Suspicious process executed on virtual machine" {
		t.Fatalf("title = %q", alert.Title)
	}
	if alert.Severity != model.SeverityHigh {
		t.Fatalf("severity = %s", alert.Severity)
	}
	if alert.VendorStatus != "active" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	if alert.CloudAccountUID != "00000000-0000-0000-0000-000000000001" {
		t.Fatalf("subscription = %q", alert.CloudAccountUID)
	}
	if alert.Region != "centralus" {
		t.Fatalf("region = %q", alert.Region)
	}
	if alert.Resource.ID == "" || alert.Resource.Name != "vm-web-01" ||
		alert.Resource.Type != "Microsoft.Compute/virtualMachines" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	if alert.SourceIP != "203.0.113.42" {
		t.Fatalf("source ip = %q", alert.SourceIP)
	}
	if alert.Tactic != "Execution" || alert.Technique != "T1059" {
		t.Fatalf("attack = %q / %q", alert.Tactic, alert.Technique)
	}
	if len(alert.Observables) < 5 || len(alert.Evidences) == 0 {
		t.Fatalf("observables=%d evidences=%d", len(alert.Observables), len(alert.Evidences))
	}
	if alert.EventTime.IsZero() || alert.FirstSeenAt.IsZero() || alert.LastSeenAt.IsZero() {
		t.Fatalf("times = %+v / %+v / %+v", alert.EventTime, alert.FirstSeenAt, alert.LastSeenAt)
	}
	if alert.Raw == nil || !json.Valid(alert.Raw) {
		t.Fatal("raw payload not retained")
	}
}

func TestNormalizeAlertWithoutProperties(t *testing.T) {
	alert, err := normalizeAlert(json.RawMessage(`{"id":"/subscriptions/sub/providers/Microsoft.Security/locations/eastus/alerts/a","name":"a"}`))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "a" || alert.Title == "" || alert.Severity != model.SeverityUnknown {
		t.Fatalf("alert = %+v", alert)
	}
}
