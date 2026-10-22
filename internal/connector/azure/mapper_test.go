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
	if alert.VendorStatus != "Active" {
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
	if alert.Resource.Source != model.ResourceSourceVendorDeclared {
		t.Fatalf("compromised entity is a declared name: %+v", alert.Resource)
	}
	if alert.Resource.AccountUID == "" {
		t.Fatalf("resource subscription was not projected: %+v", alert.Resource)
	}
	if alert.SourceIP != "" || alert.Actor != "" {
		t.Fatalf("generic IP/affected host must not imply source or actor: %+v", alert)
	}
	if alert.Tactic != "Execution" || alert.Technique != "T1059,T1059.001" {
		t.Fatalf("attack = %q / %q", alert.Tactic, alert.Technique)
	}
	if len(alert.Observables) < 5 || len(alert.Evidences) == 0 {
		t.Fatalf("observables=%d evidences=%d", len(alert.Observables), len(alert.Evidences))
	}
	foundIP := false
	for _, o := range alert.Observables {
		if o.Name == "entity.ip" && o.Value == "203.0.113.42" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatal("neutral IP entity was lost")
	}
	if alert.EventTime.IsZero() || alert.FirstSeenAt.IsZero() || alert.LastSeenAt.IsZero() {
		t.Fatalf("times = %+v / %+v / %+v", alert.EventTime, alert.FirstSeenAt, alert.LastSeenAt)
	}
	if alert.Raw == nil || !json.Valid(alert.Raw) {
		t.Fatal("raw payload not retained")
	}
}

func TestAllResourceIdentifiersAndExplicitIPRoles(t *testing.T) {
	raw := json.RawMessage(`{"name":"a","properties":{"compromisedEntity":"host","resourceIdentifiers":[{"type":"AzureResource","azureResourceId":"/subscriptions/s/providers/Microsoft.Compute/virtualMachines/a"},{"type":"AzureResource","azureResourceId":"/subscriptions/s/providers/Microsoft.Compute/virtualMachines/b"}],"entities":[{"type":"ip","address":"203.0.113.1"},{"type":"network","sourceIp":"203.0.113.2","destinationIp":"10.0.0.1"},{"type":"network","sourceIp":"203.0.113.3"}]}}`)
	alert, err := normalizeAlert(raw)
	if err != nil {
		t.Fatal(err)
	}
	if alert.SourceIP != "203.0.113.2" || alert.DestinationIP != "10.0.0.1" || len(alert.Resources) != 2 {
		t.Fatalf("alert=%+v", alert)
	}
	values := map[string]bool{}
	for _, o := range alert.Observables {
		values[o.Value] = true
	}
	if !values["203.0.113.3"] || !values[alert.Resources[1].ID] {
		t.Fatalf("secondary values lost: %+v", alert.Observables)
	}
	unnamed, err := normalizeAlert(json.RawMessage(`{"name":"a","properties":{"compromisedEntity":"host"}}`))
	if err != nil || unnamed.Resource.ID != "" {
		t.Fatalf("invented resource id: %+v err=%v", unnamed.Resource, err)
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
