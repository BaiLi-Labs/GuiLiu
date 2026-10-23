package defender

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

const sampleAlert = `{
  "id": "da637000000000000000_0000000000",
  "providerAlertId": "00000000-0000-0000-0000-000000000000",
  "incidentId": "123",
  "status": "new",
  "severity": "high",
  "determination": "malware",
  "classification": "truePositive",
  "title": "Suspicious process",
  "description": "A suspicious process was executed",
  "category": "Execution",
  "alertWebUrl": "https://security.microsoft.com/alerts/1",
  "createdDateTime": "2026-10-23T09:59:00Z",
  "firstActivityDateTime": "2026-10-23T09:58:00Z",
  "lastActivityDateTime": "2026-10-23T10:00:00Z",
  "lastUpdateDateTime": "2026-10-23T10:01:00Z",
  "actorDisplayName": "alice",
  "threatDisplayName": "Trojan",
  "threatFamilyName": "Emotet",
  "serviceSource": "microsoftDefenderForEndpoint",
  "detectionSource": "edr",
  "productName": "Microsoft Defender for Endpoint",
  "mitreTechniques": ["T1059.001", "T1105"],
  "evidence": [
    {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "win-01"},
    {"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "203.0.113.7"},
    {"@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": {"accountName": "alice", "domainName": "corp"}},
    {"@odata.type": "#microsoft.graph.security.fileEvidence", "fileDetails": {"fileName": "a.exe", "fileHash": {"hashType": "sha256", "hashValue": "abc123"}}}
  ]
}`

func TestNormalizeDefenderAlert(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(sampleAlert))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "da637000000000000000_0000000000" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.Severity != model.SeverityHigh || alert.OriginalSeverity != "high" {
		t.Fatalf("severity = %v/%q", alert.Severity, alert.OriginalSeverity)
	}
	if alert.Resource.ID != "win-01" || alert.Resource.Type != "host" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	if alert.Technique != "T1059.001,T1105" {
		t.Fatalf("technique = %q", alert.Technique)
	}
	if alert.Actor != "alice" {
		t.Fatalf("actor = %q", alert.Actor)
	}
	want := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	if !alert.EventTime.Equal(want) {
		t.Fatalf("event time = %v want %v", alert.EventTime, want)
	}
	if alert.SourceCreatedAt.IsZero() || alert.SourceUpdatedAt.IsZero() {
		t.Fatal("source timestamps were not parsed")
	}
	if len(alert.Observables) != 4 {
		t.Fatalf("observables = %+v", alert.Observables)
	}
	if !json.Valid(alert.Raw) {
		t.Fatal("raw payload was not preserved")
	}
}

func TestNormalizeFallsBackToCreatedTime(t *testing.T) {
	alert, err := (&Connector{}).Normalize(json.RawMessage(`{"id":"a","createdDateTime":"2026-10-23T09:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	if alert.EventTime.IsZero() {
		t.Fatal("createdDateTime should be used when no activity time is present")
	}
	if alert.Severity != model.SeverityUnknown {
		t.Fatalf("severity = %v", alert.Severity)
	}
}

func TestSeverityMapping(t *testing.T) {
	for value, want := range map[string]model.Severity{
		"informational": model.SeverityInformational,
		"low":           model.SeverityLow,
		"medium":        model.SeverityMedium,
		"high":          model.SeverityHigh,
		"unknown":       model.SeverityUnknown,
	} {
		if got := severityOf(value); got != want {
			t.Fatalf("severityOf(%q) = %v want %v", value, got, want)
		}
	}
}

func TestGraphErrorClassification(t *testing.T) {
	body := []byte(`{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`)
	err := graphError(403, body)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !connector.AuthError(err) {
		t.Fatalf("403 must classify as an authorization error: %s", err)
	}
	if connector.Retryable(err) {
		t.Fatal("a permission failure must not be retried")
	}

	throttled := graphError(429, []byte(`{"error":{"code":"TooManyRequests"}}`))
	if !connector.Throttled(throttled) {
		t.Fatalf("429 must be retryable: %s", throttled)
	}
}
