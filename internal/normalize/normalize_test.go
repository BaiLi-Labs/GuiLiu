package normalize

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/ocsf"
)

func TestBuildDetectionFinding(t *testing.T) {
	now := time.Date(2026, 10, 20, 6, 0, 0, 0, time.UTC)
	alert := model.Alert{
		FindingKind: model.FindingDetection, EventTime: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), ExternalID: "alert-1",
		Title:         "Reverse shell",
		Description:   "cmd spawned by nginx",
		Severity:      model.SeverityCritical,
		FirstSeenAt:   now.Add(-time.Hour),
		LastSeenAt:    now,
		OriginalTime:  "2026-10-20 14:00:00",
		Product:       "Host Security (CWP)",
		AlertType:     "MaliciousProcess",
		SourceIP:      "203.0.113.9",
		DestinationIP: "10.0.0.5",
		Tactic:        "TA0002",
		Resource:      model.Resource{ID: "ins-1", Name: "web-01", Type: "host"},
		Unmapped:      map[string]any{"tencent_csip": map[string]any{"uin": "123"}},
	}
	acct := model.Account{ID: "acct-1", Name: "prod-tencent", Provider: "tencent", AccountUID: "123456", Region: "ap-guangzhou"}

	raw, err := Build(alert, acct, Info{
		VendorName:    "Tencent Cloud",
		ProductName:   "Cloud Security Center (CSIP)",
		ProductUID:    "tencent.csip",
		LogProvider:   "Tencent Cloud",
		MapperVersion: "tencent-csip/v1",
	})
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["class_uid"].(float64) != ocsf.ClassUID {
		t.Fatalf("class_uid = %v", got["class_uid"])
	}
	if got["type_uid"].(float64) != ocsf.ClassUID*100 {
		t.Fatalf("type_uid = %v", got["type_uid"])
	}
	if got["severity_id"].(float64) != 5 || got["severity"] != "Critical" {
		t.Fatalf("severity = %v/%v", got["severity_id"], got["severity"])
	}
	finding := got["finding_info"].(map[string]any)
	if finding["uid"] != "alert-1" || finding["title"] != "Reverse shell" {
		t.Fatalf("finding_info = %v", finding)
	}
	metadata := got["metadata"].(map[string]any)
	if metadata["version"] != ocsf.SchemaVersion {
		t.Fatalf("metadata version = %v", metadata["version"])
	}
	product := metadata["product"].(map[string]any)
	if product["vendor_name"] != "Tencent Cloud" {
		t.Fatalf("product = %v", product)
	}
	cloud := got["cloud"].(map[string]any)
	if cloud["provider"] != "Tencent Cloud" || cloud["region"] != "ap-guangzhou" {
		t.Fatalf("cloud = %v", cloud)
	}
	account := cloud["account"].(map[string]any)
	if account["uid"] != "123456" {
		t.Fatalf("cloud account = %v", account)
	}
	observables, ok := got["observables"].([]any)
	if !ok || len(observables) < 3 {
		t.Fatalf("observables = %v", got["observables"])
	}
	unmapped := got["unmapped"].(map[string]any)
	if unmapped["mapper_version"] != "tencent-csip/v1" {
		t.Fatalf("unmapped = %v", unmapped)
	}
	if _, ok := unmapped["tencent_csip"]; !ok {
		t.Fatalf("vendor extension lost: %v", unmapped)
	}
	if got["is_alert"] != nil {
		t.Fatalf("is_alert = %v", got["is_alert"])
	}
}

func TestMultipleTacticsAndResources(t *testing.T) {
	a := model.Alert{
		FindingKind: model.FindingDetection, EventTime: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC), ExternalID: "a", Tactic: "TA0002,TA0005,TA0002", Technique: "T1059",
		Resources: []model.Resource{{ID: "host-1", Type: "host"}, {ID: "host-2", Type: "host"}},
	}
	raw, err := Build(a, model.Account{ID: "account"}, Info{})
	if err != nil {
		t.Fatal(err)
	}
	var got ocsf.Finding
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.FindingInfo.Attacks) != 3 || len(got.Resources) != 2 {
		t.Fatalf("payload=%s", raw)
	}
	for _, attack := range got.FindingInfo.Attacks {
		if attack.Version != "" {
			t.Fatal("unknown ATT&CK version must not be fabricated")
		}
		if attack.Tactic != nil && attack.Tactic.UID != "TA0002" && attack.Tactic.UID != "TA0005" {
			t.Fatalf("invalid tactic: %+v", attack)
		}
	}
}
