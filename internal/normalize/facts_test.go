package normalize

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector/gcp"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/ocsf"
)

func TestUnknownIdentityAndObservableRolesRemainFaithful(t *testing.T) {
	a := model.Alert{ExternalID: "a", FindingKind: model.FindingDetection, EventTime: time.Now().UTC(), SourceIP: "10.0.0.1", DestinationIP: "10.0.0.1"}
	b, err := Build(a, model.Account{ID: "local-configuration-id"}, Info{})
	if err != nil {
		t.Fatal(err)
	}
	var f ocsf.Finding
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Cloud.Account.UID != "" {
		t.Fatalf("unknown cloud account became %q", f.Cloud.Account.UID)
	}
	if len(f.Observables) != 2 || f.Observables[0].Name == f.Observables[1].Name {
		t.Fatalf("source/destination role lost: %+v", f.Observables)
	}
	if f.FindingInfo.CreatedTime != 0 || f.FindingInfo.ModifiedTime != 0 {
		t.Fatal("observation time impersonated source creation or modification")
	}
}

func TestSourceClassAndUnknownTimeControlOCSFProjection(t *testing.T) {
	raw := json.RawMessage(`{"name":"organizations/1/sources/2/findings/3","findingClass":"VULNERABILITY","category":"VULN","eventTime":"2026-10-20T10:00:00Z","vulnerability":{"cve":{"id":"CVE-2026-12345"}}}`)
	a, err := (&gcp.Connector{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(a, model.Account{}, Info{})
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err = json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f["class_uid"] != float64(2002) || f["vulnerabilities"] == nil {
		t.Fatalf("vulnerability reclassified: %s", b)
	}
	for _, a := range []model.Alert{{FindingKind: model.FindingOther, EventTime: time.Now()}, {FindingKind: model.FindingDetection}, {FindingKind: model.FindingVulnerability, EventTime: time.Now()}, {FindingKind: model.FindingCompliance, EventTime: time.Now()}, {FindingKind: model.FindingIncident, EventTime: time.Now()}} {
		b, err := Build(a, model.Account{}, Info{})
		if err != nil || len(b) != 0 {
			t.Fatalf("unsupported or timeless record manufactured OCSF: %s %v", b, err)
		}
	}
}
