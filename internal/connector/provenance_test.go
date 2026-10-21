package connector

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestProvenancePointsToConcreteSourceFieldsAndConfiguration(t *testing.T) {
	a := model.Alert{ExternalID: "a", Region: "configured-region", Raw: json.RawMessage(`{"ID":"a","CreateTime":"2026-10-20 10:00:00","UpdateTime":"2026-10-20 11:00:00","Attacker":{"IP":"203.0.113.1"},"Level":4,"Status":0}`), Observables: []model.Observable{{TypeID: 2, Name: "src_endpoint.ip", Value: "203.0.113.1"}}}
	ApplyProvenance(&a, "tencent", model.Account{ID: "local", AccountUID: "cloud-uid", Region: "configured-region"})
	if !reflect.DeepEqual(a.Provenance["event_time"].Paths, []string{"/CreateTime"}) {
		t.Fatalf("event provenance=%+v", a.Provenance)
	}
	if _, exists := a.Provenance["source_updated_at"]; exists {
		t.Fatal("recent alert time claimed to be source modification time")
	}
	if a.Provenance["account_uid"].Source != "configuration" || a.Provenance["region"].Source != "configuration" {
		t.Fatal("configured scope was presented as a source field")
	}
	if !reflect.DeepEqual(a.Provenance["observables/0/value"].Paths, []string{"/Attacker/IP"}) {
		t.Fatalf("observable origin=%+v", a.Provenance)
	}
	first, _ := json.Marshal(a.Provenance)
	ApplyProvenance(&a, "tencent", model.Account{ID: "local", AccountUID: "cloud-uid", Region: "configured-region"})
	again, _ := json.Marshal(a.Provenance)
	if string(first) != string(again) {
		t.Fatal("mapping cannot be deterministically replayed")
	}
	b := model.Alert{Raw: json.RawMessage(`{"finding":{"name":"finding","connections":[{"sourceIp":"203.0.113.2"},{"sourceIp":"203.0.113.3"}]},"resource":{"gcpMetadata":{"project":"projects/1"}}}`), Observables: []model.Observable{{TypeID: 2, Name: "src_endpoint.ip", Value: "203.0.113.3"}}}
	ApplyProvenance(&b, "gcp", model.Account{})
	if !reflect.DeepEqual(b.Provenance["observables/0/value"].Paths, []string{"/finding/connections/1/sourceIp"}) || !reflect.DeepEqual(b.Provenance["account_uid"].Paths, []string{"/resource/gcpMetadata/project"}) {
		t.Fatalf("envelope origin=%+v", b.Provenance)
	}
}
