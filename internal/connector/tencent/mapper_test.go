package tencent

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	csip "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/csip/v20221121"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func strPtr(s string) *string { return &s }
func u64Ptr(v uint64) *uint64 { return &v }
func i64Ptr(v int64) *int64   { return &v }

func sampleAlert(t *testing.T) json.RawMessage {
	t.Helper()
	level := uint64(5)
	status := uint64(0)
	count := uint64(7)
	a := &csip.AlertInfo{
		ID:     strPtr("alert-1001"),
		Name:   strPtr("Reverse shell detected"),
		Source: strPtr("CWP"),
		Level:  &level,
		Status: &status,
		Attacker: &csip.RoleInfo{
			IP:      strPtr("203.0.113.9"),
			Address: strPtr("示例省示例市"),
			Country: strPtr("示例国家"),
			MD5:     strPtr("d41d8cd98f00b204e9800998ecf8427e"),
		},
		Victim: &csip.RoleInfo{
			IP:         strPtr("10.0.0.5"),
			InstanceID: strPtr("ins-abc"),
			AssetType:  i64Ptr(1),
			Name:       strPtr("web-prod-01"),
			Account:    strPtr("1250000000"),
		},
		ProcessType:      strPtr("BlockAttackIP"),
		CreateTime:       strPtr("2026-10-20 08:00:00"),
		UpdateTime:       strPtr("2026-10-20 09:00:00"),
		Type:             strPtr("MaliciousProcess"),
		SubType:          strPtr("ReverseShell"),
		Count:            &count,
		EvidencePath:     strPtr("/tmp/x"),
		EvidenceLocation: strPtr("host"),
		EvidenceData:     strPtr(base64.StdEncoding.EncodeToString([]byte("curl http://evil.example"))),
		Uin:              strPtr("1234567890"),
		AppID:            strPtr("1250000000"),
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestExtraInfoAndUnknownAlertTypesArePreserved(t *testing.T) {
	raw := json.RawMessage(`{"ID":"new-id","Source":"new-source","Type":"new-type","SubType":"new-subtype","ExtraInfo":{"SourceIP":"203.0.113.1","ProcessCommandLine":"vendor command line","CVE":"CVE-2026-12345","FileMD5":"vendor-hash","RequestHeaders":"vendor headers"}}`)
	alert, err := (&Connector{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if alert.AlertType != "new-type/new-subtype" || alert.Product != "new-source" || alert.SourceIP != "203.0.113.1" || string(alert.Raw) != string(raw) {
		t.Fatalf("alert=%+v", alert)
	}
	evidence, err := json.Marshal(alert.Evidences)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"vendor command line", "CVE-2026-12345", "vendor headers"} {
		if !strings.Contains(string(evidence), value) {
			t.Errorf("missing evidence %s", value)
		}
	}
	foundHash := false
	for _, o := range alert.Observables {
		if o.Value == "vendor-hash" {
			foundHash = true
		}
	}
	if !foundHash {
		t.Fatal("ExtraInfo file hash not searchable")
	}
}

func TestResourceNameOriginIsExplicit(t *testing.T) {
	// RoleInfo.Name is an enterprise name, not an asset name.
	enterprise, err := (&Connector{}).Normalize(json.RawMessage(`{"ID":"a","Victim":{"IP":"10.0.0.6","InstanceID":"ins-x","AssetType":1,"Name":"Example Holdings Ltd"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if enterprise.Resource.Name != "10.0.0.6" || enterprise.Resource.Source != model.ResourceSourceIdentifierFallback {
		t.Fatalf("enterprise name became an asset name: %+v", enterprise.Resource)
	}
	if enterprise.Resource.DeclaredName != "Example Holdings Ltd" {
		t.Fatalf("declared name was not preserved: %+v", enterprise.Resource)
	}

	fallback, err := (&Connector{}).Normalize(json.RawMessage(`{"ID":"b","Victim":{"IP":"10.0.0.7","InstanceID":"ins-y","AssetType":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	if fallback.Resource.Name != "10.0.0.7" || fallback.Resource.Source != model.ResourceSourceIdentifierFallback {
		t.Fatalf("fallback resource = %+v", fallback.Resource)
	}

	domain, err := (&Connector{}).Normalize(json.RawMessage(`{"ID":"c","Victim":{"Domain":"example.com","AssetType":2}}`))
	if err != nil {
		t.Fatal(err)
	}
	if domain.Resource.Name != "example.com" || domain.Resource.Source != model.ResourceSourceIdentifierFallback {
		t.Fatalf("domain resource = %+v", domain.Resource)
	}
	// A domain alert has no instance ID; the domain itself becomes the scoped
	// identity so repeated findings for one domain can form a group.
	if domain.Resource.ID != "example.com" || domain.Resource.Type != "domain" {
		t.Fatalf("domain resource identity = %+v", domain.Resource)
	}
}

func TestNormalize(t *testing.T) {
	c := &Connector{}
	alert, err := c.Normalize(sampleAlert(t))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "alert-1001" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.Severity != model.SeverityCritical {
		t.Fatalf("severity = %v", alert.Severity)
	}
	if alert.SourceIP != "203.0.113.9" || alert.DestinationIP != "10.0.0.5" {
		t.Fatalf("ips = %q -> %q", alert.SourceIP, alert.DestinationIP)
	}
	if alert.Resource.ID != "ins-abc" || alert.Resource.Type != "host" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	if alert.Resource.Name != "10.0.0.5" || alert.Resource.Source != model.ResourceSourceIdentifierFallback {
		t.Fatalf("resource name = %+v, want an identifier fallback", alert.Resource)
	}
	if alert.Resource.AccountUID != "" {
		t.Fatalf("Victim.Account is an AppID, not a UIN; it must not become account_uid: %q", alert.Resource.AccountUID)
	}
	if alert.Resource.DeclaredName != "web-prod-01" {
		t.Fatalf("the source-declared name must be kept verbatim: %q", alert.Resource.DeclaredName)
	}
	evidence, err := json.Marshal(alert.Evidences)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(evidence), "web-prod-01") {
		t.Fatal("the role name must stay available in vendor evidence")
	}
	if alert.SourceLocation != "示例省示例市" || alert.SourceCountry != "示例国家" {
		t.Fatalf("source location = %q/%q", alert.SourceLocation, alert.SourceCountry)
	}
	if alert.ResponseAction != "BlockAttackIP" {
		t.Fatalf("response action = %q", alert.ResponseAction)
	}
	if alert.Product != "Host Security (CWP)" {
		t.Fatalf("product = %q", alert.Product)
	}
	if alert.AlertType != "MaliciousProcess/ReverseShell" {
		t.Fatalf("alert type = %q", alert.AlertType)
	}
	wantFirst := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	if !alert.FirstSeenAt.Equal(wantFirst) {
		t.Fatalf("first seen = %s, want %s", alert.FirstSeenAt, wantFirst)
	}
	if !alert.EventTime.Equal(wantFirst) {
		t.Fatalf("event time = %s", alert.EventTime)
	}
	if len(alert.Evidences) != 1 || alert.Evidences[0].Data["data"] != "curl http://evil.example" {
		t.Fatalf("evidence = %+v", alert.Evidences)
	}
	if alert.VendorStatus != "0" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	if alert.Unmapped == nil {
		t.Fatal("expected unmapped vendor fields")
	}
}
