package tencent

import (
	"encoding/base64"
	"encoding/json"
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
		ID:               strPtr("alert-1001"),
		Name:             strPtr("Reverse shell detected"),
		Source:           strPtr("CWP"),
		Level:            &level,
		Status:           &status,
		Attacker:         &csip.RoleInfo{IP: strPtr("203.0.113.9"), MD5: strPtr("d41d8cd98f00b204e9800998ecf8427e")},
		Victim:           &csip.RoleInfo{IP: strPtr("10.0.0.5"), InstanceID: strPtr("ins-abc"), AssetType: i64Ptr(1)},
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
	if !alert.EventTime.Equal(wantFirst.Add(time.Hour)) {
		t.Fatalf("event time = %s", alert.EventTime)
	}
	if len(alert.Evidences) != 1 || alert.Evidences[0].Data["data"] != "curl http://evil.example" {
		t.Fatalf("evidence = %+v", alert.Evidences)
	}
	if alert.VendorStatus != "unhandled" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	if alert.Unmapped == nil {
		t.Fatal("expected unmapped vendor fields")
	}
}
