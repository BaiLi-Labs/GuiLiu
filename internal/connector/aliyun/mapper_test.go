package aliyun

import (
	"encoding/json"
	"testing"
	"time"

	sas "github.com/alibabacloud-go/sas-20181203/v3/client"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func strPtr(s string) *string { return &s }
func i32Ptr(v int32) *int32   { return &v }
func i64Ptr(v int64) *int64   { return &v }

func sampleAlert(t *testing.T) json.RawMessage {
	t.Helper()
	id := int64(9001)
	status := int32(1)
	occ := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC).UnixMilli()
	last := occ + 3600_000
	a := &sas.DescribeSuspEventsResponseBodySuspEvents{
		Id:                    &id,
		Name:                  strPtr("Webshell detected"),
		Desc:                  strPtr("A PHP webshell was written"),
		Level:                 strPtr("serious"),
		EventStatus:           &status,
		OccurrenceTime:        strPtr("2026-10-20 08:00:00"),
		OccurrenceTimeStamp:   &occ,
		LastTimeStamp:         &last,
		AlarmEventTypeDisplay: strPtr("恶意文件"),
		InstanceId:            strPtr("i-bp1xxxx"),
		InstanceName:          strPtr("web-01"),
		InternetIp:            strPtr("47.0.0.1"),
		Uuid:                  strPtr("uuid-1"),
		Details: []*sas.DescribeSuspEventsResponseBodySuspEventsDetails{
			{NameDisplay: strPtr("源IP"), Value: strPtr("198.51.100.7")},
			{NameDisplay: strPtr("文件路径"), Value: strPtr("/var/www/html/shell.php")},
		},
		TacticItems: []*sas.DescribeSuspEventsResponseBodySuspEventsTacticItems{
			{TacticId: strPtr("TA0001"), TacticDisplayName: strPtr("Initial Access")},
		},
		SecurityEventIds: strPtr("event-1"),
		AlarmUniqueInfo:  strPtr("unique-1"),
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
	if alert.ExternalID != "9001" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.Severity != model.SeverityCritical {
		t.Fatalf("severity = %v", alert.Severity)
	}
	if alert.OriginalSeverity != "serious" {
		t.Fatalf("original severity = %q", alert.OriginalSeverity)
	}
	if alert.SourceIP != "198.51.100.7" {
		t.Fatalf("source ip = %q", alert.SourceIP)
	}
	if alert.DestinationIP != "47.0.0.1" {
		t.Fatalf("destination ip = %q", alert.DestinationIP)
	}
	if alert.Resource.ID != "i-bp1xxxx" || alert.Resource.Type != "host" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	if alert.Tactic != "TA0001" {
		t.Fatalf("tactic = %q", alert.Tactic)
	}
	if alert.VendorStatus != "unhandled" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	if len(alert.Evidences) != 2 {
		t.Fatalf("evidences = %+v", alert.Evidences)
	}
	wantFirst := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	if !alert.FirstSeenAt.Equal(wantFirst) {
		t.Fatalf("first seen = %s, want %s", alert.FirstSeenAt, wantFirst)
	}
	if len(alert.Observables) < 3 {
		t.Fatalf("observables = %+v", alert.Observables)
	}
}
