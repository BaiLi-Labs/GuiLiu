package cef

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/pushwire"
)

func cefRaw(t *testing.T) json.RawMessage {
	t.Helper()
	cef, err := pushwire.ParseCEF(`CEF:0|Fortinet|FortiGate|7.6|1059028705|traffic:forward|8|externalId=evt-1 src=203.0.113.10 dst=198.51.100.20 shost=web-01 dvchost=fw-1 suser=alice requestURL=https://example.test/login rt=1792749600000 msg=blocked by policy act=blocked`)
	if err != nil {
		t.Fatal(err)
	}
	env := pushwire.Envelope{
		Format: "syslog",
		Syslog: &pushwire.Message{
			Facility: 16, Severity: 6, Version: 1,
			Timestamp: "2026-10-23T10:00:00Z", Hostname: "fw-1", AppName: "FortiGate",
			Message: cef.Raw,
		},
		CEF:     &cef,
		Message: cef.Raw,
	}
	raw, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNormalizeCEFRecord(t *testing.T) {
	alert, err := (&Connector{}).Normalize(cefRaw(t))
	if err != nil {
		t.Fatal(err)
	}
	if alert.ExternalID != "evt-1" {
		t.Fatalf("external id = %q", alert.ExternalID)
	}
	if alert.Severity != model.SeverityHigh {
		t.Fatalf("severity = %v", alert.Severity)
	}
	if alert.OriginalSeverity != "8" {
		t.Fatalf("original severity = %q", alert.OriginalSeverity)
	}
	want := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	if !alert.EventTime.Equal(want) {
		t.Fatalf("event time = %v want %v", alert.EventTime, want)
	}
	if alert.SourceIP != "203.0.113.10" || alert.DestinationIP != "198.51.100.20" {
		t.Fatalf("ips = %q/%q", alert.SourceIP, alert.DestinationIP)
	}
	if alert.Resource.ID != "fw-1" || alert.Resource.Type != "host" {
		t.Fatalf("resource = %+v", alert.Resource)
	}
	if alert.Resource.Source != model.ResourceSourceIdentifierFallback {
		t.Fatalf("resource name source = %q", alert.Resource.Source)
	}
	if alert.Title != "traffic:forward" || alert.RuleID != "1059028705" {
		t.Fatalf("title/rule = %q/%q", alert.Title, alert.RuleID)
	}
	if alert.VendorStatus != "blocked" {
		t.Fatalf("vendor status = %q", alert.VendorStatus)
	}
	if len(alert.Observables) != 5 {
		t.Fatalf("observables = %+v", alert.Observables)
	}
	if len(alert.Raw) == 0 || !json.Valid(alert.Raw) {
		t.Fatal("raw payload was not preserved")
	}
}

func TestNormalizeMissingTimeStaysUnknown(t *testing.T) {
	cef, err := pushwire.ParseCEF(`CEF:0|Acme|Sensor|1|42|probe|3|src=203.0.113.9`)
	if err != nil {
		t.Fatal(err)
	}
	env := pushwire.Envelope{Format: "webhook", CEF: &cef, Message: cef.Raw}
	raw, _ := env.Marshal()
	alert, err := (&Connector{}).Normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !alert.EventTime.IsZero() {
		t.Fatalf("event time must stay unknown, got %v", alert.EventTime)
	}
	if alert.ExternalID == "" {
		t.Fatal("a record without an external id must fall back to a content hash")
	}
}

func TestDecodePushWebhook(t *testing.T) {
	body := `CEF:0|Fortinet|FortiGate|7.6|1059028705|traffic:forward|5|src=203.0.113.10`
	raws, err := (&Connector{}).DecodePush(connector.PushRequest{
		Format:     connector.PushWebhook,
		Body:       []byte(body),
		Header:     http.Header{},
		RemoteAddr: "203.0.113.5:5000",
		ReceivedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 1 {
		t.Fatalf("records = %d", len(raws))
	}
	var env pushwire.Envelope
	if err := json.Unmarshal(raws[0].Raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.CEF == nil || env.CEF.DeviceProduct != "FortiGate" {
		t.Fatalf("decoded envelope = %+v", env)
	}
}

func TestDecodePushSyslogIgnoresNonCEF(t *testing.T) {
	frame := `<134>1 2026-10-23T10:00:00Z fw-1 FortiGate - - - system ready`
	env, err := pushwire.DecodeSyslog([]byte(frame))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := env.Marshal()
	raws, err := (&Connector{}).DecodePush(connector.PushRequest{Format: connector.PushSyslog, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if len(raws) != 0 {
		t.Fatalf("non-CEF syslog frame produced %d records", len(raws))
	}
}

func TestInfoDeclaresPushSupport(t *testing.T) {
	desc := (&Connector{}).Info()
	if !desc.PushOnly {
		t.Fatal("CEF must be marked push-only")
	}
	if len(desc.PushFormats) != 2 {
		t.Fatalf("push formats = %+v", desc.PushFormats)
	}
}

func TestDeviceIdentityDoesNotMergeDifferentEvents(t *testing.T) {
	for _, eventIDs := range []bool{true, false} {
		var ids []string
		for _, name := range []string{"one", "two", "one"} {
			line := "CEF:0|Acme|Sensor|1|42|" + name + "|5|deviceExternalId=sensor-1"
			if eventIDs {
				line += " eventId=" + name
			}
			c := &Connector{}
			raws, err := c.DecodePush(connector.PushRequest{Format: connector.PushWebhook, Body: []byte(line)})
			if err != nil {
				t.Fatal(err)
			}
			alert, err := c.Normalize(raws[0].Raw)
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, alert.ExternalID)
		}
		if ids[0] == ids[1] || ids[0] != ids[2] {
			t.Fatalf("event IDs (explicit=%v) = %v; distinct events must differ and retries must match", eventIDs, ids)
		}
	}
}
