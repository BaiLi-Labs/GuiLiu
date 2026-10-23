package pushwire

import (
	"strings"
	"testing"
)

const sampleCEF = `CEF:0|Fortinet|FortiGate|7.6|1059028705|traffic:forward|5|src=203.0.113.10 dst=198.51.100.20 spt=51515 dpt=443 msg=blocked\=by\=policy act=blocked cs1Label=Policy cs1=web-access`

func TestParseCEF(t *testing.T) {
	cef, err := ParseCEF(sampleCEF)
	if err != nil {
		t.Fatal(err)
	}
	if cef.Version != "0" || cef.DeviceVendor != "Fortinet" || cef.SignatureID != "1059028705" {
		t.Fatalf("header = %+v", cef)
	}
	if cef.Severity != "5" || cef.Name != "traffic:forward" {
		t.Fatalf("severity/name = %q/%q", cef.Severity, cef.Name)
	}
	if got := cef.Extension["src"]; got != "203.0.113.10" {
		t.Fatalf("src = %q", got)
	}
	if got := cef.Extension["msg"]; got != "blocked=by=policy" {
		t.Fatalf("escaped value = %q", got)
	}
	if got := cef.Extension["cs1"]; got != "web-access" {
		t.Fatalf("cs1 = %q", got)
	}
	if !strings.HasPrefix(cef.Raw, "CEF:0|Fortinet") {
		t.Fatalf("raw not preserved: %q", cef.Raw)
	}
}

func TestParseCEFRejectsIncompleteHeader(t *testing.T) {
	if _, err := ParseCEF("CEF:0|only|three"); err == nil {
		t.Fatal("expected an error for a truncated header")
	}
	if _, err := ParseCEF("not a cef line"); err == nil {
		t.Fatal("expected an error for a non-CEF line")
	}
}

func TestParseRFC5424WithStructuredData(t *testing.T) {
	frame := `<134>1 2026-10-23T10:00:00.123Z fw-1 FortiGate - - [meta key="value with space"] ` + sampleCEF
	msg, err := ParseSyslog([]byte(frame))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Facility != 16 || msg.Severity != 6 {
		t.Fatalf("priority = %d/%d", msg.Facility, msg.Severity)
	}
	if msg.Hostname != "fw-1" || msg.AppName != "FortiGate" {
		t.Fatalf("host/app = %q/%q", msg.Hostname, msg.AppName)
	}
	if msg.StructuredData != `[meta key="value with space"]` {
		t.Fatalf("structured data = %q", msg.StructuredData)
	}
	if msg.Message != sampleCEF {
		t.Fatalf("message = %q", msg.Message)
	}
}

func TestParseRFC3164(t *testing.T) {
	frame := `<134>Oct 23 10:00:00 fw-1 FortiGate[1234]: ` + sampleCEF
	msg, err := ParseSyslog([]byte(frame))
	if err != nil {
		t.Fatal(err)
	}
	if !msg.Legacy || msg.AppName != "FortiGate" || msg.ProcID != "1234" {
		t.Fatalf("legacy frame = %+v", msg)
	}
	if msg.Message != sampleCEF {
		t.Fatalf("message = %q", msg.Message)
	}
}

func TestDecodeSyslogDetectsCEF(t *testing.T) {
	frame := `<134>1 2026-10-23T10:00:00Z fw-1 FortiGate - - - ` + sampleCEF
	env, err := DecodeSyslog([]byte(frame))
	if err != nil {
		t.Fatal(err)
	}
	if env.CEF == nil || env.CEF.DeviceProduct != "FortiGate" {
		t.Fatalf("cef not decoded: %+v", env)
	}
	if env.Message != sampleCEF {
		t.Fatalf("original message not preserved")
	}
}

func TestParseSyslogRejectsMissingPriority(t *testing.T) {
	if _, err := ParseSyslog([]byte("Oct 23 10:00:00 host app: message")); err == nil {
		t.Fatal("expected an error for a frame without a priority")
	}
}
