package connector

import (
	"testing"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

func TestNamedResourceRecordsNameOrigin(t *testing.T) {
	declared := NamedResource("ins-1", "host", "web-01", "10.0.0.5", "ins-1")
	if declared.Name != "web-01" || declared.Source != model.ResourceSourceVendorDeclared {
		t.Fatalf("declared = %+v", declared)
	}
	if declared.ID != "ins-1" || declared.Type != "host" {
		t.Fatalf("identity = %+v", declared)
	}

	fallback := NamedResource("ins-1", "host", "", "", "10.0.0.5", "ins-1")
	if fallback.Name != "10.0.0.5" || fallback.Source != model.ResourceSourceIdentifierFallback {
		t.Fatalf("fallback = %+v", fallback)
	}

	// A name is never invented when the vendor declares nothing usable.
	empty := NamedResource("ins-1", "host", "   ", "")
	if empty.Name != "" || empty.Source != "" {
		t.Fatalf("empty = %+v", empty)
	}
}
