package connector

import (
	"net/http"
	"time"
)

// PushFormat identifies the transport a source uses to deliver records.
// It is deliberately transport-level: a connector decides which formats it
// accepts, while the intake layer owns framing, authentication and durability.
type PushFormat string

const (
	PushWebhook PushFormat = "webhook"
	PushSyslog  PushFormat = "syslog"
)

// PushRequest is one inbound transport payload after the intake layer has
// validated its envelope. Body is never rewritten: for a webhook it is the
// exact request body; for syslog it is the JSON envelope produced by
// internal/syslog, which retains the original message text.
type PushRequest struct {
	Format     PushFormat
	Body       []byte
	Header     http.Header
	RemoteAddr string
	ReceivedAt time.Time
}

// Pusher is the push counterpart of Connector. A connector implements it only
// when the product actually delivers records instead of exposing them for
// polling. The accepted transports are declared statically in
// Descriptor.PushFormats. DecodePush must preserve the vendor payload verbatim
// so that Normalize stays a pure function of RawAlert.Raw.
type Pusher interface {
	Connector
	// DecodePush turns one transport payload into zero or more raw records.
	// Returning no records is valid (for example a heartbeat).
	DecodePush(req PushRequest) ([]RawAlert, error)
}

// AsPusher reports whether a connector also accepts pushed records.
func AsPusher(c Connector) (Pusher, bool) {
	p, ok := c.(Pusher)
	return p, ok
}
