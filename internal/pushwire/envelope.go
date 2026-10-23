package pushwire

import (
	"encoding/json"
	"strings"
)

// Envelope is the JSON document the intake layer hands to a Pusher. It keeps
// the original message text and, when the payload is CEF, the decoded header
// and extension.
//
// It deliberately excludes receipt time and peer address: those are transport
// observations, not vendor payload. Including them would change the raw record
// on every retry, produce a new revision for an identical event and defeat
// deduplication.
type Envelope struct {
	Format  string   `json:"format"`
	Syslog  *Message `json:"syslog,omitempty"`
	CEF     *CEF     `json:"cef,omitempty"`
	Message string   `json:"message,omitempty"`
}

// DecodeSyslog turns one syslog frame into an intake envelope.
func DecodeSyslog(raw []byte) (Envelope, error) {
	msg, err := ParseSyslog(raw)
	if err != nil {
		return Envelope{}, err
	}
	env := Envelope{
		Format:  "syslog",
		Syslog:  &msg,
		Message: msg.Message,
	}
	if strings.Contains(msg.Message, "CEF:") {
		if cef, cefErr := ParseCEF(msg.Message); cefErr == nil {
			env.CEF = &cef
		}
	}
	return env, nil
}

// DecodeWebhook turns a webhook body into an intake envelope. A JSON body is
// passed through untouched; a CEF text body is decoded and preserved verbatim.
func DecodeWebhook(body []byte) Envelope {
	env := Envelope{Format: "webhook"}
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "CEF:") {
		if cef, err := ParseCEF(text); err == nil {
			env.CEF = &cef
			env.Message = text
			return env
		}
	}
	env.Message = text
	return env
}

// Marshal renders the envelope for PushRequest.Body.
func (e Envelope) Marshal() ([]byte, error) { return json.Marshal(e) }
