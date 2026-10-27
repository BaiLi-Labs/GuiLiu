package connector

import (
	"context"
	"encoding/json"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// EventSource is an optional read-only capability alongside Finding polling.
// Continuation tokens are private to the source; the shared event service seals
// them and binds them to the connection, configuration and normalized query.
type EventSource interface {
	SearchEvents(context.Context, model.EventSearch, json.RawMessage) (*model.EventPage, error)
	EventFields(context.Context) (*model.EventFields, error)
	EventEvidence(context.Context, model.EventReference) (*model.EventEvidence, error)
}
