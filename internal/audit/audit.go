// Package audit records authenticated access separately from security facts.
package audit

import (
	"context"
	"log/slog"
	"reflect"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/auth"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
	"github.com/google/uuid"
)

type spanKey struct{}
type Span struct {
	Event model.AuditEvent
	store store.Store
	log   *slog.Logger
	start time.Time
}

func FromContext(ctx context.Context) *Span { s, _ := ctx.Value(spanKey{}).(*Span); return s }

// The start must be durable before the operation executes. If completion cannot
// be persisted, the original in_progress row remains as an honest audit gap.
func Begin(ctx context.Context, st store.Store, log *slog.Logger, event model.AuditEvent) (context.Context, *Span, error) {
	if log == nil {
		log = slog.Default()
	}
	if parent := FromContext(ctx); parent != nil {
		event.RequestID = parent.Event.RequestID
		event.ParentSequence = parent.Event.Sequence
		event.PeerIP = parent.Event.PeerIP
	}
	if event.RequestID == "" {
		event.RequestID = uuid.NewString()
	}
	event.StartedAt = time.Now().UTC()
	event.Outcome = "in_progress"
	event.AuthType = "anonymous"
	if event.Parameters == nil {
		event.Parameters = map[string]any{}
	}
	event.Summary = map[string]any{}
	s := &Span{Event: event, store: st, log: log, start: time.Now()}
	if p, ok := auth.FromContext(ctx); ok {
		s.SetPrincipal(p)
	} else if event.Surface == "mcp_stdio" {
		s.Event.AuthType = "local_process"
	}
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := st.StartAuditEvent(persist, &s.Event); err != nil {
		log.Error("audit start failed", "request_id", event.RequestID)
		return ctx, nil, err
	}
	return context.WithValue(ctx, spanKey{}, s), s, nil
}
func (s *Span) SetPrincipal(p *auth.Principal) {
	if p == nil {
		return
	}
	s.Event.AuthType = p.Kind
	s.Event.UserID = p.User.ID
	s.Event.Username = Text(p.User.Username)
	s.Event.Role = p.User.Role
	s.Event.APIKeyID = p.APIKeyID
	s.Event.APIKeyName = Text(p.APIKeyName)
}
func SetPrincipal(ctx context.Context, p *auth.Principal) error {
	if s := FromContext(ctx); s != nil {
		s.SetPrincipal(p)
		persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err := s.store.IdentifyAuditEvent(persist, &s.Event); err != nil {
			s.log.Error("audit identity persistence failed", "request_id", s.Event.RequestID)
			return err
		}
	}
	return nil
}

// Record the server-resolved time bounds and pinned Finding snapshot, including
// defaults that were not present in the caller's submitted parameters.
func FindingQuery(ctx context.Context, f model.AlertFilter) {
	s := FromContext(ctx)
	if s == nil {
		return
	}
	values := map[string]any{"provider": f.Provider, "account_id": f.AccountID, "account_uid": f.AccountUID, "region": f.Region, "resource_id": f.ExactResourceID, "resource_type": f.ResourceType, "resource": f.Resource, "severity": f.Severities, "status": f.Statuses, "keyword": f.Keyword, "ip": f.IP, "observable_type": f.ObservableType, "observable_value": f.ObservableValue, "rule_id": f.RuleID, "finding_kind": f.FindingKind, "vendor_status": f.VendorStatus, "after_id": f.AfterID, "sort": f.Sort, "group_by": f.GroupBy, "group_key": f.GroupKey, "limit": f.Limit, "offset": f.Offset, "asset_snapshot_sequence": f.AssetSnapshotSequence, "vendor_title": f.VendorTitle, "snapshot_sequence": f.SnapshotSequence}
	if f.Start != nil {
		values["start"] = f.Start.UTC().Format(time.RFC3339Nano)
	}
	if f.End != nil {
		values["end"] = f.End.UTC().Format(time.RFC3339Nano)
	}
	values["time_field"] = f.TimeField
	if f.TimeField == "" {
		values["time_field"] = "event_time"
	}
	for key, value := range values {
		v := object(reflect.ValueOf(value))
		if !v.IsValid() || ((v.Kind() == reflect.String || v.Kind() == reflect.Map || v.Kind() == reflect.Slice) && v.Len() == 0) {
			delete(values, key)
		}
	}
	s.Event.EffectiveQuery = Parameters(values)
}
func (s *Span) Finish(ctx context.Context, outcome, code string) {
	at := time.Now().UTC()
	s.Event.FinishedAt = &at
	s.Event.DurationMS = time.Since(s.start).Milliseconds()
	s.Event.Outcome = outcome
	s.Event.ErrorCode = code
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := s.store.FinishAuditEvent(persist, &s.Event); err != nil {
		s.log.Error("audit completion failed", "sequence", s.Event.Sequence, "request_id", s.Event.RequestID)
	}
	s.log.Info("audit", "sequence", s.Event.Sequence, "request_id", s.Event.RequestID, "surface", s.Event.Surface, "operation", s.Event.Operation, "tool", s.Event.Tool, "user_id", s.Event.UserID, "api_key_id", s.Event.APIKeyID, "outcome", outcome, "status", s.Event.HTTPStatus, "duration_ms", s.Event.DurationMS)
}
