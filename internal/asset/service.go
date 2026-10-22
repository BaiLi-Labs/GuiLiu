package asset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/credential"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

var ErrInvalidRequest = errors.New("invalid asset request")
var ErrNotVisible = errors.New("resource not visible in this scope")

const CacheTTL = 5 * time.Minute

type Service struct {
	Store     store.Store
	Cipher    *secret.Cipher
	Synthetic bool
	// Factory builds the Tencent raw caller. It defaults to TencentCall and
	// exists so tests can inject API-shaped responses; other providers always
	// use their registered Provider.New.
	Factory func(connector.Credential, string) Call
	limiter *connector.Limiter
	now     func() time.Time

	limiterMu sync.Mutex
	limiters  map[string]*connector.Limiter
}

func New(st store.Store, cipher *secret.Cipher, synthetic bool) *Service {
	return &Service{
		Store: st, Cipher: cipher, Synthetic: synthetic,
		Factory:  TencentCall,
		limiter:  connector.NewLimiter(2),
		now:      time.Now,
		limiters: map[string]*connector.Limiter{},
	}
}

type RefreshResult struct {
	Status       string              `json:"status"`
	Attempt      *model.AssetRefresh `json:"attempt,omitempty"`
	Asset        *model.Asset        `json:"asset,omitempty"`
	CacheSeconds int                 `json:"cache_seconds"`
	Related      []RelatedRefresh    `json:"related,omitempty"`
}

// errorCode maps a source failure to a stable, non-secret reason. Provider
// classification is used only to distinguish authorization problems.
func errorCode(err error, provider string) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	if provider != "" && connector.AuthError(connector.Classify(provider, err)) {
		return "permission_denied"
	}
	if errors.Is(err, ErrNotVisible) {
		return "not_found_or_not_visible"
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "notfound") || strings.Contains(lower, "not found") || strings.Contains(lower, "does not exist") {
		return "not_found_or_not_visible"
	}
	// Never expose SDK error messages, request signatures, or response payloads.
	return "source_request_failed"
}

func (s *Service) limiterFor(p Provider) *connector.Limiter {
	if p.ID == "tencent" {
		return s.limiter
	}
	s.limiterMu.Lock()
	defer s.limiterMu.Unlock()
	if s.limiters == nil {
		s.limiters = map[string]*connector.Limiter{}
	}
	if l, ok := s.limiters[p.ID]; ok {
		return l
	}
	qps := p.QPS
	if qps <= 0 {
		qps = 2
	}
	l := connector.NewLimiter(qps)
	s.limiters[p.ID] = l
	return l
}

// client resolves the provider client for this connection. Credentials are
// decrypted only here; source payloads never include them.
func (s *Service) client(ctx context.Context, a model.Account, p Provider) (Client, error) {
	limiter := s.limiterFor(p)
	if s.Synthetic {
		// Offline fixtures must not be throttled by a live-source budget.
		return p.Synthetic(connector.NewLimiter(100000)), nil
	}
	cred, err := credential.Load(ctx, s.Store, s.Cipher, a.ID)
	if err != nil {
		return nil, err
	}
	if err := p.ValidateCredential(cred); err != nil {
		return nil, err
	}
	if p.ID == "tencent" && s.Factory != nil {
		return &tencentClient{call: s.Factory(cred, a.Region), limiter: limiter, nicCache: &nicCache{}}, nil
	}
	return p.New(cred, a, limiter)
}

func (s *Service) Refresh(ctx context.Context, accountID, kind, id string) (*RefreshResult, error) {
	a, err := s.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	p, ok := ProviderFor(a.Provider)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported provider %q", ErrInvalidRequest, a.Provider)
	}
	if kind == "" {
		kind = p.HostType
	}
	regionMissing := p.RequiresRegion && a.Region == ""
	if !a.Enabled || a.AccountUID == "" || regionMissing || !p.Valid(kind, id) {
		return nil, fmt.Errorf("%w: enabled %s connection, explicit account UID, required region scope and valid resource type/ID required", ErrInvalidRequest, p.Name)
	}
	if p.ValidateAccount != nil {
		if err := p.ValidateAccount(*a); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
		}
	}
	attempt := model.AssetRefresh{AccountID: a.ID, Region: a.Region, ResourceID: id, AttemptedAt: s.now().UTC(), Status: "refreshing"}
	claimed, err := s.Store.BeginAssetRefresh(ctx, attempt, CacheTTL)
	if err != nil {
		return nil, err
	}
	result := &RefreshResult{CacheSeconds: int(CacheTTL.Seconds())}
	if !claimed {
		result.Status = "cached"
		result.Attempt, err = s.Store.GetAssetRefresh(ctx, a.ID, a.Region, id)
		if err != nil {
			return nil, err
		}
	} else {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		var value *model.Asset
		var client Client
		if client, err = s.client(ctx, *a, p); err == nil && client != nil {
			if kind == p.HostType {
				value, err = client.ReadInstance(ctx, *a, id)
			} else {
				var items map[string]*model.Asset
				items, err = client.ReadNetwork(ctx, *a, kind, []string{id})
				if err == nil {
					value = items[id]
					if value == nil {
						err = ErrNotVisible
					}
				}
				if err == nil && kind == "security_group" && !p.PoliciesInDetails {
					component, policyErr := client.ReadPolicies(ctx, *a, id)
					if policyErr != nil {
						component = model.AssetComponent{Status: "failed", Reason: errorCode(policyErr, p.ID), SourceAPI: p.PolicyAPI, APIVersion: p.APIVersion}
					}
					value.Components["policies"] = component
				}
			}
			if value != nil {
				value.Synthetic = s.Synthetic
			}
		}
		if err == nil && client == nil {
			err = errors.New("asset client unavailable")
		}
		if err == nil && value == nil {
			err = ErrNotVisible
		}
		attempt.Status = "available"
		if err != nil {
			attempt.Status = errorCode(err, p.ID)
		} else {
			for key, c := range value.Components {
				if (strings.HasPrefix(key, "security_group:") || key == "policies" || key == "network_interfaces") && c.Status != "available" {
					attempt.Status = "partial"
				}
			}
			if kind == p.HostType {
				var partial bool
				result.Related, partial, err = s.enrichNetworks(ctx, *a, p, value, client)
				if partial {
					attempt.Status = "partial"
				}
				if err != nil {
					attempt.Status = "storage_failed"
				}
			}
			if err = s.saveObservation(ctx, value); err != nil {
				attempt.Status = "storage_failed"
			}
		}
		// Persist attempt status even if the caller disconnected or timed out.
		finishCtx, finishCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer finishCancel()
		if finishErr := s.Store.FinishAssetRefresh(finishCtx, attempt); finishErr != nil {
			return nil, finishErr
		}
		result.Status = attempt.Status
		result.Attempt = &attempt
	}
	readCtx, readCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer readCancel()
	items, err := s.Store.ListAssets(readCtx, model.AssetFilter{Provider: a.Provider, AccountUID: a.AccountUID, Region: a.Region, ResourceID: id, ResourceType: kind, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(items) > 0 {
		result.Asset = &items[0]
	}
	return result, nil
}

// A failed optional network lookup must not discard an already-read instance.
func (s *Service) saveObservation(ctx context.Context, value *model.Asset) error {
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return s.Store.SaveAsset(persist, value)
}
