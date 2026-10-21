package asset

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/credential"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"github.com/BaiLi-Labs/GuiLiu/internal/secret"
	"github.com/BaiLi-Labs/GuiLiu/internal/store"
)

var ErrInvalidRequest = errors.New("invalid asset request")
var ErrNotVisible = errors.New("instance not visible in this scope")

const CacheTTL = 5 * time.Minute

type Service struct {
	Store     store.Store
	Cipher    *secret.Cipher
	Synthetic bool
	Factory   func(connector.Credential, string) Call
	limiter   *connector.Limiter
	now       func() time.Time
}

func New(st store.Store, cipher *secret.Cipher, synthetic bool) *Service {
	return &Service{Store: st, Cipher: cipher, Synthetic: synthetic, Factory: TencentCall, limiter: connector.NewLimiter(2), now: time.Now}
}

type RefreshResult struct {
	Status       string              `json:"status"`
	Attempt      *model.AssetRefresh `json:"attempt,omitempty"`
	Asset        *model.Asset        `json:"asset,omitempty"`
	CacheSeconds int                 `json:"cache_seconds"`
}

func errorCode(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	if connector.AuthError(connector.Classify("tencent", err)) {
		return "permission_denied"
	}
	if errors.Is(err, ErrNotVisible) {
		return "not_found_or_not_visible"
	}
	// Never expose SDK error messages, request signatures, or response payloads.
	return "source_request_failed"
}

func (s *Service) Refresh(ctx context.Context, accountID, id string) (*RefreshResult, error) {
	a, err := s.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if a.Provider != "tencent" || !a.Enabled || a.AccountUID == "" || a.Region == "" || !instanceID.MatchString(id) {
		return nil, fmt.Errorf("%w: enabled Tencent connection, explicit account UID, region and CVM instance ID required", ErrInvalidRequest)
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
		if s.Synthetic {
			value, err = SyntheticTencent(ctx, *a, id, s.limiter)
		} else {
			var cred connector.Credential
			cred, err = credential.Load(ctx, s.Store, s.Cipher, a.ID)
			if err == nil && (cred.AccessKeyID == "" || cred.AccessKeySecret == "") {
				err = errors.New("missing credential")
			}
			if err == nil {
				value, err = ReadTencent(ctx, *a, id, s.Factory(cred, a.Region), s.limiter)
			}
		}
		attempt.Status = "available"
		if err != nil {
			attempt.Status = errorCode(err)
		} else {
			for key, c := range value.Components {
				if strings.HasPrefix(key, "security_group:") && c.Status != "available" {
					attempt.Status = "partial"
				}
			}
			if err = s.Store.SaveAsset(ctx, value); err != nil {
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
	items, err := s.Store.ListAssets(context.WithoutCancel(ctx), model.AssetFilter{Provider: a.Provider, AccountUID: a.AccountUID, Region: a.Region, ResourceID: id, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(items) > 0 {
		result.Asset = &items[0]
	}
	return result, nil
}
