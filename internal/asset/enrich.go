package asset

import (
	"context"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

type RelatedRefresh struct {
	Reference model.AssetReference `json:"reference"`
	Status    string               `json:"status"`
}

// enrichNetworks adds at most three metadata requests to the CVM refresh:
// one SG batch, one VPC, one subnet. Policies are reused from the host request.
// Shared network metadata is cached independently of each host.
func (s *Service) enrichNetworks(ctx context.Context, a model.Account, p Provider, host *model.Asset, client Client) ([]RelatedRefresh, bool, error) {
	results := []RelatedRefresh{}
	partial := false
	for _, kind := range []string{"security_group", "vpc", "subnet"} {
		if ctx.Err() != nil {
			for _, ref := range host.References {
				if ref.ResourceType == kind {
					results = append(results, RelatedRefresh{ref, "timeout"})
					partial = true
				}
			}
			continue
		}
		pending := []model.AssetReference{}
		attempts := map[string]model.AssetRefresh{}
		seen := map[string]bool{}
		for _, ref := range host.References {
			if ref.ResourceType != kind || seen[ref.ResourceID] {
				continue
			}
			seen[ref.ResourceID] = true
			if !p.Valid(kind, ref.ResourceID) {
				results = append(results, RelatedRefresh{ref, "invalid_source_reference"})
				partial = true
				continue
			}
			if len(seen) > MaxSecurityGroups {
				results = append(results, RelatedRefresh{ref, "request_budget_exceeded"})
				partial = true
				continue
			}
			cached, err := s.Store.ListAssets(ctx, model.AssetFilter{Provider: a.Provider, AccountUID: a.AccountUID, Region: a.Region, ResourceID: ref.ResourceID, ResourceType: kind, Limit: 1})
			if err != nil {
				return results, true, err
			}
			if len(cached) > 0 && s.now().Sub(cached[0].LastObservedAt) < CacheTTL {
				results = append(results, RelatedRefresh{ref, "cached"})
				continue
			}
			attempt := model.AssetRefresh{AccountID: a.ID, Region: a.Region, ResourceID: ref.ResourceID, AttemptedAt: s.now().UTC(), Status: "refreshing"}
			claimed, err := s.Store.BeginAssetRefresh(ctx, attempt, CacheTTL)
			if err != nil {
				return results, true, err
			}
			if !claimed {
				old, err := s.Store.GetAssetRefresh(ctx, a.ID, a.Region, ref.ResourceID)
				if err != nil {
					return results, true, err
				}
				results = append(results, RelatedRefresh{ref, old.Status})
				if old.Status != "available" {
					partial = true
				}
				continue
			}
			pending = append(pending, ref)
			attempts[ref.ResourceID] = attempt
		}
		if len(pending) == 0 {
			continue
		}
		ids := make([]string, 0, len(pending))
		for _, ref := range pending {
			ids = append(ids, ref.ResourceID)
		}
		items, fetchErr := client.ReadNetwork(ctx, a, kind, ids)
		for _, ref := range pending {
			attempt := attempts[ref.ResourceID]
			attempt.Status = "available"
			if fetchErr != nil {
				attempt.Status = errorCode(fetchErr, p.ID)
			} else if items[ref.ResourceID] == nil {
				attempt.Status = "not_found_or_not_visible"
			} else {
				value := items[ref.ResourceID]
				value.Synthetic = s.Synthetic
				if kind == "security_group" {
					c, ok := host.Components["security_group:"+ref.ResourceID]
					if !ok {
						c = model.AssetComponent{Status: "not_collected", Reason: "request_budget_exceeded"}
					}
					value.Components["policies"] = c
					if c.Status != "available" {
						attempt.Status = "partial"
					}
				}
				if err := s.saveObservation(ctx, value); err != nil {
					attempt.Status = "storage_failed"
				}
			}
			finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			err := s.Store.FinishAssetRefresh(finishCtx, attempt)
			cancel()
			if err != nil {
				return results, true, err
			}
			results = append(results, RelatedRefresh{ref, attempt.Status})
			if attempt.Status != "available" {
				partial = true
			}
		}
	}
	return results, partial, nil
}
