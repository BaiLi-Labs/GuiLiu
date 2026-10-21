package asset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

// readAssetBody keeps one component response inside the 2 MiB asset budget and
// rejects truncated JSON instead of storing a partial source record.
func readAssetBody(r io.Reader) (json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("asset response exceeds size limit")
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("source response is not complete JSON")
	}
	return data, nil
}

// requireAKSK is the credential contract shared by the AK/SK clouds.
func requireAKSK(cred connector.Credential) error {
	if cred.AccessKeyID == "" || cred.AccessKeySecret == "" {
		return errors.New("AccessKey ID and Secret are required")
	}
	return nil
}

// Client is one cloud's read-only control-plane asset reader. Implementations
// request exact native IDs only; listing, scanning and inference are out of
// scope. Methods must not mutate the account or source records.
type Client interface {
	// ReadInstance reads one host by its native resource ID.
	ReadInstance(ctx context.Context, a model.Account, id string) (*model.Asset, error)
	// ReadNetwork reads network resources by exact native IDs. The returned
	// map must only contain the requested identities.
	ReadNetwork(ctx context.Context, a model.Account, kind string, ids []string) (map[string]*model.Asset, error)
	// ReadPolicies reads the security-group rule set as its own component.
	ReadPolicies(ctx context.Context, a model.Account, securityGroupID string) (model.AssetComponent, error)
}

// Provider declares how one cloud satisfies the bounded asset contract. The
// contract is the same as the Tencent CVM/VPC first version: identify a host,
// read its control-plane fields, and follow explicit native references.
type Provider struct {
	ID         string
	Name       string
	HostType   string
	APIVersion string
	// HostAPI and PolicyAPI are the human-readable source APIs recorded on
	// components, for example "CVM DescribeInstances".
	HostAPI   string
	PolicyAPI string
	// ResourceTypes lists the native resource kinds this provider supports,
	// host type first.
	ResourceTypes []string
	MapperVersion string
	DocsURL       string
	// PoliciesInDetails reports that the security-group detail response
	// already contains the rule set, so no second request is needed.
	PoliciesInDetails bool
	// RequiresRegion is true when the connection scope must pin a region.
	RequiresRegion bool
	// ValidateCredential checks the provider-specific credential bundle.
	ValidateCredential func(connector.Credential) error
	// ValidateAccount checks provider-specific non-secret connection options.
	ValidateAccount func(model.Account) error
	// SyntheticHostID is the fabricated native ID served in synthetic mode.
	SyntheticHostID string
	// HostID maps an alert's explicit primary resource to the native host ID
	// stored by this provider. It must not infer identity from IP or name.
	HostID func(model.Resource) (string, bool)
	// AlertResourceIDs returns the exact source resource IDs an alert for this
	// host may carry (for example native ID plus ARN). Nil means native only.
	AlertResourceIDs func(model.Account, string) []string
	// AlertHostType filters related Findings by the stored source resource
	// type. Empty means the provider cannot pin one stable type and matching
	// relies on the exact native ID alone.
	AlertHostType string
	Valid         func(kind, id string) bool
	QPS           float64
	// New builds a client from decrypted credentials. It must not perform any
	// network request.
	New func(connector.Credential, model.Account, *connector.Limiter) (Client, error)
	// Synthetic returns an offline client serving API-shaped fixtures.
	Synthetic func(*connector.Limiter) Client
}

var (
	providerMu sync.RWMutex
	providers  = map[string]Provider{}
)

func registerProvider(p Provider) {
	if p.ID == "" || p.HostType == "" || p.Valid == nil || p.New == nil || p.ValidateCredential == nil {
		panic(fmt.Sprintf("asset provider %q is incomplete", p.ID))
	}
	providerMu.Lock()
	defer providerMu.Unlock()
	if _, ok := providers[p.ID]; ok {
		panic("asset provider " + p.ID + " already registered")
	}
	providers[p.ID] = p
}

// ProviderFor returns a registered provider by its connector ID.
func ProviderFor(id string) (Provider, bool) {
	providerMu.RLock()
	defer providerMu.RUnlock()
	p, ok := providers[id]
	return p, ok
}

// Providers lists registered providers in stable ID order.
func Providers() []Provider {
	providerMu.RLock()
	defer providerMu.RUnlock()
	out := make([]Provider, 0, len(providers))
	for _, p := range providers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Supports reports whether the provider declares this resource kind.
func (p Provider) Supports(kind string) bool {
	for _, k := range p.ResourceTypes {
		if k == kind {
			return true
		}
	}
	return false
}

// NativeHostID returns the provider's native host identity for an alert
// resource, or false when the alert does not explicitly reference a host.
func NativeHostID(p Provider, r model.Resource) (string, bool) {
	if p.HostID == nil || r.ID == "" {
		return "", false
	}
	return p.HostID(r)
}
