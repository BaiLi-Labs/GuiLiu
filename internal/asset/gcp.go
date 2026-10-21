// Google Cloud control-plane assets.
//
// Source APIs (read-only, exact resource paths only):
//
//	Compute Instances.Get, Networks.Get, Subnetworks.Get, Firewalls.Get
//
// The API client is given an authenticated HTTP client whose transport captures
// the exact JSON response bytes before the typed client decodes them.
//
// GCP has no per-instance security-group attachment: firewalls are network
// scoped and selected by target tags. A host therefore carries VPC/subnet
// references only, and no policy set is attributed to it.
package asset

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

const gcpAPIVersion = "v1"
const gcpMapperVersion = "gcp-gce/v1"

var (
	gcpInstancePath = regexp.MustCompile(`^projects/[^/]+/zones/[^/]+/instances/[^/]+$`)
	gcpVPCNetwork   = regexp.MustCompile(`^projects/[^/]+/global/networks/[^/]+$`)
	gcpSubnetwork   = regexp.MustCompile(`^projects/[^/]+/regions/[^/]+/subnetworks/[^/]+$`)
	gcpFirewall     = regexp.MustCompile(`^projects/[^/]+/global/firewalls/[^/]+$`)
)

type gcpRawKey struct{}

type gcpRecorder struct {
	mu   sync.Mutex
	body []byte
}

func (r *gcpRecorder) store(data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.body = data
}

func (r *gcpRecorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body
}

type gcpCapture struct{ base http.RoundTripper }

func (t *gcpCapture) RoundTrip(req *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	recorder, ok := req.Context().Value(gcpRawKey{}).(*gcpRecorder)
	if !ok || response.Body == nil {
		return response, nil
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	response.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("asset response exceeds size limit")
	}
	recorder.store(data)
	response.Body = io.NopCloser(bytes.NewReader(data))
	return response, nil
}

// gcpRaw performs one exact resource read.
type gcpRaw func(ctx context.Context, action string, params map[string]string) (json.RawMessage, error)

// GcpRaw builds a Compute caller that keeps exact response bytes.
func GcpRaw(ctx context.Context, cred connector.Credential) (gcpRaw, error) {
	if cred.ServiceAccountJSON == "" {
		return nil, fmt.Errorf("GCP service account JSON is required")
	}
	credentials, err := google.CredentialsFromJSON(ctx, []byte(cred.ServiceAccountJSON), compute.ComputeScope)
	if err != nil {
		return nil, err
	}
	base := oauth2.NewClient(ctx, credentials.TokenSource)
	capture := &gcpCapture{base: base.Transport}
	service, err := compute.NewService(ctx, option.WithHTTPClient(&http.Client{Transport: capture, Timeout: 15 * time.Second}))
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, action string, params map[string]string) (json.RawMessage, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		recorder := &gcpRecorder{}
		ctx = context.WithValue(ctx, gcpRawKey{}, recorder)
		var callErr error
		switch action {
		case "Instance":
			_, callErr = service.Instances.Get(params["project"], params["zone"], params["name"]).Context(ctx).Do()
		case "Network":
			_, callErr = service.Networks.Get(params["project"], params["name"]).Context(ctx).Do()
		case "Subnetwork":
			_, callErr = service.Subnetworks.Get(params["project"], params["region"], params["name"]).Context(ctx).Do()
		case "Firewall":
			_, callErr = service.Firewalls.Get(params["project"], params["name"]).Context(ctx).Do()
		default:
			return nil, fmt.Errorf("unsupported asset action")
		}
		if callErr != nil {
			return nil, callErr
		}
		if raw := recorder.bytes(); len(raw) > 0 {
			return append(json.RawMessage(nil), raw...), nil
		}
		return nil, fmt.Errorf("GCP API returned no response bytes")
	}, nil
}

type gcpClient struct {
	raw     gcpRaw
	project string
	limiter *connector.Limiter
}

func (c *gcpClient) ReadInstance(ctx context.Context, a model.Account, id string) (*model.Asset, error) {
	return ReadGCP(ctx, a, id, c.raw, c.project, c.limiter)
}

func (c *gcpClient) ReadNetwork(ctx context.Context, a model.Account, kind string, ids []string) (map[string]*model.Asset, error) {
	return readGCPNetworkBatch(ctx, a, kind, ids, c.raw, c.limiter)
}

func (c *gcpClient) ReadPolicies(ctx context.Context, a model.Account, id string) (model.AssetComponent, error) {
	return model.AssetComponent{Status: "not_collected", Reason: "source_has_no_instance_security_group_attachment"}, nil
}

// gcpResourcePath normalizes full or relative Compute resource names.
func gcpResourcePath(value string) (string, bool) {
	v := strings.TrimSpace(value)
	v = strings.TrimPrefix(v, "https://www.googleapis.com/compute/v1/")
	v = strings.TrimPrefix(v, "//compute.googleapis.com/")
	v = strings.TrimPrefix(v, "/")
	if !strings.HasPrefix(v, "projects/") || strings.Contains(v, "..") {
		return "", false
	}
	return v, true
}

func gcpSegments(path string) []string {
	return strings.Split(path, "/")
}

func gcpNameAt(path string, key string) string {
	parts := gcpSegments(path)
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == key {
			return parts[i+1]
		}
	}
	return ""
}

// ReadGCP requests exactly one instance by its full resource path.
func ReadGCP(ctx context.Context, a model.Account, id string, raw gcpRaw, project string, limiter *connector.Limiter) (*model.Asset, error) {
	path, ok := gcpResourcePath(id)
	if !ok || !gcpInstancePath.MatchString(path) {
		return nil, fmt.Errorf("invalid Compute instance resource name")
	}
	if limiter != nil {
		if err := limiter.Wait(ctx); err != nil {
			return nil, err
		}
	}
	projectFromPath := gcpNameAt(path, "projects")
	if project == "" {
		project = projectFromPath
	}
	zone := gcpNameAt(path, "zones")
	name := gcpNameAt(path, "instances")
	payload, err := raw(ctx, "Instance", map[string]string{"project": project, "zone": zone, "name": name})
	if err != nil {
		return nil, err
	}
	var i struct {
		ID          string            `json:"id"`
		Name        string            `json:"name"`
		Status      string            `json:"status"`
		MachineType string            `json:"machineType"`
		Zone        string            `json:"zone"`
		Labels      map[string]string `json:"labels"`
		Tags        struct {
			Items []string `json:"items"`
		} `json:"tags"`
		Disks []struct {
			Licenses []string `json:"licenses"`
		} `json:"disks"`
		NetworkInterfaces []struct {
			Network       string `json:"network"`
			Subnetwork    string `json:"subnetwork"`
			NetworkIP     string `json:"networkIP"`
			Ipv6Address   string `json:"ipv6Address"`
			AccessConfigs []struct {
				NatIP string `json:"natIP"`
			} `json:"accessConfigs"`
		} `json:"networkInterfaces"`
	}
	if json.Unmarshal(payload, &i) != nil || i.Name != name {
		return nil, fmt.Errorf("instance identity mismatch")
	}
	if i.Zone != "" && gcpNameAt(i.Zone, "zones") != zone {
		return nil, fmt.Errorf("instance zone mismatch")
	}
	machine := i.MachineType
	if parts := gcpSegments(strings.TrimPrefix(machine, "https://www.googleapis.com/compute/v1/")); len(parts) > 0 {
		machine = parts[len(parts)-1]
	}
	var publicIPs, privateIPs []string
	var references []model.AssetReference
	vpcPaths, subnetPaths := map[string]string{}, map[string]string{}
	seenRef := map[string]bool{}
	for n, nic := range i.NetworkInterfaces {
		if nic.NetworkIP != "" {
			privateIPs = append(privateIPs, nic.NetworkIP)
		}
		if nic.Ipv6Address != "" {
			privateIPs = append(privateIPs, nic.Ipv6Address)
		}
		for _, config := range nic.AccessConfigs {
			if config.NatIP != "" {
				publicIPs = append(publicIPs, config.NatIP)
			}
		}
		if network, ok := gcpResourcePath(nic.Network); ok && !seenRef["vpc|"+network] {
			seenRef["vpc|"+network] = true
			vpcPaths[network] = fmt.Sprintf("/networkInterfaces/%d/network", n)
			references = append(references, reference(a, "vpc", network, "belongs_to_vpc", "instance", vpcPaths[network]))
		}
		if subnet, ok := gcpResourcePath(nic.Subnetwork); ok && !seenRef["subnet|"+subnet] {
			seenRef["subnet|"+subnet] = true
			subnetPaths[subnet] = fmt.Sprintf("/networkInterfaces/%d/subnetwork", n)
			references = append(references, reference(a, "subnet", subnet, "in_subnet", "instance", subnetPaths[subnet]))
		}
	}
	sort.Strings(publicIPs)
	sort.Strings(privateIPs)
	at := time.Now().UTC()
	out := &model.Asset{
		AccountID: a.ID, Provider: "gcp", AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: path, ResourceType: "gce", Name: i.Name, State: i.Status,
		InstanceType: machine, Zone: zone, PublicIPs: publicIPs, PrivateIPs: privateIPs,
		ObservedAt: at, MapperVersion: gcpMapperVersion,
		Components: map[string]model.AssetComponent{"instance": component(payload, "Compute Instances.Get", gcpAPIVersion, at)},
		Provenance: map[string]model.FieldOrigin{},
	}
	if len(references) > 0 {
		out.References = references
	}
	for _, ref := range out.References {
		switch ref.ResourceType {
		case "vpc":
			if out.VPCID == "" {
				out.VPCID = ref.ResourceID
				out.Provenance["vpc_id"] = model.FieldOrigin{Source: "component:instance", Paths: []string{vpcPaths[ref.ResourceID]}, Transform: "source_url_to_resource_path"}
			}
		case "subnet":
			if out.SubnetID == "" {
				out.SubnetID = ref.ResourceID
				out.Provenance["subnet_id"] = model.FieldOrigin{Source: "component:instance", Paths: []string{subnetPaths[ref.ResourceID]}, Transform: "source_url_to_resource_path"}
			}
		}
	}
	if len(i.Disks) > 0 && len(i.Disks[0].Licenses) > 0 {
		license := i.Disks[0].Licenses[0]
		if parts := gcpSegments(license); len(parts) > 0 {
			out.OS = parts[len(parts)-1]
			out.Provenance["os"] = model.FieldOrigin{Source: "component:instance", Paths: []string{"/disks/0/licenses"}, Transform: "source_license_projection"}
		}
	}
	if i.Labels != nil {
		keys := make([]string, 0, len(i.Labels))
		for key := range i.Labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.Tags = []model.AssetTag{}
		for _, key := range keys {
			out.Tags = append(out.Tags, model.AssetTag{Key: key, Value: i.Labels[key]})
		}
		out.Provenance["tags"] = model.FieldOrigin{Source: "component:instance", Paths: []string{"/labels"}, Transform: "source_map_projection"}
	}
	out.Provenance["resource_id"] = model.FieldOrigin{Source: "request_scope", Paths: []string{"/name"}, Transform: "resource_path_projection"}
	for field, path := range map[string]string{"name": "/name", "state": "/status", "instance_type": "/machineType", "zone": "/zone", "private_ips": "/networkInterfaces", "public_ips": "/networkInterfaces"} {
		if sourceHas(payload, path) {
			out.Provenance[field] = model.FieldOrigin{Source: "component:instance", Paths: []string{path}, Transform: "source_field_projection"}
		}
	}
	for field, path := range map[string]string{"account_uid": "/account_uid", "region": "/region"} {
		out.Provenance[field] = model.FieldOrigin{Source: "configuration", Paths: []string{path}, Transform: "explicit_connection_scope"}
	}
	out.Components["software"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["listening_ports"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["reachability"] = model.AssetComponent{Status: "not_collected", Reason: "source_not_connected"}
	out.Components["security_groups"] = model.AssetComponent{Status: "not_collected", Reason: "source_has_no_instance_security_group_attachment"}
	return out, nil
}

func gcpNetworkAction(kind string) (action, pattern, api string) {
	switch kind {
	case "vpc":
		return "Network", `^projects/[^/]+/global/networks/[^/]+$`, "Compute Networks.Get"
	case "subnet":
		return "Subnetwork", `^projects/[^/]+/regions/[^/]+/subnetworks/[^/]+$`, "Compute Subnetworks.Get"
	case "security_group":
		return "Firewall", `^projects/[^/]+/global/firewalls/[^/]+$`, "Compute Firewalls.Get"
	}
	return "", "", ""
}

func readGCPNetworkBatch(ctx context.Context, a model.Account, kind string, ids []string, raw gcpRaw, limiter *connector.Limiter) (map[string]*model.Asset, error) {
	action, pattern, api := gcpNetworkAction(kind)
	if action == "" || len(ids) == 0 || len(ids) > MaxSecurityGroups {
		return nil, fmt.Errorf("invalid network query scope")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	out := map[string]*model.Asset{}
	seen := map[string]bool{}
	for _, id := range ids {
		path, ok := gcpResourcePath(id)
		if !ok || !re.MatchString(path) || seen[path] {
			return nil, fmt.Errorf("invalid or repeated network ID")
		}
		seen[path] = true
		if limiter != nil {
			if err := limiter.Wait(ctx); err != nil {
				return nil, err
			}
		}
		params := map[string]string{"project": gcpNameAt(path, "projects"), "name": ""}
		switch kind {
		case "vpc", "security_group":
			params["name"] = gcpNameAt(path, "networks")
			if kind == "security_group" {
				params["name"] = gcpNameAt(path, "firewalls")
			}
		case "subnet":
			params["region"] = gcpNameAt(path, "regions")
			params["name"] = gcpNameAt(path, "subnetworks")
		}
		payload, err := raw(ctx, action, params)
		if err != nil {
			return nil, err
		}
		value, err := normalizeGCPNetwork(a, kind, path, api, payload)
		if err != nil {
			return nil, err
		}
		out[path] = value
	}
	return out, nil
}

func normalizeGCPNetwork(a model.Account, kind, path, api string, raw json.RawMessage) (*model.Asset, error) {
	var value struct {
		Name              string          `json:"name"`
		Description       string          `json:"description"`
		IPv4Range         string          `json:"IPv4Range"`
		IPCIDRRange       string          `json:"ipCidrRange"`
		Network           string          `json:"network"`
		Region            string          `json:"region"`
		CreationTimestamp string          `json:"creationTimestamp"`
		AutoCreate        *bool           `json:"autoCreateSubnetworks"`
		PrivateGoogle     *bool           `json:"privateIpGoogleAccess"`
		Direction         string          `json:"direction"`
		Priority          *int64          `json:"priority"`
		Disabled          *bool           `json:"disabled"`
		SourceRanges      []string        `json:"sourceRanges"`
		TargetTags        []string        `json:"targetTags"`
		Allowed           json.RawMessage `json:"allowed"`
		Denied            json.RawMessage `json:"denied"`
	}
	if err := json.Unmarshal(raw, &value); err != nil || gcpNameAt(path, gcpKindSegment(kind)) != value.Name {
		return nil, fmt.Errorf("network identity mismatch")
	}
	at := time.Now().UTC()
	out := &model.Asset{
		AccountID: a.ID, Provider: "gcp", AccountUID: a.AccountUID, Region: a.Region,
		ResourceID: path, ResourceType: kind, Name: value.Name, ObservedAt: at,
		MapperVersion: "gcp-network/v1",
		Components:    map[string]model.AssetComponent{"details": component(raw, api, gcpAPIVersion, at)},
		Provenance:    map[string]model.FieldOrigin{},
		Network:       &model.AssetNetwork{Description: value.Description, CIDRBlock: firstNonEmpty(value.IPCIDRRange, value.IPv4Range), IsDefault: nil, SourceCreatedTime: value.CreationTimestamp},
	}
	paths := map[string]string{"resource_id": "/name", "name": "/name", "network.cidr_block": "/ipCidrRange", "network.source_created_time": "/creationTimestamp", "network.description": "/description"}
	switch kind {
	case "vpc":
		out.VPCID = path
		out.Provenance["vpc_id"] = model.FieldOrigin{Source: "request_scope", Paths: []string{"/name"}, Transform: "resource_path_projection"}
		if value.IPv4Range != "" {
			paths["network.cidr_block"] = "/IPv4Range"
		}
	case "subnet":
		out.SubnetID = path
		out.Provenance["subnet_id"] = model.FieldOrigin{Source: "request_scope", Paths: []string{"/name"}, Transform: "resource_path_projection"}
		if network, ok := gcpResourcePath(value.Network); ok {
			out.VPCID = network
			out.References = []model.AssetReference{reference(a, "vpc", network, "belongs_to_vpc", "details", "/network")}
			paths["vpc_id"] = "/network"
		}
		// The native region stays inside the resource path and the component
		// evidence. Asset.Region is the connection scope so that references
		// from a host resolve to the same identity scope.
	case "security_group":
		if network, ok := gcpResourcePath(value.Network); ok {
			out.VPCID = network
			paths["vpc_id"] = "/network"
		}
		out.Components["policies"] = component(raw, api, gcpAPIVersion, at)
	}
	for field, path := range paths {
		if sourceHas(raw, path) {
			out.Provenance[field] = model.FieldOrigin{Source: "component:details", Paths: []string{path}, Transform: "source_field_projection"}
		}
	}
	for field, path := range map[string]string{"account_uid": "/account_uid", "region": "/region"} {
		if _, exists := out.Provenance[field]; exists {
			continue
		}
		out.Provenance[field] = model.FieldOrigin{Source: "configuration", Paths: []string{path}, Transform: "explicit_connection_scope"}
	}
	return out, nil
}

func gcpKindSegment(kind string) string {
	switch kind {
	case "vpc":
		return "networks"
	case "subnet":
		return "subnetworks"
	case "security_group":
		return "firewalls"
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// ValidGCPResource validates normalized Compute resource paths.
func ValidGCPResource(kind, id string) bool {
	path, ok := gcpResourcePath(id)
	if !ok || len(path) > 300 {
		return false
	}
	switch kind {
	case "gce":
		return gcpInstancePath.MatchString(path)
	case "vpc":
		return gcpVPCNetwork.MatchString(path)
	case "subnet":
		return gcpSubnetwork.MatchString(path)
	case "security_group":
		return gcpFirewall.MatchString(path)
	}
	return false
}

func init() {
	registerProvider(Provider{
		ID:            "gcp",
		Name:          "Google Cloud",
		HostType:      "gce",
		APIVersion:    gcpAPIVersion,
		HostAPI:       "Compute Instances.Get",
		PolicyAPI:     "Compute Firewalls.Get",
		ResourceTypes: []string{"gce", "security_group", "vpc", "subnet"},
		MapperVersion: gcpMapperVersion,
		// Firewalls are network scoped and not attached to a host, so a
		// host refresh never claims a policy set.
		PoliciesInDetails: true,
		RequiresRegion:    false,
		DocsURL:           "https://cloud.google.com/compute/docs/reference/rest/v1/instances/get",
		SyntheticHostID:   SyntheticGCPInstanceID,
		HostID: func(r model.Resource) (string, bool) {
			switch strings.ToLower(r.Type) {
			case "host", "instance", "instances", "gce", "computeinstance", "google.compute.instance":
			default:
				return "", false
			}
			path, ok := gcpResourcePath(r.ID)
			if !ok || !gcpInstancePath.MatchString(path) {
				return "", false
			}
			return path, true
		},
		AlertResourceIDs: func(a model.Account, native string) []string {
			return []string{native, "//compute.googleapis.com/" + native}
		},
		Valid: ValidGCPResource,
		QPS:   2,
		ValidateCredential: func(cred connector.Credential) error {
			if cred.ServiceAccountJSON == "" {
				return fmt.Errorf("GCP service account JSON is required")
			}
			return nil
		},
		New: func(cred connector.Credential, a model.Account, limiter *connector.Limiter) (Client, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			raw, err := GcpRaw(ctx, cred)
			if err != nil {
				return nil, err
			}
			project := ""
			if a.Options != nil {
				project = a.Options["project"]
			}
			if project == "" {
				project = a.AccountUID
			}
			return &gcpClient{raw: raw, project: project, limiter: limiter}, nil
		},
		Synthetic: func(limiter *connector.Limiter) Client {
			return &gcpClient{raw: SyntheticGCPRaw(), project: SyntheticGCPProject, limiter: limiter}
		},
	})
}
