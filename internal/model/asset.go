package model

import (
	"encoding/json"
	"time"
)

// Asset is an independent control-plane observation, never embedded in Alert.
// Its revision and observation times are independent of the Finding change log.
type Asset struct {
	ID               string                    `json:"id"`
	AccountID        string                    `json:"account_id"`
	Provider         string                    `json:"provider"`
	AccountUID       string                    `json:"account_uid"`
	Region           string                    `json:"region"`
	ResourceID       string                    `json:"resource_id"`
	ResourceType     string                    `json:"resource_type"`
	Name             string                    `json:"name,omitempty"`
	OS               string                    `json:"os,omitempty"`
	State            string                    `json:"state,omitempty"`
	InstanceType     string                    `json:"instance_type,omitempty"`
	Zone             string                    `json:"zone,omitempty"`
	PublicIPs        []string                  `json:"public_ips"`
	PrivateIPs       []string                  `json:"private_ips"`
	VPCID            string                    `json:"vpc_id,omitempty"`
	SubnetID         string                    `json:"subnet_id,omitempty"`
	SecurityGroupIDs []string                  `json:"security_group_ids"`
	Tags             []AssetTag                `json:"tags"`
	Components       map[string]AssetComponent `json:"components"`
	Provenance       map[string]FieldOrigin    `json:"provenance"`
	MapperVersion    string                    `json:"mapper_version"`
	Revision         int                       `json:"revision"`
	ObservedAt       time.Time                 `json:"observed_at"`
	LastObservedAt   time.Time                 `json:"last_observed_at"`
	Synthetic        bool                      `json:"synthetic"`
}

type AssetTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type AssetComponent struct {
	Status     string          `json:"status"`
	Reason     string          `json:"reason,omitempty"`
	SourceAPI  string          `json:"source_api,omitempty"`
	APIVersion string          `json:"api_version,omitempty"`
	ObservedAt *time.Time      `json:"observed_at,omitempty"`
	RawHash    string          `json:"raw_hash,omitempty"`
	Raw        json.RawMessage `json:"raw,omitempty"`
	RawURL     string          `json:"raw_url,omitempty"`
}

type AssetFilter struct {
	Provider, AccountID, AccountUID, Region, ResourceID, AfterID string
	Limit                                                        int
}

// AssetRefresh records operational state separately from source observations.
type AssetRefresh struct {
	AccountID   string    `json:"account_id"`
	Region      string    `json:"region"`
	ResourceID  string    `json:"resource_id"`
	Status      string    `json:"status"`
	AttemptedAt time.Time `json:"attempted_at"`
}
