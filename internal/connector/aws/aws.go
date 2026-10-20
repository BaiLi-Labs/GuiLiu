// Package aws implements the AWS Security Hub connector using the OCSF
// GetFindingsV2 API.
package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/BaiLi-Labs/GuiLiu/internal/connector"
	"github.com/BaiLi-Labs/GuiLiu/internal/model"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
)

const (
	providerID      = "aws"
	mapperVersion   = "aws-securityhub-ocsf/v1"
	defaultRegion   = "us-east-1"
	defaultPageSize = 100
	defaultQPS      = 5
)

func init() {
	connector.Register(descriptor(), New)
}

func descriptor() connector.Descriptor {
	return connector.Descriptor{
		ID:            providerID,
		Name:          "AWS",
		Vendor:        "Amazon Web Services",
		Product:       "Security Hub",
		ProductUID:    "aws.securityhub",
		APIVersion:    "2018-10-26",
		DocsURL:       "https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingsV2.html",
		MapperVersion: mapperVersion,
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "Access Key ID", Help: "留空使用 IAM Role / 环境默认凭据"},
			{Name: "access_key_secret", Label: "Secret Access Key", Secret: true, Help: "留空使用 IAM Role / 环境默认凭据"},
			{Name: "session_token", Label: "Session Token", Secret: true, Help: "可选，临时凭据"},
		},
		Products: []connector.Product{
			{Code: "SecurityHub", Name: "Security Hub"},
			{Code: "GuardDuty", Name: "GuardDuty findings via Security Hub"},
			{Code: "Inspector", Name: "Inspector findings via Security Hub"},
		},
	}
}

// Connector talks to AWS Security Hub.
type Connector struct {
	client   *securityhub.Client
	limiter  *connector.Limiter
	pageSize int
}

func New(cfg connector.AccountConfig) (connector.Connector, error) {
	region := cfg.Region
	if region == "" {
		region = defaultRegion
	}
	loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if cfg.Credential.AccessKeyID != "" || cfg.Credential.AccessKeySecret != "" {
		if cfg.Credential.AccessKeyID == "" || cfg.Credential.AccessKeySecret == "" {
			return nil, connector.ConfigError(providerID, "access_key_id and access_key_secret must be provided together")
		}
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				cfg.Credential.AccessKeyID,
				cfg.Credential.AccessKeySecret,
				cfg.Credential.SessionToken,
			),
		))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), loadOpts...)
	if err != nil {
		return nil, connector.ConfigError(providerID, "load AWS config: "+err.Error())
	}
	endpoint := cfg.Options["endpoint"]
	client := securityhub.NewFromConfig(awsCfg, func(o *securityhub.Options) {
		if endpoint != "" {
			o.BaseEndpoint = awssdk.String(endpoint)
		}
	})
	return &Connector{
		client:   client,
		limiter:  connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", defaultQPS)),
		pageSize: connector.OptionInt(cfg.Options, "page_size", defaultPageSize),
	}, nil
}

func (c *Connector) Info() connector.Descriptor { return descriptor() }

func (c *Connector) Check(ctx context.Context) error {
	end := time.Now().UTC()
	_, err := c.Fetch(ctx, connector.Query{Start: end.Add(-time.Hour), End: end, PageSize: 1})
	return err
}

func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	if err := ctx.Err(); err != nil {
		return connector.Page{}, err
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return connector.Page{}, err
	}
	pageSize := q.PageSize
	if pageSize <= 0 {
		pageSize = c.pageSize
	}
	if pageSize > 100 {
		pageSize = 100
	}
	start := q.Start.UTC().Format(time.RFC3339)
	end := q.End.UTC().Format(time.RFC3339)
	filters := &types.OcsfFindingFilters{
		CompositeOperator: types.AllowedOperatorsAnd,
		CompositeFilters: []types.CompositeFilter{{
			Operator: types.AllowedOperatorsAnd,
			DateFilters: []types.OcsfDateFilter{{
				FieldName: types.OcsfDateFieldFindingInfoLastSeenTimeDt,
				Filter:    &types.DateFilter{Start: &start, End: &end},
			}},
		}},
	}
	input := &securityhub.GetFindingsV2Input{
		Filters:    filters,
		MaxResults: awssdk.Int32(int32(pageSize)),
	}
	if q.Token != "" {
		input.NextToken = awssdk.String(q.Token)
	}
	resp, err := c.client.GetFindingsV2(ctx, input)
	if err != nil {
		return connector.Page{}, connector.Classify(providerID, err)
	}
	records := make([]connector.RawAlert, 0, len(resp.Findings))
	for _, finding := range resp.Findings {
		raw, err := finding.MarshalSmithyDocument()
		if err != nil {
			return connector.Page{}, fmt.Errorf("encode AWS OCSF finding: %w", err)
		}
		records = append(records, connector.RawAlert{Raw: raw})
	}
	next := ""
	if resp.NextToken != nil {
		next = *resp.NextToken
	}
	return connector.Page{Records: records, NextToken: next, Total: len(records)}, nil
}

func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	var finding map[string]any
	if err := json.Unmarshal(raw, &finding); err != nil {
		return model.Alert{}, fmt.Errorf("decode AWS finding: %w", err)
	}
	alert, err := normalizeFinding(finding, raw)
	if err != nil {
		return model.Alert{}, err
	}
	return alert, nil
}
