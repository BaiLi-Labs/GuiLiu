package connector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aws/smithy-go"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"golang.org/x/oauth2"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestOfficialSDKErrors(t *testing.T) {
	const secret = "DO_NOT_LEAK_SIGNATURE_OR_CREDENTIAL"
	tc := func(code string) error { return tcerrors.NewTencentCloudSDKError(code, secret, "synthetic-request") }
	ali := func(code string, status int) error {
		return &tea.SDKError{Code: tea.String(code), StatusCode: tea.Int(status), Message: tea.String(secret), AccessDeniedDetail: map[string]interface{}{"AuthPrincipalOwnerId": secret}}
	}
	aws := func(code string) error {
		return &smithy.OperationError{ServiceID: "EC2", OperationName: "DescribeInstances", Err: &smithy.GenericAPIError{Code: code, Message: secret}}
	}
	tests := []struct {
		provider string
		err      error
		kind     ErrorKind
		code     string
		http     int
	}{
		{"tencent", tc("UnauthorizedOperation"), KindPermission, "UnauthorizedOperation", 0},
		{"tencent", tc("AuthFailure.UnauthorizedOperation"), KindPermission, "AuthFailure.UnauthorizedOperation", 0},
		{"tencent", tc("AuthFailure.SecretIdNotFound"), KindAuth, "AuthFailure.SecretIdNotFound", 0},
		{"tencent", tc("AuthFailure.SignatureFailure"), KindAuth, "AuthFailure.SignatureFailure", 0},
		{"tencent", tc("RequestLimitExceeded"), KindThrottled, "RequestLimitExceeded", 0},
		{"tencent", tc("LimitExceeded"), KindPermanent, "LimitExceeded", 0},
		{"tencent", tc("ResourceNotFound"), KindNotFound, "ResourceNotFound", 0},
		{"tencent", tc("NewVendorCode"), KindPermanent, "NewVendorCode", 0},
		{"tencent", tc("ClientError.NetworkError"), KindTransient, "ClientError.NetworkError", 0},
		{"aliyun", ali("Forbidden.RAM", 403), KindPermission, "Forbidden.RAM", 403},
		{"aliyun", ali("NoPermission", 403), KindPermission, "NoPermission", 403},
		{"aliyun", ali("InvalidAccessKeyId.NotFound", 403), KindAuth, "InvalidAccessKeyId.NotFound", 403},
		{"aliyun", ali("Forbidden.RiskControl", 403), KindDenied, "Forbidden.RiskControl", 403},
		{"aliyun", ali("Throttling.User", 400), KindThrottled, "Throttling.User", 400},
		{"aws", aws("UnauthorizedOperation"), KindPermission, "UnauthorizedOperation", 0},
		{"aws", aws("Client.UnauthorizedOperation"), KindPermission, "Client.UnauthorizedOperation", 0},
		{"aws", aws("AccessDeniedException"), KindPermission, "AccessDeniedException", 0},
		{"aws", aws("AuthFailure"), KindAuth, "AuthFailure", 0},
		{"aws", aws("ExpiredToken"), KindAuth, "ExpiredToken", 0},
		{"aws", aws("RequestLimitExceeded"), KindThrottled, "RequestLimitExceeded", 0},
		{"aws", aws("InvalidInstanceID.NotFound"), KindNotFound, "InvalidInstanceID.NotFound", 0},
		{"huawei", &sdkerr.ServiceResponseError{StatusCode: 403, ErrorCode: "Ecs.0003", ErrorMessage: secret}, KindDenied, "Ecs.0003", 403},
		{"huawei", &sdkerr.ServiceResponseError{StatusCode: 401, ErrorCode: "Common.0013", ErrorMessage: secret}, KindAuth, "Common.0013", 401},
		{"azure", &azcore.ResponseError{StatusCode: 403, ErrorCode: "AuthorizationFailed"}, KindPermission, "AuthorizationFailed", 403},
		{"azure", &azcore.ResponseError{StatusCode: 401, ErrorCode: "InvalidAuthenticationToken"}, KindAuth, "InvalidAuthenticationToken", 401},
		{"azure", &azcore.ResponseError{StatusCode: 403, ErrorCode: "SubscriptionDisabled"}, KindDenied, "SubscriptionDisabled", 403},
		{"azure", &azidentity.AuthenticationFailedError{RawResponse: &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(secret))}}, KindTransient, "", 503},
		{"gcp", &googleapi.Error{Code: 403, Message: secret, Errors: []googleapi.ErrorItem{{Reason: "forbidden", Message: secret}}}, KindDenied, "forbidden", 403},
		{"gcp", &googleapi.Error{Code: 403, Message: secret, Details: []interface{}{map[string]interface{}{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED", "metadata": map[string]interface{}{"consumer": secret}}}}, KindDenied, "SERVICE_DISABLED", 403},
		{"gcp", &googleapi.Error{Code: 401, Message: secret}, KindAuth, "", 401},
		{"gcp", &googleapi.Error{Code: 429, Message: secret}, KindThrottled, "", 429},
		{"gcp", status.Error(codes.PermissionDenied, secret), KindDenied, "PermissionDenied", 0},
		{"gcp", status.Error(codes.Unauthenticated, secret), KindAuth, "Unauthenticated", 0},
		{"gcp", &oauth2.RetrieveError{ErrorCode: "invalid_grant", ErrorDescription: secret, Response: &http.Response{StatusCode: 400}}, KindAuth, "invalid_grant", 400},
	}
	for _, tt := range tests {
		t.Run(tt.provider+"/"+tt.code+"/"+string(tt.kind), func(t *testing.T) {
			wrapped := fmt.Errorf("outer %s: %w", secret, tt.err)
			err := Classify(tt.provider, wrapped)
			var got *Error
			if !errors.As(err, &got) || got.Kind != tt.kind || got.Code != tt.code || got.HTTPStatus != tt.http {
				t.Fatalf("unexpected classification: %+v", got)
			}
			if !errors.Is(err, tt.err) {
				t.Fatal("SDK error chain lost")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("source error message leaked")
			}
			if Retryable(err) != (tt.kind == KindThrottled || tt.kind == KindTransient) {
				t.Fatal("wrong retry policy")
			}
			if tt.provider == "aws" && got.SourceAPI != "EC2 DescribeInstances" {
				t.Fatal("SDK operation lost")
			}
		})
	}
}

func TestUnstructuredMessagesDoNotEstablishSourceFacts(t *testing.T) {
	for _, provider := range []string{"tencent", "aliyun", "aws", "huawei", "azure", "gcp"} {
		for _, message := range []string{"UnauthorizedOperation", "AuthFailure", "AccessDenied", "permission denied", "timeout", "not found", "throttling", "signature invalid"} {
			err := Classify(provider, errors.New(message+": DO_NOT_LEAK"))
			detail := SourceError(err)
			if detail.Kind != string(KindPermanent) || detail.Code != "" || AuthError(err) || Retryable(err) || strings.Contains(err.Error(), "DO_NOT_LEAK") {
				t.Fatalf("guessed facts from %s/%s: %+v", provider, message, detail)
			}
		}
	}
	if !Retryable(Classify("tencent", context.DeadlineExceeded)) {
		t.Fatal("typed timeout must be retryable")
	}
	err := WithSourceAPI("tencent", "VPC DescribeVpcs", tcerrors.NewTencentCloudSDKError("UnauthorizedOperation", "DO_NOT_LEAK", ""))
	if SourceError(err).SourceAPI != "VPC DescribeVpcs" || SourceError(err).Kind != string(KindPermission) {
		t.Fatal(err)
	}
	if SourceError(WithSourceAPI("tencent", "CVM DescribeInstances", err)).SourceAPI != "CVM DescribeInstances" || SourceError(err).SourceAPI != "VPC DescribeVpcs" {
		t.Fatal("shared error mutated")
	}
}

func TestOfficialHTTPErrorDecoders(t *testing.T) {
	tests := []struct {
		provider   string
		status     int
		body, code string
		kind       ErrorKind
	}{
		{"azure", 403, `{"error":{"code":"AuthorizationFailed","message":"DO_NOT_LEAK"}}`, "AuthorizationFailed", KindPermission},
		{"azure", 403, `{"error":{"code":"SubscriptionDisabled","message":"DO_NOT_LEAK"}}`, "SubscriptionDisabled", KindDenied},
		{"azure", 401, "DO_NOT_LEAK", "", KindAuth},
		{"gcp", 403, `{"error":{"code":403,"message":"DO_NOT_LEAK","errors":[{"reason":"insufficientPermissions"}]}}`, "insufficientPermissions", KindPermission},
		{"gcp", 403, `{"error":{"code":403,"message":"DO_NOT_LEAK","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"SERVICE_DISABLED"}]}}`, "SERVICE_DISABLED", KindDenied},
		{"gcp", 503, "DO_NOT_LEAK", "", KindTransient},
	}
	for _, tt := range tests {
		t.Run(tt.provider+tt.code, func(t *testing.T) {
			err := HTTPError(tt.provider, "tested API", &http.Response{StatusCode: tt.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(tt.body))})
			got := SourceError(err)
			if got.Kind != string(tt.kind) || got.Code != tt.code || got.HTTPStatus != tt.status || got.SourceAPI != "tested API" || strings.Contains(err.Error(), "DO_NOT_LEAK") {
				t.Fatalf("unexpected error: %+v %v", got, err)
			}
		})
	}
}
