package connector

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	tcerrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"golang.org/x/oauth2"
	"google.golang.org/api/googleapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/BaiLi-Labs/GuiLiu/internal/model"
)

var sourceCode = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// Classify reads the installed official SDK's error contract. Human-readable
// messages are deliberately never used to infer permissions or retryability.
// The exact code mappings and official references are in docs/source-errors.md.
func Classify(provider string, err error) error {
	if err == nil {
		return nil
	}
	var existing *Error
	if errors.As(err, &existing) {
		return err
	}
	e := &Error{Provider: provider, Kind: KindPermanent, Err: err}
	structured := false
	switch provider {
	case "tencent":
		var sdk *tcerrors.TencentCloudSDKError
		if errors.As(err, &sdk) {
			structured = true
			e.Code = sdk.GetCode()
			switch {
			case codeFamily(e.Code, "UnauthorizedOperation"), e.Code == "AuthFailure.UnauthorizedOperation":
				e.Kind = KindPermission
			case codeFamily(e.Code, "AuthFailure"):
				e.Kind = KindAuth
			case codeFamily(e.Code, "RequestLimitExceeded"):
				e.Kind = KindThrottled
			case codeFamily(e.Code, "InternalError"), e.Code == "ServiceUnavailable", e.Code == "ClientError.NetworkError":
				e.Kind = KindTransient
			case codeFamily(e.Code, "ResourceNotFound"):
				e.Kind = KindNotFound
			}
		}
	case "aliyun":
		var sdk *tea.SDKError
		if errors.As(err, &sdk) {
			structured = true
			e.Code, e.HTTPStatus = tea.StringValue(sdk.Code), tea.IntValue(sdk.StatusCode)
			e.Kind = httpErrorKind(e.HTTPStatus)
			switch {
			case codeFamily(e.Code, "Forbidden.RAM"), codeFamily(e.Code, "Forbidden.NoPermission"), e.Code == "NoPermission", e.Code == "User.NoPermission", e.Code == "NotAuthorized":
				e.Kind = KindPermission
			case codeFamily(e.Code, "InvalidAccessKeyId"), codeFamily(e.Code, "InvalidSecurityToken"), e.Code == "SignatureDoesNotMatch", e.Code == "SignatureNonceUsed", e.Code == "IncompleteSignature":
				e.Kind = KindAuth
			case codeFamily(e.Code, "Throttling"):
				e.Kind = KindThrottled
			}
		}
	case "aws":
		var sdk smithy.APIError
		var response *smithyhttp.ResponseError
		if errors.As(err, &response) {
			e.HTTPStatus = response.HTTPStatusCode()
		}
		if errors.As(err, &sdk) {
			structured = true
			e.Code = sdk.ErrorCode()
			e.Kind = httpErrorKind(e.HTTPStatus)
			// EC2 Query may return a Client. prefix. It remains in Code.
			code := strings.TrimPrefix(e.Code, "Client.")
			switch code {
			case "UnauthorizedOperation", "AccessDenied", "AccessDeniedException", "NotAuthorizedException":
				e.Kind = KindPermission
			case "AuthFailure", "InvalidClientTokenId", "UnrecognizedClientException", "ExpiredToken", "ExpiredTokenException", "InvalidSignatureException", "SignatureDoesNotMatch", "MissingAuthenticationToken":
				e.Kind = KindAuth
			case "RequestLimitExceeded", "Throttling", "ThrottlingException", "TooManyRequestsException", "LimitExceededException", "SlowDown":
				e.Kind = KindThrottled
			case "InternalError", "InternalException", "InternalServerError", "ServiceUnavailable", "ServiceUnavailableException", "Unavailable":
				e.Kind = KindTransient
			case "InvalidInstanceID.NotFound", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound", "InvalidNetworkInterfaceID.NotFound", "ResourceNotFoundException":
				e.Kind = KindNotFound
			}
		} else if response != nil {
			structured = true
			e.Kind = httpErrorKind(e.HTTPStatus)
		}
		var op *smithy.OperationError
		if errors.As(err, &op) {
			e.SourceAPI = op.Service() + " " + op.Operation()
		}
	case "huawei":
		var sdk *sdkerr.ServiceResponseError
		if errors.As(err, &sdk) {
			structured = true
			e.Code, e.HTTPStatus = sdk.ErrorCode, sdk.StatusCode
			e.Kind = httpErrorKind(e.HTTPStatus)
			// Ecs.0003 also covers insufficient balance/frozen accounts. A 403
			// alone must not be presented as a missing IAM permission.
		}
	case "azure":
		var sdk *azcore.ResponseError
		var auth *azidentity.AuthenticationFailedError
		if errors.As(err, &auth) {
			structured = true
			e.Kind = KindAuth
			if auth.RawResponse != nil {
				e.HTTPStatus = auth.RawResponse.StatusCode
				if auth.RawResponse.StatusCode == http.StatusTooManyRequests || auth.RawResponse.StatusCode >= 500 {
					e.Kind = httpErrorKind(auth.RawResponse.StatusCode)
				}
			}
		} else if errors.As(err, &sdk) {
			structured = true
			e.Code, e.HTTPStatus = sdk.ErrorCode, sdk.StatusCode
			e.Kind = httpErrorKind(e.HTTPStatus)
			switch e.Code {
			case "AuthorizationFailed", "LinkedAuthorizationFailed", "AuthorizationPermissionMismatch", "DenyAssignmentAuthorizationFailed":
				e.Kind = KindPermission
			case "AuthenticationFailed", "InvalidAuthenticationToken", "ExpiredAuthenticationToken", "InvalidAuthenticationTokenTenant":
				e.Kind = KindAuth
			}
		}
	case "gcp":
		var sdk *googleapi.Error
		var token *oauth2.RetrieveError
		if errors.As(err, &token) {
			structured = true
			e.Code = token.ErrorCode
			if token.Response != nil {
				e.HTTPStatus = token.Response.StatusCode
			}
			e.Kind = httpErrorKind(e.HTTPStatus)
			switch token.ErrorCode {
			case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope":
				e.Kind = KindAuth
			case "temporarily_unavailable", "server_error":
				e.Kind = KindTransient
			}
		} else if errors.As(err, &sdk) {
			structured = true
			e.HTTPStatus = sdk.Code
			e.Kind = httpErrorKind(sdk.Code)
			// ErrorItem.Reason is the API's typed reason. Details may contain
			// google.rpc.ErrorInfo; never copy its identity/resource metadata.
			if len(sdk.Errors) > 0 {
				e.Code = sdk.Errors[0].Reason
			}
			for _, detail := range sdk.Details {
				if info, ok := detail.(map[string]interface{}); ok && info["@type"] == "type.googleapis.com/google.rpc.ErrorInfo" {
					if reason, ok := info["reason"].(string); ok {
						e.Code = reason
						break
					}
				}
			}
			switch e.Code {
			case "insufficientPermissions", "IAM_PERMISSION_DENIED", "ACCESS_TOKEN_SCOPE_INSUFFICIENT":
				e.Kind = KindPermission
			case "rateLimitExceeded", "userRateLimitExceeded", "RATE_LIMIT_EXCEEDED":
				e.Kind = KindThrottled
			}
		} else if st, ok := status.FromError(err); ok {
			structured = true
			e.Code = st.Code().String()
			switch st.Code() {
			case codes.Unauthenticated:
				e.Kind = KindAuth
			case codes.PermissionDenied:
				e.Kind = KindDenied
			case codes.ResourceExhausted:
				e.Kind = KindThrottled
			case codes.Unavailable, codes.DeadlineExceeded, codes.Internal:
				e.Kind = KindTransient
			case codes.NotFound:
				e.Kind = KindNotFound
			}
		}
	}
	if !structured {
		var network net.Error
		switch {
		case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network), errors.Is(err, io.ErrUnexpectedEOF):
			e.Kind = KindTransient
		}
	}
	if !sourceCode.MatchString(e.Code) {
		e.Code = ""
	}
	e.Message = errorSummary(e.Kind)
	return e
}

func codeFamily(code, family string) bool {
	return code == family || strings.HasPrefix(code, family+".")
}

func httpErrorKind(status int) ErrorKind {
	switch {
	case status == http.StatusUnauthorized:
		return KindAuth
	case status == http.StatusForbidden:
		return KindDenied
	case status == http.StatusNotFound:
		return KindNotFound
	case status == http.StatusTooManyRequests:
		return KindThrottled
	case status == http.StatusRequestTimeout || status >= 500:
		return KindTransient
	default:
		return KindPermanent
	}
}

func errorSummary(kind ErrorKind) string {
	switch kind {
	case KindAuth:
		return "source authentication failed; check credentials, token and signing configuration"
	case KindPermission:
		return "source authorization failed for this API and scope; check the source access policy"
	case KindDenied:
		return "source denied access; the response does not establish which permission or service prerequisite is missing"
	case KindNotFound:
		return "source resource not found or not visible in this scope"
	case KindThrottled:
		return "source request rate or quota limit reached"
	case KindTransient:
		return "source temporarily unavailable or request timed out"
	default:
		return "source request failed; inspect the source error code"
	}
}

// WithSourceAPI attaches the operation the adapter actually invoked, never an
// operation guessed from an error message. It does not mutate a shared error.
func WithSourceAPI(provider, api string, err error) error {
	classified := Classify(provider, err)
	if classified == nil {
		return nil
	}
	var e *Error
	if !errors.As(classified, &e) {
		return classified
	}
	copy := *e
	copy.SourceAPI = api
	return &copy
}

func SourceError(err error) *model.SourceError {
	var e *Error
	if !errors.As(err, &e) {
		return nil
	}
	return &model.SourceError{Provider: e.Provider, Kind: string(e.Kind), Code: e.Code, HTTPStatus: e.HTTPStatus, SourceAPI: e.SourceAPI}
}
