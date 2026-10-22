# 来源访问失败与权限提示

归流根据实际请求返回的官方 SDK / API 字段记录失败，不根据错误描述中的关键词判断权限，不枚举或推测一组凭据拥有的全部权限。查询成功只说明该次 API、账号、地域和资源范围内的请求成功。

## SDK 依据

依赖版本以 `go.mod` 为准。本轮核对本地依赖源码中的以下类型与字段：

| 来源 | 官方 SDK 类型 | 使用的字段 |
| --- | --- | --- |
| 腾讯云 | `common/errors.TencentCloudSDKError`，common v1.3.195 | `GetCode()`；SDK 自身的网络错误也有明确代码 |
| 阿里云 | `tea.SDKError`，tea v1.3.13 | `Code`、`StatusCode`；不输出 `AccessDeniedDetail` 或 `Data` |
| AWS | `smithy.APIError`、`smithy.OperationError`、HTTP `ResponseError`，smithy-go v1.28.5 | `ErrorCode()`、`Service()`、`Operation()`、`HTTPStatusCode()` |
| 华为云 | `sdkerr.ServiceResponseError`，SDK v0.1.219 | `ErrorCode`、`StatusCode`；不输出授权诊断或响应体 |
| GCP | `googleapi.Error`，API v0.305.0；OAuth2 / gRPC 标准错误类型 | HTTP `Code`、`ErrorItem.Reason`、`google.rpc.ErrorInfo.reason`、标准状态码或 OAuth 错误码 |
| Azure | `azcore.ResponseError`，azcore v1.23.3；`azidentity.AuthenticationFailedError` | `ErrorCode`、`StatusCode`；认证失败类型，不读取响应消息 |

保留原始响应的 Azure / GCP 告警适配器，分别使用官方 `runtime.NewResponseError`、`googleapi.CheckResponseWithBody` 解码失败响应。腾讯云、阿里云的通用请求与其他云的生成客户端均保留 SDK 错误链；成功响应的原始证据保存方式不变。

## 归一规则与边界

| 返回事实 | 归流分类 | 资产刷新状态 |
| --- | --- | --- |
| 明确的认证失败，例如腾讯云 `AuthFailure.SignatureFailure`、AWS `AuthFailure` | `auth` | `authentication_failed` |
| 明确的授权拒绝，例如腾讯云 `UnauthorizedOperation` / `AuthFailure.UnauthorizedOperation`、阿里云 `Forbidden.RAM`、AWS `UnauthorizedOperation`、Azure `AuthorizationFailed` | `permission` | `permission_denied` |
| 仅有 HTTP 403，或来源拒绝但不能确定是 IAM 问题 | `access_denied` | `access_denied` |
| 官方限流代码或 HTTP 429 | `throttled` | `throttled` |
| 明确资源未找到或 HTTP 404 | `not_found` | `not_found_or_not_visible` |
| 明确临时服务错误、HTTP 5xx 或类型化网络故障 | `transient` | `source_request_failed`；明确上下文超时为 `timeout` |
| 未识别的 SDK 错误码或没有结构化依据的错误 | `permanent` | `source_request_failed` |

具体映射在 `internal/connector/sdk_errors.go`，以版本控制与回归测试共同约束。未识别代码保留其合法、长度受限的原值，不从 Message 补猜。`permanent` 表示归流没有自动重试依据，不表示厂商故障永远不可恢复。

特别注意：腾讯云 `LimitExceeded` 表示配额限制，不等同于请求频率超限；华为云 `Ecs.0003` 也可能涉及余额或冻结；GCP `SERVICE_DISABLED` 表示服务前置条件问题。不能一律指导用户“增加 IAM 权限”。

官方参考：

- [腾讯云 CVM 公共与业务错误码](https://cloud.tencent.com/document/api/213/30435)、[安全组规则 API](https://cloud.tencent.com/document/api/215/15804)。
- [阿里云 RAM 权限错误与认证失败的区别](https://www.alibabacloud.com/help/en/ram/support/how-to-troubleshoot-an-access-denied-error)。
- [AWS EC2 错误码](https://docs.aws.amazon.com/ec2/latest/devguide/errors-overview.html)。
- [华为云 ECS 错误码](https://support.huaweicloud.com/api-ecs/ecs_07_0002.html)。
- [Google API 错误契约 AIP-193](https://google.aip.dev/193)、[googleapi 错误类型](https://pkg.go.dev/google.golang.org/api/googleapi#Error)。
- [Azure ARM 错误码](https://learn.microsoft.com/en-us/azure/azure-resource-manager/troubleshooting/common-deployment-errors)、[azcore ResponseError](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azcore#ResponseError)。

## 查询与展示

`source_error` 只包含来源、归流分类、原错误码、HTTP 状态（SDK 提供时）和实际调用的 API，例如：

```json
{
  "provider": "tencent",
  "kind": "permission",
  "code": "UnauthorizedOperation",
  "source_api": "VPC DescribeSecurityGroupPolicies"
}
```

这表示该次安全组规则请求未获授权，不表示告警或主机查询也不可用，更不表示安全组没有规则。

- 资产刷新尝试与失败组件携带 `source_error`；主机成功、规则失败时返回 `partial`，保留已读取的事实和来源明确的关系。已有资产不因整个刷新失败而删除。
- 没有本地资产且最近尝试被拒绝时，上下文 / lookup 直接返回对应失败原因，同时携带最近尝试时间；尚未请求时仍为 `not_collected`。
- 告警同步将结构化失败保存到同步运行 `source_error`、同步状态及 coverage 的 `last_source_error`。失败不推进同步水位；成功恢复后清除当前错误，历史运行仍可查询。
- Web、REST、MCP 与查询 CLI 的 JSON 读取同一持久记录。GET / MCP 查询不额外调用云 API。
- 云账号连接检查返回 `checked_api`、`check_scope=finding_query_only` 和限制说明；成功提示明确资产与网络权限未验证。它不是全权限预检。
- 失败诊断不复制 SDK Message、响应体、请求签名、凭据、完整身份 / 资源授权诊断。原始成功数据仍通过现有证据接口按需读取。

本轮未增加自动遍历资源的权限扫描、IAM 策略分析或推测缺失授权项。访问指引定位到实际失败的 API；具体 IAM Action 应依据该 API 的官方授权文档与客户策略核对，不能仅从 API 名称拼接。Azure 网卡引用来源的修正使用资产映射版本 `azure-vm/v2`，历史资产修订不回写。

## 验证范围

自动化使用官方 SDK 错误类型、官方结构的合成 HTTP 响应，以及合成资产。覆盖六云分类、认证 / 授权区分、未知错误不推断、脱敏、局部失败、重启保存、失败后恢复、旧 schema 5 增加诊断列，以及 REST / MCP 一致性。Azure 网络引用逐条验证能够取回对应原始组件。

没有使用真实失效密钥或受限账号验证本轮变更；不能将这些测试标记为六家云真实权限验收通过。
