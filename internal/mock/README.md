# Mock fixtures

`make mock` 注册六家云的 mock connector，使用内存库、关闭认证，并直接注入 fixtures 中的合成告警。每个 mock connector 都调用对应厂商的**生产 mapper**，所以 mock 数据和真实 SDK 响应走同一条归一化与 OCSF 路径。

## Provider 与数据

| Provider | fixture | 原始格式 | 覆盖分类 |
| --- | --- | --- | --- |
| `tencent` | `fixtures/tencent.json` | CSIP `AlertInfo` | CFW / WAF / CWP / CSIP，SQL 注入、Webshell、反弹 Shell、暴力破解、弱口令、端口扫描、CC |
| `aliyun` | `fixtures/aliyun.json` | SAS `DescribeSuspEvents` 的 `SuspEvents` 项 | 主机恶意进程、Webshell、SSH 暴力破解、容器逃逸、K8s 特权 Pod、漏洞、基线、网络扫描 |
| `huawei` | `fixtures/huawei.json` | SecMaster `ListAlerts` 的 `ListAlertRsp` | HSS 反弹 Shell / Webshell / 暴力破解、CFW 端口扫描、WAF SQL/命令注入、CSIP 弱口令/漏洞 |
| `aws` | `fixtures/aws.json` | Security Hub `GetFindingsV2` 返回的 OCSF finding | GuardDuty 未授权访问/钓鱼/挖矿、Inspector CVE、Security Hub S3/安全组、Macie、IAM |
| `gcp` | `fixtures/gcp.json` | SCC `ListFindings` 的 Finding（protojson） | 公开 Bucket、开放防火墙、SQL 注入、恶意软件、挖矿、IAM 外部访问、漏洞、公网 IP |
| `azure` | `fixtures/azure.json` | ARM `Microsoft.Security/alerts` 的 `Alert` | Defender for Cloud 可疑进程、SSH 暴力破解、SQL 注入、异常登录、邮件规则、挖矿、端口扫描、失败登录 |

Mock 模式使用 `Registry.Replace` 覆盖同名的生产 provider，因此不会出现两套厂商卡片或两个筛选选项；配置文件里的 provider 仍是 `tencent` / `aliyun` / `huawei` / `aws` / `gcp` / `azure`。

加载时会把时间字段改写为相对当前时间，避免 fixture 过期后从默认时间窗消失。支持的字段：

- 字符串时间：`CreateTime`、`UpdateTime`、`Date`、`OccurrenceTime`、`LastTime`、`FirstObservedTime`、`LastObservedTime`、`ArriveTime`、`first_observed_time`、`last_observed_time`、`create_time`、`eventTime`、`createTime`、`timeGeneratedUtc`、`startTimeUtc`、`endTimeUtc`、`processingEndTimeUtc` 等。
- 毫秒时间戳：`OccurrenceTimeStamp`、`LastTimeStamp`、`time`、`created_time`、`first_seen_time`、`last_seen_time`、`modified_time` 等。

## 脱敏规则

新增样本时必须遵守：

- 外部 IP 使用文档保留段：`203.0.113.0/24`、`198.51.100.0/24`、`192.0.2.0/24`。
- 内网 IP 使用 `10.0.0.0/24`。
- 账号 ID 使用 `mock-*` 或 `123456789012` / `100000000001`。
- 域名使用 `example.com` 子域。
- 资产 ID 使用 `i-mockNNNN`、`ecs-mockNNNN`、`mock-*`。
- 文件路径使用 `/var/www/html/mock-*` 或 `/tmp/mock-*`。
- 不要包含真实客户名、真实公网 IP、真实账号、真实凭证、真实主机名、真实 ARN 账号。

## 增加样本

直接编辑对应的 fixture 数组即可，建议每个厂商覆盖：

- 至少一个严重/高危、一个中危、一个低危/提示；
- 有 IP、有域名、有主机、有容器/K8s 资产；
- 有证据和无证据；
- 不同厂商状态值。

fixture 的字段名必须与 SDK 响应一致：

- 阿里云使用 Go SDK 生成的 JSON tag，例如 `AlarmEventType`、`OccurrenceTimeStamp`、`SourceAliUid`。
- 华为使用 `ListAlertRsp` 的 JSON tag，例如 `handle_status`、`alert_type`、`network_list`。
- AWS 使用 `GetFindingsV2` 返回的 OCSF 字段，例如 `finding_info.uid`、`severity_id`、`cloud.account.uid`。
- GCP 使用 `ListFindings` 的 protojson 字段，例如 `resourceName`、`sourceProperties`、`eventTime`。
- Azure 使用 ARM `Alert` 的 JSON，例如 `properties.systemAlertId`、`properties.timeGeneratedUtc`、`properties.resourceIdentifiers`、`properties.entities`。

## 验证

```bash
go test ./internal/mock
make mock
# http://127.0.0.1:8081
```

`TestAllFixturesNormalize` 会加载每个 fixture、逐条调用真实 mapper，并检查外部 ID、标题、时间、云账号、资产证据和 observables。新增样本后先跑这个测试，再跑 `make mock` 看控制台。
