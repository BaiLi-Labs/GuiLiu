# GuiLiu · 归流

**厂商中立的云安全告警数据枢纽。** 把阿里云、腾讯云等云厂商的安全告警统一接入、标准化为 [OCSF](https://github.com/ocsf/ocsf-schema) Detection Finding，并提供 Web 控制台、REST API 和只读 MCP，供人和 Agent 使用同一份数据。

> 不替代云安全产品，不做 SIEM，不做 SOAR，也不内置 Agent。
> 只解决四件事：**可靠接入、字段归一、统一查询、同步健康**。

---

## 为什么做这个

- 告警散落在阿里云 SAS、腾讯云 CSIP、WAF、HIDS、CWPP、AWS Security Hub 等几十个控制台里，字段、等级、状态各不相同。
- 每个企业 Agent 都在重复实现同一套事情：认证、分页、限流、重试、字段转换。
- 现有开源项目要么偏 SIEM（Wazuh、OpenSearch），要么偏 SOAR（Shuffle、Tracecat），要么只做单云扫描（Prowler）。
- 先用 AI 降低基础设施的开发成本，把“跨云安全数据”做成稳定、可验证、人和 Agent 都能直接调用的能力；而不是先造一个 Agent 再让它到处写脚本。

GuiLiu 的边界很明确：**数据面优先，AI 无关**。即使没有任何 Agent，它也应该是一个完整好用的工具。

---

## 当前能力

| 能力 | 说明 |
| --- | --- |
| 插件化接入 | 每个云厂商实现一个 `connector.Connector`，`init()` 自注册，新增厂商不改核心 |
| 腾讯云 | 云安全中心 CSIP `DescribeAlertList`（聚合 CWP / CFW / WAF / CSIP 告警） |
| 阿里云 | 云安全中心 SAS `DescribeSuspEvents` |
| 统一模型 | OCSF Detection Finding (`class_uid=2004`) + 平台扩展字段 |
| 原始证据 | 每条告警保留厂商原始 JSON 与 `mapper_version`，可重放映射 |
| 增量同步 | 时间窗口 + 重叠回看 + 分页游标 + 去重 upsert，失败不推进游标 |
| 可靠性 | 按厂商限速、指数退避重试、错误分类、单账号并发保护、页数上限保护 |
| 查询 | 按厂商 / 账号 / 等级 / 状态 / 时间 / IP / 资产 / 关键词过滤，统计聚合 |
| 生命周期 | 平台侧 `open / acknowledged / suppressed / closed`，不覆盖厂商原始状态 |
| 控制台 | 单页 Web 控制台：概览、告警、详情抽屉、账号接入、同步健康、MCP 配置 |
| REST API | `/api/v1/*`，Bearer Token |
| MCP | Streamable HTTP `/mcp` + stdio `guiliu mcp`，8 个只读工具 |
| 凭据安全 | AK/SK 使用 AES-256-GCM 加密存储；API 只返回 `****后四位` |
| 存储 | 默认 SQLite（纯 Go，无 CGO）；`store.Store` 接口可替换 PostgreSQL / ClickHouse |

---

## 快速开始

环境：Go 1.26+（依赖 `modernc.org/sqlite` 的最低要求）。

```bash
git clone <this-repo> guiliu && cd guiliu
go build -o bin/guiliu ./cmd/guiliu

cp configs/guiliu.example.json guiliu.json
# 编辑 guiliu.json，或直接用环境变量提供凭据：
export GUILIU_API_TOKEN='change-me'
export TENCENT_SECRET_ID='...'
export TENCENT_SECRET_KEY='...'
export ALIYUN_ACCESS_KEY_ID='...'
export ALIYUN_ACCESS_KEY_SECRET='...'

./bin/guiliu serve
```

打开 <http://127.0.0.1:8080>。

> 未配置 `api_token` 时认证关闭，服务默认只监听 `127.0.0.1`。对外暴露前务必设置 Token。

### Docker

```bash
export GUILIU_API_TOKEN='change-me'
docker compose up -d --build
```

容器使用命名卷 `guiliu-data` 保存 SQLite 与主密钥。账号可以在控制台/API 中动态添加，也可以通过挂载 `guiliu.json` 声明式接入。

> 备份数据库时必须同时备份 `data/secret.key`（或你的 `GUILIU_SECRET_KEY`）。密钥丢失后，库里的 AK/SK 无法解密。

### 方式一：在控制台接入

「云账号 → 接入云账号」选择厂商，填写 AK/SK。凭据加密后写入数据库，不回显。

### 方式二：声明式配置（IaC）

`guiliu.json` 中 `accounts` 会在启动时按名称 upsert：

```json
{
  "accounts": [
    {
      "name": "prod-tencent",
      "provider": "tencent",
      "account_uid": "1234567890",
      "region": "ap-guangzhou",
      "access_key_id": "${TENCENT_SECRET_ID}",
      "access_key_secret": "${TENCENT_SECRET_KEY}",
      "options": {"rate_limit": "3", "page_size": "100"}
    }
  ]
}
```

配置文件会先做环境变量展开，因此凭据可以只存在于环境 / Secret Manager 中。

### 方式三：REST API

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/accounts \
  -H "Authorization: Bearer $GUILIU_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "prod-aliyun",
    "provider": "aliyun",
    "account_uid": "1234567890123456",
    "region": "cn-hangzhou",
    "access_key_id": "LTAI...",
    "access_key_secret": "..."
  }'
```

---

## 先验证“能不能查到”，再验证“字段对不对”

这是本项目刻意保留的工作流。**不要在没有真实样本的情况下相信字段映射。**

```bash
# 直连厂商 API，确认凭据、权限、时间窗口有效
./bin/guiliu probe -account prod-tencent -since 24h -limit 5

# 看厂商原始 JSON（可接 jq）
./bin/guiliu probe -account prod-tencent -since 24h -limit 5 -raw | jq .

# 看归一化结果与生成的 OCSF
./bin/guiliu probe -account prod-tencent -since 24h -limit 5 -mapped

# 真正跑一次同步并写入数据库
./bin/guiliu sync -account prod-tencent
```

建议流程：

1. 用 `probe` 确认目标时间范围内确实有告警；
2. 用 `-raw` 抽样，核对厂商字段与分页行为；
3. 用 `-mapped` 检查等级、资产、IP、证据；
4. 再启动 `serve` 让调度器持续同步；
5. 调整映射时提升 `mapper_version`，原始 JSON 已保留，可重放。

---

## 架构

```text
腾讯云 CSIP ─┐
阿里云 SAS  ─┤   Connector 插件层
AWS / Azure ─┘   AK/SK · 分页 · 限流 · 重试 · 错误分类
                       │  raw vendor JSON
                       ▼
              Normalization 层
              OCSF Detection Finding 2004
              严重等级 · 资产 · 可观测对象 · 证据
              版本化 mapper_version · 保留 raw
                       │
                       ▼
              SQLite（Store 接口）
              alerts · accounts · sync_states · sync_runs
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   Web Console     REST API       MCP Server
   人              程序            企业自有 Agent
```

### 代码结构

```text
cmd/guiliu/                  CLI：serve / mcp / sync / probe / accounts
internal/app/                进程装配与声明式账号 bootstrap
internal/config/             JSON 配置 + 环境变量覆盖
internal/connector/          Connector 接口、注册表、限流、错误分类
internal/connector/tencent/  腾讯云 CSIP 接入 + 映射
internal/connector/aliyun/   阿里云 SAS 接入 + 映射
internal/connector/all/      统一 blank import，注册内置连接器
internal/normalize/          唯一的 OCSF 序列化实现
internal/ocsf/               OCSF 结构体与枚举
internal/model/              厂商无关领域模型
internal/store/              Store 接口 + SQLite 实现
internal/ingest/             同步引擎（窗口/游标/重试/去重/健康）
internal/api/                REST 路由与鉴权
internal/mcp/                MCP JSON-RPC（HTTP + stdio）与只读工具
internal/view/               REST/MCP 共用的公开 JSON 契约
internal/webui/              内嵌单页控制台
internal/secret/             AES-256-GCM 凭据加密
```

**关键设计：** 连接器只做两件事——`Fetch` 取原始数据、`Normalize` 把原始 JSON 映射成领域模型。OCSF 组装只在 `internal/normalize` 一处发生。因此：

- 所有厂商输出同一个 Schema；
- 映射逻辑是纯函数，可对历史 `raw` 重放；
- 修复字段映射不需要重新调用云 API。

---

## 字段映射

### 严重等级（映射是显式且可版本化的）

| 厂商原始值 | GuiLiu / OCSF `severity_id` |
| --- | --- |
| 腾讯云 `Level=1` 提示 | 1 Informational |
| 腾讯云 `Level=2` 低危 | 2 Low |
| 腾讯云 `Level=3` 中危 | 3 Medium |
| 腾讯云 `Level=4` 高危 | 4 High |
| 腾讯云 `Level=5` 严重 | 5 Critical |
| 阿里云 `Level=remind` 提醒 | 2 Low |
| 阿里云 `Level=suspicious` 可疑 | 3 Medium |
| 阿里云 `Level=serious` 紧急 | 5 Critical |

原始等级始终保存在 `original_severity` 与 OCSF `unmapped.original_severity`，不做丢失式转换。

### 核心字段

| GuiLiu | 腾讯云 CSIP | 阿里云 SAS |
| --- | --- | --- |
| `external_id` | `AlertInfo.ID` | `SuspEvents.Id` |
| `title` | `Name` | `Name` |
| `description` | `RiskInvestigation` / `UrgentSuggestion` | `Desc` |
| `event_time` | `UpdateTime` | `LastTimeStamp` / `OccurrenceTimeStamp` |
| `first_seen_at` | `CreateTime` | `OccurrenceTimeStamp` |
| `last_seen_at` | `UpdateTime` | `LastTimeStamp` |
| `source_ip` | `Attacker.IP` | `Details` 中“源IP / source ip”等字段（启发式） |
| `destination_ip` | `Victim.IP` | `InternetIp` / `IntranetIp` |
| `resource.id` | `Victim.InstanceID` | `InstanceId` / `Uuid` |
| `resource.name` | `Victim.Domain` / `Victim.IP` | `InstanceName` / `ContainerImageName` |
| `vendor_status` | `Status` 0/1/2 | `EventStatus` |
| `product` | `Source`（CWP/CFW/WAF/CSIP） | `SAS` |
| `alert_type` | `Type/SubType` | `AlarmEventTypeDisplay` |
| `tactic` | — | `TacticItems[].TacticId` |

### 三种语义不要混在一起

- **Event**：云厂商原始的日志 / 行为记录（本项目第一阶段不采集）。
- **Finding / Alert**：厂商给出的安全发现。GuiLiu 存的就是这一层。
- **Incident**：多条 Finding 聚合后的安全事件。第一阶段不做自动聚合。

平台生命周期状态（`open / acknowledged / suppressed / closed`）与厂商处理状态（`vendor_status`）分开存储：分析人员可以标记处置，但不会回写云厂商，也不会因为下一次同步被覆盖。

### OCSF 输出示例（截断）

```json
{
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "category_uid": 2,
  "category_name": "Findings",
  "activity_id": 1,
  "activity_name": "Create",
  "type_uid": 200401,
  "severity_id": 5,
  "severity": "Critical",
  "time": 1792484400000,
  "metadata": {
    "version": "1.6.0",
    "product": {
      "vendor_name": "Tencent Cloud",
      "name": "Cloud Security Center (CSIP)",
      "uid": "tencent.csip",
      "feature": {"name": "Host Security (CWP)"}
    },
    "log_provider": "Tencent Cloud",
    "log_name": "Host Security (CWP)"
  },
  "finding_info": {
    "uid": "alert-1001",
    "title": "Reverse shell detected",
    "first_seen_time": 1792480800000,
    "last_seen_time": 1792484400000,
    "attacks": [{"tactic": {"uid": "TA0002"}, "version": "1.0"}]
  },
  "cloud": {
    "provider": "Tencent Cloud",
    "region": "ap-guangzhou",
    "account": {"uid": "1234567890", "name": "prod-tencent", "type": "Tencent Cloud Account"}
  },
  "resources": [{"uid": "ins-abc", "name": "web-01", "type": "host", "role": "Target"}],
  "observables": [{"name": "src_endpoint.ip", "type_id": 2, "value": "203.0.113.9"}],
  "is_alert": true,
  "unmapped": {
    "vendor_status": "unhandled",
    "original_severity": "5",
    "mapper_version": "tencent-csip/v1",
    "tencent_csip": {"uin": "1234567890"}
  }
}
```

> `unmapped` 是 OCSF 的标准扩展点，用来保留没有标准归属的厂商字段；它不替代数据库中的完整 `raw`。

---

## REST API

鉴权：`Authorization: Bearer <api_token>` 或 `X-API-Key`。所有接口只读，只有账号配置与告警状态可写。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/healthz` | 健康检查（无需鉴权） |
| GET | `/api/v1/meta` | 版本、OCSF 版本、连接器列表、调度配置 |
| GET | `/api/v1/providers` | 连接器能力与凭据字段 |
| GET | `/api/v1/accounts` | 账号列表 + 同步状态 |
| POST | `/api/v1/accounts` | 新增账号（AK/SK 加密存储） |
| GET | `/api/v1/accounts/{id}` | 账号详情 |
| PATCH | `/api/v1/accounts/{id}` | 修改名称 / 地域 / 启停 / 凭据 / options |
| DELETE | `/api/v1/accounts/{id}?purge=true` | 删除账号（默认保留历史告警） |
| POST | `/api/v1/accounts/{id}/check` | 验证凭据与只读权限 |
| POST | `/api/v1/accounts/{id}/sync` | 异步触发单账号同步 |
| GET | `/api/v1/accounts/{id}/health` | 游标、错误、最近运行 |
| POST | `/api/v1/sync` | 异步同步全部账号 |
| GET | `/api/v1/sync-runs` | 同步运行记录 |
| GET | `/api/v1/alerts` | 告警查询 |
| GET | `/api/v1/alerts/{id}` | 详情（含 OCSF 与 raw） |
| GET | `/api/v1/alerts/{id}/raw` | 厂商原始 JSON |
| PATCH | `/api/v1/alerts/{id}` | 修改平台状态 |
| GET | `/api/v1/stats` | 聚合统计 |
| POST | `/mcp` | MCP Streamable HTTP |

查询参数：`provider`、`account_id`、`severity`（逗号分隔）、`status`、`start`、`end`、`ip`、`resource`、`q`、`sort`、`limit`（≤200）、`offset`。

```bash
curl -s "http://127.0.0.1:8080/api/v1/alerts?severity=critical,high&start=2026-10-19T00:00:00Z&limit=20" \
  -H "Authorization: Bearer $GUILIU_API_TOKEN" | jq .

curl -s "http://127.0.0.1:8080/api/v1/alerts?ip=203.0.113.9" \
  -H "Authorization: Bearer $GUILIU_API_TOKEN" | jq '.total'
```

---

## MCP

设计原则：**MCP 是统一 API 的适配层，不是权限更大的旁路。** 所有工具只读，带返回数量与时间范围护栏，不暴露 SQL、云凭证或封禁能力。

### HTTP（推荐）

```json
{
  "mcpServers": {
    "guiliu": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp",
      "headers": {"Authorization": "Bearer <API_TOKEN>"}
    }
  }
}
```

Claude Code：

```bash
claude mcp add --transport http guiliu http://127.0.0.1:8080/mcp \
  --header "Authorization: Bearer $GUILIU_API_TOKEN"
```

### stdio

```json
{
  "mcpServers": {
    "guiliu": {
      "command": "guiliu",
      "args": ["mcp", "-config", "/etc/guiliu/guiliu.json"]
    }
  }
}
```

### 工具

| 工具 | 用途 |
| --- | --- |
| `list_cloud_accounts` | 云账号与同步健康（不含凭据） |
| `list_alerts` | 跨云告警查询与筛选 |
| `get_alert` | 单条告警 + 完整 OCSF + 原始 JSON |
| `get_alert_evidence` | 证据、可观测对象、原始载荷 |
| `search_alerts_by_ip` | 按源 / 目标 IP 检索（默认 7 天） |
| `search_alerts_by_asset` | 按资产 ID / 名称检索（默认 7 天） |
| `get_alert_statistics` | 按等级 / 厂商 / 状态 / 天 / 资产聚合 |
| `get_connector_health` | 游标、最近成功、错误、最近运行 |

护栏：单次最多 200 条，时间范围最多 90 天，不支持任意 SQL。

---

## 安全模型

- **最小权限**：只需要各云安全中心的告警只读权限。不要使用主账号 AK。
- **静态加密**：AK/SK 使用 AES-256-GCM；主密钥来自 `GUILIU_SECRET_KEY`（base64 32 字节）或 `secret_key_file`（首次启动生成，权限 `0600`）。
- **不回显**：API 只返回 `access_key_hint`（`****1234`），不返回 Secret。
- **默认本机**：监听 `127.0.0.1:8080`。对外暴露时设置 `api_token` 并放在反向代理 / 内网之后。
- **只读数据面**：不提供云 API 写操作、自动封禁、任意 SQL。
- **多租户未实现**：当前是所有账号共享一个数据集与一个 Token。生产多租户需要额外的 RBAC 与行级隔离。

---

## 同步可靠性

一次同步的规则：

1. 窗口：`[cursor - overlap, now - 0]`；首次为 `now - initial_lookback`（默认 24h，优先保证当前告警可见；设置更长的回溯会从最早时间开始按 `max_window` 分段追赶）。
2. 单次最多推进 `max_window`（默认 24h），积压时自动分段追赶。
3. 每页最多 `page_size`（默认 100），每个窗口最多 `max_pages`（默认 100）。
4. 页内每条 raw 独立归一化/入库，单条失败记为 `failed`，不阻塞整批。
5. **所有页成功后**才提交游标；失败时游标不动，下一轮重叠重试。
6. 去重键：`provider + account_id + external_id`；更新时保留分析人员设置的平台状态。
7. 每个账号同一时刻只允许一个同步任务。

账号级 options 可覆盖：

```json
{"options": {"page_size": "100", "rate_limit": "2", "max_pages": "10", "initial_lookback": "24h", "overlap": "30m"}}
```

默认限速：腾讯云 CSIP 2 QPS（官方上限 3/s，实测按固定间隔打满 3/s 会被限流，留出余量），阿里云 SAS 5 QPS。两者的 API 都有分页/频率限制，连接器内部自行限速。

默认每个 run 最多 10 页（1000 条）。到页数预算时不是失败，而是保存页 token、以 `partial` 状态结束，下一轮从断点续传。这样既不会长时间占用 API 配额，也不会因为一次限流把已经拉取的进度丢掉。账号级 `max_pages` 可覆盖。

---

## 已知限制与待校准项

这是第一版，刻意保留诚实的边界：

- **映射需要真实样本校准**：阿里云 `source_ip` 来自 `Details` 的中文字段名启发式匹配；腾讯云时间字符串按东八区解析。请用 `probe -raw` 抽样验证，再提升 `mapper_version`。

- **只接告警，不接全量日志**：云流量日志、审计日志数据量高一个数量级，混入会把这个轻量平台做成另一个 SIEM。
- **只做 Detection Finding**：暂不做 Incident 聚合、跨厂商实体消歧。
- **不写回云厂商**：平台状态独立，避免误操作与权限扩张。
- **单实例 SQLite**：适合单机/小团队与 POC；数据量上来后替换 `store.Store` 为 PostgreSQL / ClickHouse。
- **未实现 OIDC / RBAC / 多租户**：当前 Token 是全局的。
- **AWS / Azure / 华为云尚未实现**：接口已就绪，见 `docs/connector-guide.md`。

---

## 开发

```bash
make test     # go test ./...
make vet      # go vet ./...
make build    # bin/guiliu
make run      # 本地启动
```

测试覆盖：

- 两家厂商的映射（等级、时间、IP、资产、证据、原始载荷）；
- OCSF 输出的关键字段与扩展点；
- SQLite upsert 去重、状态保留、过滤与统计；
- 同步引擎：分页、游标推进、重叠去重、失败不推进游标、页数上限；
- MCP：initialize / tools/list / tools/call / stdio；
- REST：鉴权、账号接入、凭据不回显、告警查询、状态更新、MCP HTTP。

### 新增一个云厂商

见 [`docs/connector-guide.md`](docs/connector-guide.md)。核心步骤：实现 `Info / Check / Fetch / Normalize`，在 `init()` 注册，加入 `internal/connector/all`，补映射测试与 `probe` 验证。

---

## 真实环境验证记录

2026-10-20 使用真实腾讯云账号做了接入验证：

- `DescribeAlertList` 的 `Filter.StartTime/EndTime` **确实生效**：1h / 6h / 24h 分别返回 17 / 746 / 7607 条。
- `Level` 1–5、`Uin` / `AppID`、`Attacker.IP`、`Victim.IP` / `InstanceID`、`EvidenceLocation`、`Type/SubType` 均按预期映射。
- 真实告警量级约为 **7.6k 条/天**（该账号当期遭受持续扫描/漏洞利用），SQLite 单机可承受；更大的规模应切 PostgreSQL / ClickHouse。
- 真实数据暴露并已修复：中文标题按字节截断、厂商账号 UID 未写入 OCSF、空 observable 未过滤、`probe` 未重试限流错误。
- 阿里云连接器仍需用真实 AK 做同样一轮校准。

## 路线图

1. AWS Security Hub（`GetFindingsV2` / OCSF 原生）、Azure Defender、华为云 SecMaster。
2. 官方 OCSF Schema 校验进入 CI，对每个 mapper 的输出做结构校验。
3. PostgreSQL / ClickHouse 存储实现（接口已隔离）。
4. 基于 `raw + mapper_version` 的重放/重建索引任务。
5. OIDC、RBAC、租户级数据隔离。
6. Webhook / 日志订阅接入，补充拉取模式的延迟问题。
7. 告警去重与 Incident 聚合（同资产、同 IP、同规则的时间窗聚合）。

---

## 一句话总结

**过去我们为人开发工具，再教 AI 使用工具；现在可以用 AI 大规模建设过去缺失的工具，而这些工具从一开始就同时服务人和 AI。**
