# 归流安全数据访问契约

归流：统一安全数据，不统一安全结论。

归流是 Security Data Access Layer。它保存来源记录、执行可重放的字段转换、维护查询索引，并向 Web、REST、MCP 提供相同的数据。厂商的误报、攻击、风险、处理结果仅作为来源声明；归流不新增这些判断。巡检调度、研判、封禁、通知和工单属于消费方。

## 数据分层

1. 来源记录：保留完整单条 API JSON 对象及外层上下文、精确字节 SHA-256、采集时间。未知字段不经 SDK 结构体裁剪。
2. 标准事实：保留来源 ID、规则 ID、云账号、分类、原始等级和状态、独立时间、实体、证据、Mapper 版本和字段来源。
3. 查询索引：当前事实投影、不可变的历史投影、按类型和值索引的 Observables。索引不替代原始记录。
4. 查询视图：明细、等值分组、统计、历史快照、变更流。可从视图返回每条成员及指定版本原始载荷。

当前数据库为 schema 5。开发阶段不提供旧库迁移：旧库会被明确拒绝打开，不会自动覆盖或清空。修改配置中的 `database` 使用新文件即可启动。连接器账号删除保留事实与修订；删除配置后，历史来源覆盖状态为未配置/不完整。扫描范围在开始同步后不可改到另一个地域、订阅、项目或工作空间，应创建独立连接。

## 身份、时间与字段来源

- `account_id` 是归流的连接配置 ID；`account_uid` 是来源明确提供或用户明确配置的真实云身份。缺失时保持未知，不以本地 ID 替代。
- `external_id` 使用原生 ID。缺少可定位的原生身份会保留为映射失败，覆盖状态为部分失败，不把内容哈希冒充厂商告警 ID。
- `rule_id` 只映射来源中明确的规则标识。没有规则 ID 的来源不使用标题、相似度或分类名称推造规则。
- `event_time`、`first_seen_at`、`last_seen_at` 描述厂商提供的发生/观测时间；`source_created_at`、`source_updated_at` 描述来源记录自身的创建/修改时间。
- 腾讯 `CreateTime` / `UpdateTime` 分别为首次/最近告警时间。阿里 `LastTime` 是最近发生时间；这些字段不冒充通用修改时间。
- `ingested_at` 是当前来源内容首次采集时间；`last_ingested_at` 是最近再次采集时间；`created_at` 是归流首次保存时间；`updated_at` 是事实投影发生变化的保存时间。相同内容重采不会刷新 `updated_at`。
- 未知时间在公开明细中为空，不用当前时间、窗口末尾、其他时间字段补造。按发生时间筛选时，未知发生时间不属于该时间范围；可用不带起点的查询或指定 ID 读取。
- `provenance` 标明来源类别（`record`、`configuration`、`connector`）、实际 JSON Pointer 输入及版本化转换规则。输入列表按 Mapper 规则表达优先级或组合关系，不声明每个候选字段都被直接复制到输出。
- Observable 的实际路径在 Mapper 提取字段时记录。同类型、同角色、同值合并路径，不跨角色按值反查；同一个 IP 同时出现在源、目的或无角色字段时，各自只保留实际提取位置。
- `GET /api/v1/providers/{provider}/mapping` 和 MCP `get_provider_mapping` 可读取该连接器的映射说明。

严重等级仅为显式显示映射，未知等级为 Unknown，并保留原值。`status` 是使用者的本地标注；`vendor_status` 直接保留厂商状态原值（数值状态转为十进制字符串），不重命名或改变大小写。本地标注不会产生来源修订、进入变更流或回写厂商。

`account_name` 是当前连接的本地展示名称，与本地标注一样不冻结在来源快照中。修改连接名称立即更新展示，不改变来源内容指纹、事实更新时间或变更流。通用 OCSF 不把该名称填入厂商云账号名称；来源原生 OCSF 的账号名称仍原样保留。

## 乱序记录与当前投影

每条新记录的当前投影选择遵循明确的优先级：双方都具有厂商 `source_updated_at` 且不相等时，选择厂商更新时间较晚的记录；否则选择最近实际采集到的内容。后者只描述平台观测顺序，不宣称厂商版本先后。相同内容的重复采集推进其最近观测时间；旧失败记录重试不能把这个时间倒退。`event_time`、首次/最近发生时间不用于推断来源版本顺序。

不同内容的较旧记录仍以独立修订保存，并进入 Change Feed，但不替换当前事实、查询索引或固定快照。Feed 和修订的 `projection_updated` 表示该次写入是否更新了当前投影，不表示该版本现在仍是最新版本。`false` 时消费方仍可按精确修订读取原始证据。相同旧载荷重复补偿不会反复生成修订。

修订号描述平台记录顺序。因此当前投影的 `revision` 可能小于历史中最大的修订号；分组的 `revision_count` 统计快照序号之前实际记录的全部内容变化，包含保留的较旧版本，不从当前投影修订号推算。

## OCSF 投影

标准事实是基础契约，OCSF 是按来源语义提供的标准投影。

- AWS 已提供 OCSF，保留原有类别、版本、生命周期和全部字段。
- 检测、漏洞、合规、事件分别对应来源明确表达的 Finding 类别。
- GCP `THREAT` 映射检测，`VULNERABILITY` 映射漏洞。无法明确对应的类别保留为 `other`，不强行当作检测。
- 缺少发生时间、类别无法映射、缺少漏洞细节，或尚未实现该类别的必需结构时不制造 OCSF；返回 `ocsf_omission_reason`，标准事实与原始记录仍可查询。当前通用投影支持检测与带 CVE 的漏洞，合规/事件保留来源原生 OCSF；不会仅替换 `class_uid` 就宣称完成新类别映射。
- 通用转换不推造 Create 生命周期动作、告警有效性或资源攻击角色。
- 同类型、同值但不同角色的 Observable 分别保留。例如源与目的 IP 相同，也保留两个来源位置。

通用投影固定 OCSF 1.6.0，类别的必需结构以该版本的 [Detection Finding](https://github.com/ocsf/ocsf-schema/blob/v1.6.0/events/findings/detection_finding.json)、[Vulnerability Finding](https://github.com/ocsf/ocsf-schema/blob/v1.6.0/events/findings/vulnerability_finding.json)、[Compliance Finding](https://github.com/ocsf/ocsf-schema/blob/v1.6.0/events/findings/compliance_finding.json) 和 [Incident Finding](https://github.com/ocsf/ocsf-schema/blob/v1.6.0/events/findings/incident_finding.json) 为准。来源原生 OCSF 的版本不被强制改写。

## Snapshot Query

`GET /api/v1/alerts` 和 `/alerts/groups` 首次请求返回 `snapshot_sequence`、绝对 `window.start/end` 与覆盖信息。后续分页、分组展开及详情读取重复这三个值，冻结来源事实，避免后台新增或更新改变成员集合。

```http
GET /api/v1/alerts?sort=id&limit=100
GET /api/v1/alerts?sort=id&after_id=返回的next_cursor&snapshot_sequence=123&limit=100
GET /api/v1/alerts/groups?start=...&end=...&snapshot_sequence=123
GET /api/v1/alerts/{id}?snapshot_sequence=123
```

`sort=id` 使用稳定 ID 顺序并返回 `next_cursor`；把该值作为 `after_id`，直到 `has_more=false`。普通 Offset 分页也可使用同一快照，没有 MCP 10000 条截断。快照只读取该序号及之前的来源版本。本地标注始终返回当前值，不属于来源变更历史；按本地 `status` 筛选的成员会随使用者修改标注而变化。

时间筛选可通过 `time_field=event_time|source_updated_at|ingested_at` 明确选择依据；缺失发生时间的记录仍可按采集时间检索。覆盖判断会标明时间依据与厂商采集窗口不一致的限制。

统一筛选支持 `provider`、`account_id`、`severity`、本地 `status`、`vendor_status`、`finding_kind`、`rule_id`、`ip`、`resource`、`q`、`start/end`。通用对象查询使用 `observable_value`（精确值）与可选 `observable_type`（OCSF 类型 ID，例如 IP=2、用户名=4、文件 Hash=8、资源=10）。类型 0 是明确的 Unknown 类型，不是全类型通配。

`ip` 覆盖源、目的及所有已明确提取的 IP Observables。任意文本里像 IP 的字符串不被自动赋予源/目的角色。完整 Raw 可查看，不等于所有未知嵌套字段都已进入查询索引。

## Finding Grouping

分组只表示字段等值。默认 `type_asset` 是类型与资产的统计视角；`signature` 使用 provider、连接配置、真实云账号 UID、region、product、原生 rule_id、资产 ID 和源 IP。关键字段缺失时保留独立记录。其他 `asset` / `source` 是不同统计视角，不代表同一次攻击或同一事件。

- `finding_count`：分组中的独立来源记录数量。
- `revision_count`：成员的可记录内容变化次数，不含每条记录的初始版本。
- `occurrence_count`：单条来源明确报告的次数，附带 `occurrence_scope`。当前不跨记录求和，不把不同厂商或不同定义的次数混算。
- `max_severity`：成员的最高厂商映射等级，不是归流对分组的风险评价。

展开成员需重复分组返回的完整 `group_key`、查询过滤条件、绝对时间窗口和 `snapshot_sequence`。

## Change Feed

```http
GET /api/v1/alerts/changes?cursor=0&limit=100
```

```json
{
  "changes": [{"sequence": 123, "alert_id": "uuid", "change_type": "updated", "revision": 3, "projection_updated": true}],
  "next_cursor": "123",
  "has_more": false
}
```

游标是当前数据库的持久单调递增提交序号，不使用厂商事件时间或分页 Offset。新增、来源内容变化和重映射产生的事实变化与修订在同一事务提交。相同内容重采、JSON 键顺序/空白变化、本地标注不会制造变更。`raw_hash` 校验精确字节；实质内容指纹按保留数值精度的 JSON 表达计算。

消费方完成处理后才保存 `next_cursor`，用 `(alert_id, revision)` 或 `sequence` 做幂等。可按 provider/account 过滤；续读必须保持相同范围。无更多匹配项时游标可推进到本轮高水位。记录时间很旧但今天才采集或变化，仍会出现在 Feed。

每条变化可用 `GET /api/v1/alerts/{id}/revisions/{revision}` 读取精确事实版本，不必读取后来再次更新的当前值。`GET /alerts/{id}/revisions?limit=50&before_revision=N` 支持遍历全部历史，返回 `has_more` / `next_before_revision`。

精确原始字节由详情的 `raw_url` 返回：`GET /alerts/{id}/revisions/{revision}/raw`。嵌入 JSON 响应的 `raw` 是同一对象，但外层 JSON 编码可能压缩空白；核验精确 SHA-256 时读取 `raw_url`。

## Coverage

`GET /api/v1/coverage?start=...&end=...` 与 MCP `get_data_coverage` 返回每个来源的 API、版本、配置作用域、时间筛选依据、历史起点、完成水位、失败数、健康状态和限制。明细与分组查询也返回相同结构。

`complete=true` 仅说明：查询时间范围有界、在已经完成采集的范围内、账号启用且同步健康、没有待映射失败。它始终受返回的 API、权限和上游限制约束。近期成功不证明更早历史已导入；空结果不证明上游没有告警。

覆盖信息明确声明未汇入该 API 的产品、权限外记录、厂商保留期、延迟到达、Offset 翻页的上游变动，以及旧告警状态更新可能落在采集窗口之外。当前没有宣称全厂商产品覆盖或持续历史状态完全一致。

## MCP 与消费端

MCP 提供 `list_alert_changes`、`get_alert_revisions`、`get_data_coverage`、`get_provider_mapping`，以及明细、分组、证据和统计查询。`get_alert` 可指定精确 `revision` 或 `snapshot_sequence`。全部工具只读；外部调度器决定何时查询，外部系统决定如何研判和响应。

## 资产上下文首版

当前新增来源为腾讯云 CVM `DescribeInstances` 与 VPC `DescribeSecurityGroupPolicies`、`DescribeSecurityGroups`、`DescribeVpcs`、`DescribeSubnets`（均为 `2017-03-12`）。通过官方 Go SDK 通用客户端签名及请求，读取原始 JSON，避免 SDK 类型裁剪未知字段。仅通过合成响应、接口契约和本地演示验证，尚未通过真实云账号验证。接口依据：[实例查询](https://cloud.tencent.com/document/product/213/15728)、[安全组策略查询](https://cloud.tencent.com/document/api/215/15804)、[安全组详情](https://cloud.tencent.com/document/api/215/15808)、[VPC 详情](https://cloud.tencent.com/document/api/215/15778)、[子网详情](https://cloud.tencent.com/document/api/215/15784)。

本轮审查与实现的区别：

| 类型 | 结果 |
| --- | --- |
| 已具备 | Finding 原始字节、字段溯源、同步与失败补偿、修订、固定快照、Change Feed、统一查询；保留现有机制 |
| 本轮修正 | REST / MCP 共用 Finding 修订选择，证据工具可读精确修订；冲突或非法版本参数明确报错 |
| 本轮新增 | 独立 CVM/安全组/VPC/子网记录与修订、控制面字段、组件证据、显式有预算刷新、精确资源关联、三种入口查询路径 |
| 后续目标 | 软件/进程/监听端口/EDR、完整资产发现、资产 Change Feed、审计与 SIEM、通用联邦查询、细粒度授权 |

资产包含实例 ID、真实云账号 UID、地域、名称、OS、规格、厂商状态、可用区、公私网 IP、VPC、子网、安全组 ID、标签与字段溯源。账号和地域来自明确的连接配置，不宣称为实例 API 返回字段。尚未提供的字段保持未知；软件、监听端口与可达性组件明确为 `not_collected`。

安全组、VPC、子网作为独立资产保存，不把完整网络资源复制进每台主机。`references` 带 provider、原生账号 UID、region、resource_type、resource_id，以及来源组件、JSON 路径和 `lookup_url`；仅来源明确的 ID 建立引用。安全组提供名称、说明、标签和独立的策略组件；VPC/子网提供名称、CIDR、来源明确给出的默认标识和标签，子网保留可用区及 VPC 引用。原生创建时间按原值保留。路由表、网络 ACL 等未建模字段仍可通过原始详情读取，不自动展开其配置，不推导有效开放端口。

资产独立保存，不复制到 Finding。对实质变化创建资产修订，相同内容只推进 `last_observed_at`；组件的 `observed_at` 和精确原始字节保留在原修订中。刷新失败保留既有资产，并单独报告最近刷新状态。资产变化不进入 Finding Change Feed，也不改变 Finding 修订。资产旧版本可按 `1..revision` 查询；首版没有资产快照或资产变更流。

| REST | MCP | 语义 |
| --- | --- | --- |
| `GET /assets` | `list_assets` | 查询本地已保存资产，按 ID 游标分页 |
| `GET /assets/lookup` | `get_asset_by_reference` | 按完整作用域的原生资源引用查询当前本地观测与最近刷新状态 |
| `GET /assets/{id}?revision=N` | `get_asset` | 读取当前或精确资产修订，默认不附完整组件载荷 |
| `GET /alerts/{id}/asset-context?revision=N` | `get_alert_asset_context` | 读取指定 Finding 明确主机引用的当前本地上下文 |
| `GET /assets/{id}/findings` | `list_asset_findings` | 查询同一完整资源身份的已保存 Finding，支持 Finding 快照分页 |
| `GET /assets/{id}/revisions/{revision}/components/{component}/raw` | `get_asset_component` | 读取精确组件证据；MCP 返回 `raw_text` 与 SHA-256，保留大整数和原字节表示 |

所有 REST 路径均以 `/api/v1` 开头并要求认证。`/assets` 支持 `provider/account_id/account_uid/region/resource_type/resource_id/after_id/limit`，类型为 `cvm/security_group/vpc/subnet`；首版不提供名称模糊匹配、IP 过滤或标签索引；未支持的参数报错。列表 `limit` 范围 1–100，后续将 `next_cursor` 作为 `after_id`。列表是当前本地观测，不承诺固定资产快照或完整云资产覆盖。

`/assets/lookup` 与 `get_asset_by_reference` 要求 `provider/account_uid/region/resource_type/resource_id`，可直接使用引用内的同名字段；可选 `account_id` 仅用于查最近刷新状态，必须与资源作用域一致。响应区分 `not_collected/available/stale`，`refresh.status` 单独说明失败或进行中状态，不把刷新失败解释为资源不存在。资产正文省略完整来源载荷，组件证据按精确修订读取。

Finding 上下文可用 `revision` 或 `snapshot_sequence` 选择引用所在版本，两者互斥；资产部分始终是当前观测，明确不代表告警发生时状态。同资源告警分页重复返回的 `snapshot_sequence`，并用 `next_cursor` 续读。匹配条件是腾讯云、原生账号 UID、地域、原生主机资源 ID 和主机类型；IP、名称、Hash 和标签均不建立身份关系。首版上下文使用主资源引用，相关告警检索同时支持明确的附加主机资源引用。作用域缺失、来源不支持、未采集和过期均明确返回。

默认 GET 与全部 MCP 工具仅查本地数据库，不触发云端读取。`POST /accounts/{id}/assets/refresh` 接受 `{"resource_type":"cvm","resource_id":"ins-..."}`，省略类型默认为 `cvm`；也可刷新 `security_group/vpc/subnet`。仅管理员可调用，要求启用的腾讯云连接、已配置真实账号 UID 与明确地域。使用已加密凭据，按需授予 `cvm:DescribeInstances`、`vpc:DescribeSecurityGroupPolicies`、`vpc:DescribeSecurityGroups`、`vpc:DescribeVpcs`、`vpc:DescribeSubnets` 只读权限。连接账号 UID 必须与这些凭据所属云账号一致；首版依据显式配置表达该归属。

主机刷新最多 9 次云 API 请求：一个实例查询、最多五个安全组策略查询，以及安全组详情批量查询、VPC、子网详情各一次。安全组详情复用已取得的策略组件；共享网络资源独立缓存，命中缓存后不扩大安全组范围。显式刷新单个安全组最多 2 次，VPC 或子网各 1 次。整个云读取阶段 15 秒、单次响应 2 MiB、服务级 2 QPS；不递归遍历网络，不展开安全组模板，不自动重试云请求。同一连接/地域/资源的尝试结果持久保留 5 分钟并复用，包括失败和进行中状态，重启不会清除这个冷却期。响应使用 `status` 与 `attempt.status` 表达成功、部分失败、未查到或不可见、权限不足及超时，`related` 说明各网络引用采集结果；失败保留既有观测，已取得的主机不会因可选网络请求超时而丢弃。安全组策略是配置证据，不代表实际监听或公网可达。

Web 告警详情展示上述本地上下文，展开网络引用可查询详情、策略、证据和来源路径，并由管理员显式刷新单个网络资源；主机支持相关告警查询。Mock 启动时植入 `ins-mock0001` 及其安全组、VPC、子网共四条合成资产，可从腾讯云的“SQL注入攻击”演示告警查看完整路径；数据始终带 `synthetic=true`。真实来源不会回退到这些合成数据。

当前实例仍为共享数据集，API Key 继承创建者角色并能读全部账号；未新增多租户或账号级授权。保留共同字段查询、已实现的专有查询与完整原始载荷读取，首版未建设任意原生 JSON 字段的通用过滤器。
