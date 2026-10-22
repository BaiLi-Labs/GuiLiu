# 归流安全数据访问契约

归流：统一安全数据，不统一安全结论。

来源权限与认证失败按官方 SDK / API 的结构化字段记录，具体分类、查询字段与验证边界参见 [来源访问失败与权限提示](source-errors.md)。

归流是 Security Data Access Layer。它保存来源记录、执行可重放的字段转换、维护查询索引，并向 Web、REST、MCP 与只读查询 CLI 提供相同的数据。厂商的误报、攻击、风险、处理结果仅作为来源声明；归流不新增这些判断。巡检调度、研判、封禁、通知和工单属于消费方。

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

## 资产与来源位置事实

- `resource.id` 只来自来源明确给出的原生资源标识；`resource.type` 只来自来源类型字段或该来源声明的固定类型。
- `resource.name` 按“来源声明的资产名 → 域名 / 地址 / 原生 ID”取值，`resource.source` 记录取值方式：`vendor_declared` 表示来源为该资产明确声明了可读名称（阿里 `InstanceName`、华为 `resource_list[].name`、AWS `resources[].name`、GCP `resource.displayName`、Azure `compromisedEntity`）；`identifier_fallback` 表示来源未声明名称，只用了域名、IP 或原生 ID。两者都是来源事实；告警标题、描述文本和本地标签不会被当作资产名。
- 腾讯 `Victim.Name` 的语义在来源侧并不一致：SDK 注释为“企业名称”，国际站接口示例为 `name1`，真实主机资产上观察到的是实例显示名。它因此不进入 `resource.name`，而是原样保留在 `resource.declared_name`（溯源 `/Victim/Name`），由使用者按来源语境解读。腾讯主机名以 CVM 资产观测为准；`declared_name` 与资产 `name` 的差异不做自动合并或推断。
- `resource.account_uid` 只在来源独立声明了受影响资源所属账号时填写（例如 Azure 资源 ID 中的订阅）。腾讯 `Victim.Account` 不写入该字段：实测值是 AppID，而告警账号 `account_uid` 取 UIN，两者不能混用身份。为空表示来源没有单独声明资源账号，不代表两者不同。
- 资产关联、资产分组、同资源告警查询和刷新连接统一使用“来源声明的资源账号优先，否则用告警账号”的规则。资源属于账号 B 而告警由账号 A 采集时，查询按 B 定位主机资产；刷新只使用 B 的连接，B 未接入时返回 `resource_account_not_connected`，不会用 A 的凭据去读 B 的资源。
- `source_location` / `source_country` 只保留来源对攻击者的位置声明（例如腾讯 `Attacker.Address` / `Attacker.Country`）。不解析 IP、不查询 GeoIP、不归一化国家名；为空表示来源没有声明。
- `response_action` 只保留来源声明的处置动作（例如腾讯 `ProcessType`）。它不代表归流执行了处置、不代表动作已生效，也不是本地 `status`。

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

统一筛选支持 `provider`、`account_id`、`severity`、本地 `status`、`vendor_status`、`finding_kind`、`rule_id`、`vendor_title`（原始名称精确匹配）、`ip`、`resource`、`q`、`start/end`。通用对象查询使用 `observable_value`（精确值）与可选 `observable_type`（OCSF 类型 ID，例如 IP=2、用户名=4、文件 Hash=8、资源=10）。类型 0 是明确的 Unknown 类型，不是全类型通配。

`ip` 覆盖源、目的及所有已明确提取的 IP Observables。任意文本里像 IP 的字符串不被自动赋予源/目的角色。完整 Raw 可查看，不等于所有未知嵌套字段都已进入查询索引。

## Finding Grouping

分组只表示字段等值。默认 `asset` 按完整资源身份统计并返回有界的资产与告警名称摘要；`type_asset` 仍提供类型与资产的统计视角；`signature` 使用 provider、连接配置、真实云账号 UID、region、product、原生 rule_id、资产 ID 和源 IP。关键字段缺失时保留独立记录。`source` 按源 IP 与类型统计，不代表同一次攻击或同一事件。

新增视角：

| `group_by` | 等值依据与用途 |
| --- | --- |
| `asset` | provider、真实账号 UID、region、资源类型与原生 ID；已有明确主机观测时使用该资产的原生身份，支持 AWS ARN / GCP 资源名等明确别名 |
| `name_asset` | 资产身份 + 来源产品 + 完全相等的厂商告警名称；名称不是规则 ID，也不用于去重来源记录 |
| `vpc` / `subnet` / `security_group` / `nic` | 主机来源明确引用的网络资源完整身份；最多跟随一层明确网卡引用读取已保存的网卡关系，不按 IP、名称或 CIDR 推断 |

网络视角表示“这些告警的主机明确引用该网络资源”，不证明告警经过某张网卡、某安全组规则生效或攻击关系成立。当前只关联明确的主资源主机；不自动将一个 Finding 的所有次要资源铺开。没有主机观测或明确网络引用的记录逐条保留，不以空值合并。普通查询只读本地数据，不调用云 API。

`asset`、`name_asset` 与网络视角返回独立的 `asset_snapshot_sequence`。翻页与展开时应同时携带它、Finding 的 `snapshot_sequence` 和绝对时间窗口；上述分组成员展开缺少资产水位会报错。资产水位在实质修订保存时持久递增，与 Finding 变化序号独立，重启后保留。已有 schema 5 资产修订在首次启动时补建辅助水位索引。同内容刷新不改变分组关系水位。摘要使用该水位下的不可变资产修订及其 `observed_at`，不宣称包含最新重复确认时间，也不表示告警发生时的历史配置。资产列表及普通资产查找仍是实时本地观测；没有新增通用资产 Change Feed。

每组返回 `asset_count`（匹配的独立主机观测数）、最多 5 个 `assets`（ID、修订、观测时间及显式引用）和最多 5 项 `top_titles`（原始名称及精确计数），它们是摘要而非完整清单。网络组额外返回最多 5 项 `relation_evidence`，固定主机修订、声明关系的主机或网卡 ID/修订，以及来源组件与 JSON Pointer，可按精确版本读取原始证据。完整成员继续按同一 `group_key` 分页读取；`vendor_title` 可精确筛选某一原始名称，保留大小写和空白，不做模糊归类。未归并记录通过 `missing_fields` 说明缺失字段。

页面级 `summary` 返回独立 `finding_count`、有主机观测的 `asset_context_finding_count`、缺少分组依据的 `ungrouped_finding_count` 和可重复的 `membership_count`。同一告警可属于多个安全组或网卡组，每组内只计一次；跨组数量不能作为独立告警总量相加。Web 默认先展开摘要，再按名称或全部成员下钻；网络详情仍独立按来源引用查询。

- `finding_count`：分组中的独立来源记录数量。
- `revision_count`：成员的可记录内容变化次数，不含每条记录的初始版本。
- `occurrence_count`：单条来源明确报告的次数，附带 `occurrence_scope`。当前不跨记录求和，不把不同厂商或不同定义的次数混算。
- `max_severity`：成员的最高厂商映射等级，不是归流对分组的风险评价。

展开成员需重复分组返回的完整 `group_key`、查询过滤条件、绝对时间窗口、`snapshot_sequence`，以及返回的 `asset_snapshot_sequence`。

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

`GET /api/v1/coverage?start=...&end=...` 与 MCP `get_data_coverage` 返回每个来源的 API、版本、配置作用域、时间筛选依据、完成采集窗口的起止水位、失败数、同步状态和限制。明细、分组和统计查询返回相同结构。

`complete=true` 是机械的采集检查：请求时间范围有界、时间戳边界落在保存的完成采集水位内、账号启用且同步健康、没有待映射失败；当前仅对默认 `event_time` 查询给出此检查。来源可能实际按更新时间、最近发生时间或来源专有时间筛选，因此它不保证事件时间完整覆盖，更不是数据可用性、可信度或安全评分。近期成功不证明更早历史已导入；空结果不证明上游没有告警。

`coverage_start` 是首次成功完成的**来源查询窗口起点**，`watermark` 是最近完整采集窗口终点；二者都不是 `MIN/MAX(event_time)`，也不是 Change Feed 游标。`observed_events` 单独给出相同过滤与 Finding 快照下命中记录的数量、最早和最晚事件时间。较早事件被较晚的来源查询返回时，两组时间可以不同。未命中记录时数量为 0、事件边界为 null，不推算未采集区间。

`outside_completed_windows` 将请求时间戳与已保存的完成采集边界比较，列出边界外的起止、秒数与原因；它不统计缺失告警、不提供缺失比例，也不假装提供每次采集窗口的完整账本。必须结合 `query_window.time_field` 和来源 `time_basis` 阅读。`pending_window` 表示尚未完成分页的采集窗口，`reasons`、失败数和来源错误单独解释当前同步事实。Finding 快照固定命中记录，采集状态始终是当前保存状态，不提供历史同步状态快照。具体契约和示例见 [查询元数据](query-metadata.md)。

覆盖信息明确声明未汇入该 API 的产品、权限外记录、厂商保留期、延迟到达、Offset 翻页的上游变动，以及旧告警状态更新可能落在采集窗口之外。当前没有宣称全厂商产品覆盖或持续历史状态完全一致。

## MCP 与消费端

MCP 提供 `list_alert_changes`、`get_alert_revisions`、`get_data_coverage`、`get_provider_mapping`，以及明细、分组、证据和统计查询。`get_alert` 可指定精确 `revision` 或 `snapshot_sequence`。全部工具只读；外部调度器决定何时查询，外部系统决定如何研判和响应。

## 资产上下文首版

控制面资产适配已覆盖已注册的六家云。每家只按精确原生 ID 读取，不做列表扫描，也不按 IP、名称或标签反查主机身份。接口依据与主机原生身份：

| provider | 主机类型 | 主机接口 | 网络接口 | 主机原生身份 |
| --- | --- | --- | --- | --- |
| tencent | cvm | CVM `DescribeInstances` | VPC `DescribeVpcs`、`DescribeSubnets`、`DescribeSecurityGroups`、`DescribeSecurityGroupPolicies` | `ins-…` |
| aliyun | ecs | ECS `DescribeInstances` | VPC `DescribeVpcs`、`DescribeVSwitches`；ECS `DescribeSecurityGroups`、`DescribeSecurityGroupAttribute` | `i-…` |
| huawei | ecs | ECS `ShowServer` | VPC `ShowVpc`、`ShowSubnet`、`ShowSecurityGroup` | UUID |
| aws | ec2 | EC2 `DescribeInstances` | EC2 `DescribeVpcs`、`DescribeSubnets`、`DescribeSecurityGroups` | `i-…`；告警可用 ARN |
| gcp | gce | Compute `Instances.Get` | Compute `Networks.Get`、`Subnetworks.Get`、`Firewalls.Get` | `projects/…/zones/…/instances/…` |
| azure | vm | Compute `VirtualMachines.Get`（instanceView） | Network Interfaces、PublicIPAddresses、VirtualNetworks、Subnets、NetworkSecurityGroups | 小写 ARM 资源 ID |

腾讯云主机刷新会额外请求一次本主机 ENI 限定查询，并把响应保存在 `network_interfaces` 组件；阿里云与 AWS 从实例响应读取 ENI ID，Azure 从 VM 的 `networkInterfaces` 引用读取。网卡（`nic`）按来源能力接入：腾讯云 `DescribeNetworkInterfaces`（先按 `attachment.instance-id` 限定本主机，再按 ENI ID 读取）、阿里云 `DescribeNetworkInterfaces`、AWS `DescribeNetworkInterfaces`、Azure `Network Interfaces.Get`。主机只引用来源明确返回的 ENI/NIC ID；网卡资产保留原生 ID、名称、MAC、主网卡标识、私网 IP、来源直接返回的公网 IP、标签，以及 `belongs_to_vpc`、`in_subnet`、`attached_security_group`、`attached_to_host` 显式关系。Azure 网卡响应只返回公网 IP 资源 ID，首版不解析其地址，公网地址仍以主机观测为准。GCP 的 `networkInterfaces` 不是独立资源，保留在主机组件中；华为云 `ShowServer` 不返回 port ID，当前不建立网卡资产。两者都在资产差异中明确说明，不补造 ID。

真实账号测试只需要提供对应云的最小只读凭据与明确作用域：

| provider | 凭据 | 连接作用域必填 |
| --- | --- | --- |
| tencent | SecretId / SecretKey（临时凭据加 token） | 账号 UID、地域 |
| aliyun | AccessKey ID / Secret（临时凭据加 STS token） | 账号 UID、地域 |
| huawei | AK / SK（临时凭据加 security token） | 账号 UID、地域、`project_id` |
| aws | AccessKey ID / Secret（临时凭据加 token） | 12 位账号 ID、地域 |
| gcp | Service Account JSON | 项目 ID（`account_uid` 或 `project`），地域可为空 |
| azure | Client ID / Secret | 订阅 ID、`subscription_id`、`tenant_id`、地域 |

只读权限：腾讯云 CVM/VPC 查询，阿里云 ECS/VPC 查询，华为云 ECS/VPC 查询，AWS `ec2:Describe*`，GCP `compute.instances.get`、`compute.networks.get`、`compute.subnetworks.get`、`compute.firewalls.get`，Azure `Microsoft.Compute/virtualMachines/read` 与 `Microsoft.Network/*/read`。凭据加密保存，日志和错误不输出凭据。

六家共用同一资产契约：实例 ID、真实云账号 UID、地域、名称、OS、规格、厂商状态、可用区、公私网 IP、VPC、子网、安全组 ID、网卡、标签与字段溯源。账号和地域来自连接配置，不宣称为实例 API 返回字段。软件、监听端口与可达性组件保持 `not_collected`。

组件证据保存来源 JSON。腾讯云、阿里云、华为云直接读取响应字节；GCP、Azure 在 SDK 传输层截获原始响应体后仍交回 SDK 解析，因此同样保存精确字节（`raw_form=exact_bytes`）。AWS EC2 使用 XML Query 协议，组件由 SDK 类型化响应重新编码为 JSON，标记 `raw_form=api_projection`，不会保留 SDK 未建模的字段。每条组件带 `source_api`、`api_version`、`observed_at` 与 `raw_hash`，按精确资产修订读取。

来源能力差异必须显式保留，不补齐、不推断：

- GCP 没有按实例绑定的安全组；防火墙按网络与 target tag 生效。GCP 主机只建立 VPC/子网引用，`security_groups` 组件标记 `source_has_no_instance_security_group_attachment`，不推导哪些防火墙对该主机生效。
- 华为云 `ShowServer` 不返回子网 ID。华为主机保留来源 `metadata.vpc_id` 的 VPC 引用，子网保持未知。
- Azure 的 IP、子网与 NSG 位于网卡上。主机刷新只跟随 VM 显式引用的网卡（最多 3 张）、公网 IP（最多 3 个）与 NSG（最多 5 个），不列举订阅内资源。
- AWS 显示名取 `Name` 标签，溯源标记 `source_tag_name_projection`；GCP OS 取磁盘 license 名，溯源标记 `source_license_projection`；GCP 标签只来自 `labels`，网络标签 `tags.items` 保留在组件证据中，不伪造成键值标签；华为云当前网络详情接口不返回标签，主机标签取 ECS `tags`。来源没有声明时保持未知。

安全组、VPC、子网作为独立资产保存，不把完整网络资源复制进每台主机。`references` 带 provider、原生账号 UID、region、resource_type、resource_id、来源组件、JSON 路径和 `lookup_url`；仅来源明确的 ID 建立引用。安全组提供名称、说明、标签和策略组件；策略来自腾讯云 `DescribeSecurityGroupPolicies`、阿里云 `DescribeSecurityGroupAttribute`，AWS/华为/Azure/GCP 的安全组或防火墙详情本身包含规则，因此不额外请求。VPC/子网提供名称、CIDR、来源明确给出的默认标识与标签；原生创建时间按原值保留。路由表、网络 ACL 等未建模字段仍可通过原始详情读取，不展开其配置，不推导有效开放端口。

资产独立保存，不复制到 Finding。对实质变化创建资产修订，相同内容只推进 `last_observed_at`；组件的 `observed_at` 和精确原始字节保留在原修订中。刷新失败保留既有资产，并单独报告最近刷新状态。资产变化不进入 Finding Change Feed，也不改变 Finding 修订。资产旧版本可按 `1..revision` 查询；资产列表与普通查找没有通用资产快照或资产变更流；Finding 资产/网络分组通过独立资产修订水位固定关系与摘要。

| REST | MCP | 语义 |
| --- | --- | --- |
| `GET /assets` | `list_assets` | 查询本地已保存资产，按 ID 游标分页 |
| `GET /assets/lookup` | `get_asset_by_reference` | 按完整作用域的原生资源引用查询当前本地观测与最近刷新状态 |
| `GET /assets/{id}?revision=N` | `get_asset` | 读取当前或精确资产修订，默认不附完整组件载荷 |
| `GET /alerts/{id}/asset-context?revision=N` | `get_alert_asset_context` | 读取指定 Finding 明确主机引用的当前本地上下文 |
| `GET /assets/{id}/findings` | `list_asset_findings` | 查询同一完整资源身份的已保存 Finding，支持 Finding 快照分页 |
| `GET /assets/{id}/revisions/{revision}/components/{component}/raw` | `get_asset_component` | 读取精确组件证据；MCP 返回 `raw_text` 与 SHA-256，保留大整数和原字节表示 |

所有 REST 路径均以 `/api/v1` 开头并要求认证。`/assets` 支持 `provider/account_id/account_uid/region/resource_type/resource_id/after_id/limit`；`resource_type` 必须是该 provider 声明的类型（主机类型加 `security_group/vpc/subnet/nic`；GCP、华为云不支持 `nic`）。首版不提供名称模糊匹配、IP 过滤或标签索引；未支持的参数报错。列表 `limit` 范围 1–100，后续将 `next_cursor` 作为 `after_id`。列表是当前本地观测，不承诺固定资产快照或完整云资产覆盖。

`/assets/lookup` 与 `get_asset_by_reference` 要求已知 provider、`account_uid`、`resource_type`、`resource_id`，以及该 provider 要求的地域（GCP 允许全局作用域为空）；可选 `account_id` 仅用于查最近刷新状态，必须与资源作用域一致。响应区分 `not_collected/available/stale`，`refresh.status` 单独说明失败或进行中状态，不把刷新失败解释为资源不存在。资产正文省略完整来源载荷，组件证据按精确修订读取。

`/alerts/{id}/asset-context` 与 `/assets/lookup` 始终返回 `scope`，说明本次查询实际使用的 provider、`account_uid`、region、`resource_type`、`resource_id`、`source_api` 与 `api_version`；来源请求本身失败时，`refresh.source_error` 保留结构化错误（provider、kind、SDK 错误码、HTTP 状态、调用的接口）。因此“范围内没有记录”“权限不足”“地域配错”可以分开判断，而不是都落在一句 unavailable 上。

刷新状态区分四种结果，其中只有最后一种携带 `source_error`：

| 状态 | 含义 | 是否请求云端 |
| --- | --- | --- |
| `scope_mismatch` | 本地作用域检查拒绝（例如资源订阅与该连接配置不一致） | 否 |
| `not_requested` | 没有可用客户端或凭据，请求未发出 | 否 |
| `not_found_or_not_visible` | 授权范围内已请求，来源没有该记录 | 是 |
| `permission_denied` / `authentication_failed` / `access_denied` / `source_request_failed` / `timeout` / `throttled` | 请求已发出并失败 | 是 |

`scope_mismatch` 与 `not_requested` 不是来源事实，不应被解读为“资源不存在”。主机资产的刷新目标账号与告警采集账号可能不同；`refresh_account_id` 为空且 `refresh_reason=resource_account_not_connected` 时，说明资源所属账号尚未配置连接。

Finding 上下文可用 `revision` 或 `snapshot_sequence` 选择引用所在版本，两者互斥；资产部分始终是当前观测，明确不代表告警发生时状态。匹配条件是 provider、**资源所属账号**（来源声明的资源账号优先，否则用告警账号）、地域、原生主机资源 ID 和主机类型；`matched_on` 用 `resource_account_uid` 表示该规则，来源未单独声明资源账号时它取告警账号的值。IP、名称、Hash 和标签均不建立身份关系。腾讯云、阿里云告警存在稳定的主机类型 `host`，该类型同时参与匹配；华为、AWS、GCP、Azure 的告警资源类型由各产品自定义，关联告警只按精确原生 ID 或声明的厂商别名（AWS ARN、GCP 完整资源名）匹配。首版上下文使用主资源引用；相关告警检索同时支持明确的附加主机资源引用。作用域缺失、来源不支持、未采集和过期均明确返回。

默认 GET 与全部 MCP 工具仅查本地数据库，不触发云端读取。`POST /accounts/{id}/assets/refresh` 接受 `{"resource_type":"…","resource_id":"…"}`；省略类型时使用该 provider 的主机类型。可刷新主机、`nic`、`security_group`、`vpc`、`subnet`。仅管理员可调用，要求启用的连接、真实账号 UID、该 provider 要求的地域，以及华为 `project_id`、Azure `subscription_id` 与 `tenant_id`（使用客户端 ID/密钥）。只读权限按实际接口授予：腾讯云 CVM/VPC、阿里云 ECS/VPC、华为云 ECS/VPC、AWS EC2、GCP Compute、Azure Compute/Network。连接账号 UID 必须与凭据所属云账号一致；首版依据显式配置表达该归属。

请求预算与失败处理使用统一边界，按来源能力分别计数：整个云读取阶段 15 秒、单次响应 2 MiB、服务级 2 QPS、不递归遍历网络、不展开安全组模板、不自动重试云请求。主机刷新最多一次实例查询，加最多五个安全组策略/详情查询；腾讯云另有一次本主机 ENI 限定查询，主机刷新总请求上限为 10。网络引用元数据按来源能力批量或逐个精确 ID 读取：腾讯云、AWS 可一次查询多个安全组，阿里云、华为云、GCP、Azure 逐个查询且最多五个；GCP 只读 VPC 与子网；Azure 另受 3 张网卡、3 个公网 IP、5 个 NSG 上限约束。网卡读取最多 5 张；腾讯云主机刷新先做一次本主机 ENI 限定查询，后续引用复用该结果，不重复请求。AWS、华为、GCP、Azure 的安全组或防火墙详情包含规则，不额外取策略。显式刷新单个安全组按来源决定是否再取策略。同一连接/地域/资源的尝试结果持久保留 5 分钟并复用，包括失败和进行中状态，重启不会清除这个冷却期。响应使用 `status` 与 `attempt.status` 表达成功、部分失败、未查到或不可见、权限不足及超时，`related` 说明各网络引用采集结果；失败保留既有观测，已取得的主机不会因可选网络请求超时而丢弃。安全组策略是配置证据，不代表实际监听或公网可达。

Web 告警详情展示上述本地上下文，展开网络引用可查询详情、策略、证据和来源路径，并由管理员显式刷新单个网络资源；主机支持相关告警查询。Mock 启动时为每个 mock 账号植入一台合成主机及其网络资源（腾讯云 `ins-mock0001`/`eni-mock0001`、阿里云 `i-mock0001`/`eni-mock0001`、AWS `i-0123456789abcdef0`/`eni-0123456789abcdef0`、Azure 固定 ARM VM/NIC ID、华为云固定 UUID、GCP 完整资源名），数据始终带 `synthetic=true`。腾讯云与阿里云的演示告警资源 ID 与合成主机一致，可直接从告警查看完整资产路径；其他云的演示告警可能引用其他资源，可通过 `/assets` 列表或 `list_assets` 查看该账号的合成主机。真实来源不会回退到这些合成数据。

腾讯云已完成一个真实账号、一台主机、一个地域的完整调查路径验证：schema 5 数据库、72 小时 CSIP 告警同步、告警→主机资产→网卡/安全组/VPC/子网引用→同一资源的相关告警→原始证据，REST/MCP/查询 CLI 结果一致；该验证不代表其他主机、其他地域或其他云已通过。Web 复用同一 REST 接口，未做浏览器视觉回归。阿里云、华为云、AWS、GCP、Azure 仍只通过合成响应、SDK/接口契约与本地测试验证。真实账号验证必须分别标记，不能互相代替。真实账号验收步骤见[资产阶段 B 验收清单](asset-acceptance.md)。

当前实例仍为共享数据集，API Key 继承创建者角色并能读全部账号；未新增多租户或账号级授权。保留共同字段查询、已实现的专有查询与完整原始载荷读取，首版未建设任意原生 JSON 字段的通用过滤器。
