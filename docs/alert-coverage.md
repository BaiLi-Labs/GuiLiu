# 云告警采集与字段覆盖核对

核对日期：2026-10-21。数据契约见 [security-data-access.md](security-data-access.md)。以 go.mod 锁定的 SDK 源码、当前连接器和厂商 API 文档为准；未使用真实账号验证权限、产品开通范围或控制台数量。

## 结论与边界

当前接入的是六个安全告警汇总入口，并非六家云所有产品的独立告警 API。只有上游入口已经收录、当前凭据可见、配置范围与时间窗口内的告警，才可能被采集。

告警类型由厂商字段提供，不维护本地类型白名单，不因类型、等级或厂商处理结果自动丢弃。字段归一与聚合不产生误报、攻击成功或风险研判。厂商返回的判断字段仅作为厂商原值展示。

| 云 | 入口与范围 | 类型字段 | 分页与范围限制 |
| --- | --- | --- | --- |
| 腾讯云 | CSIP DescribeAlertList，当前凭据可见的告警中心；Source 包括 CFW / WAF / CWP / CSIP | Type + SubType；开放字符串 | Offset / Limit，100 条/页；未传类型、等级、状态过滤；未枚举集团成员 |
| 阿里云 | SAS DescribeSuspEvents，当前账号云安全中心安全告警；不直接调用独立 WAF / CFW / ActionTrail 告警 API | AlarmEventTypeDisplay / AlarmEventType / EventSubType | CurrentPage / PageSize，100 条/页；默认显式 Status=0，用户可配置状态过滤；未启用跨账号查询 |
| 华为云 | SecMaster ListAlerts，指定 region + project_id + workspace_id | AlertType.Category + AlertType.AlertType；开放字符串 | Offset / Limit，100 条/页；无类型、等级、状态条件；未自动发现其他项目或空间 |
| AWS | Security Hub GetFindingsV2，配置地域中当前身份可见的 findings；其他产品须已汇入该入口 | finding_info.types（保留全部值），其次 metadata.event_code / class_name | NextToken，100 条/页；created / last_seen / modified 任一时间落窗；没有本地类型或等级排除；未枚举其他地域或组织 Scopes |
| GCP | SCC v2（默认），指定组织/文件夹/项目 + source + location；可显式选 v1 | category，其次 finding_class；开放字符串 | PageToken，最多 1000 条/页；sources/- 覆盖该作用域全部来源；不排除 INACTIVE 或 MUTED；每个 location 单独配置 |
| Azure | Defender for Cloud ARM Alerts - List，指定 subscription_id | properties.alertType；开放字符串 | 遍历 nextLink；无服务端时间条件，本地按厂商时间字段筛选；不直接采集 Sentinel 或 Microsoft Graph Security 告警 |

跨地域、跨订阅、跨工作空间的覆盖取决于上游汇总配置或多个连接器账号配置。仅在产品目录中列名字不能证明已接入该产品。Azure 目录已移除未直接接入的 Endpoint / Identity / Cloud Apps / Sentinel 声明；不排除上游实际转入的其他产品告警。

首次同步默认只回溯 24 小时，可配置 initial_lookback；较长回溯按 max_window 分段追赶。成功推进游标不表示厂商全部历史已导入，也不表示所有产品、地域、组织成员均被扫描。厂商保留期、上游接入、授权和版本可能限制可查历史。

### 告警类型是否有固定清单

腾讯的 Type/SubType、阿里的 AlarmEventType/EventSubType、华为的 AlertType、Azure 的 AlertType 都是开放字符串，并非 SDK 的封闭 enum；AWS 返回开放 OCSF document。不能从 SDK 源码推导出“该云只有这些告警类型”。新增厂商类型也会被拉取和保留。

GCP 的 category 同样开放；FindingClass 在本次 v2 SDK 中有 THREAT、VULNERABILITY、MISCONFIGURATION、OBSERVATION、SCC_ERROR、POSTURE_VIOLATION、TOXIC_COMBINATION、SENSITIVE_DATA_RISK、CHOKEPOINT 及未指定值。连接器不按这个枚举筛除记录，category 优先作为展示类型，完整分类仍在厂商字段中。

## 数据保留与展示

- 列表展示常用字段；详情保留原始 JSON 与统一 OCSF，并新增“字段与证据”：全部资产、可观测对象、厂商证据、可展开的全部已保存厂商字段。厂商字段名和值不翻译、不重写。
- 受影响资产的展示名优先使用厂商为该资产声明的名称（阿里 `InstanceName`、华为/AWS 资源 `name`、GCP `displayName`、Azure `compromisedEntity` 等），没有声明时才回退到域名、IP 或原生 ID；`resource.source` 记录是 `vendor_declared` 还是 `identifier_fallback`。腾讯 `Victim.Name` 的语义在来源侧不一致（SDK 写企业名称，示例与真实主机资产更像显示名），因此只原样保留为 `resource.declared_name`，不作为资产名；腾讯主机名以 CVM 资产观测为准。告警标题和描述不会成为资产名。
- 通用查询只索引明确映射的字段与 observables。能在详情查看不等于每个嵌套字段都支持搜索；未引入任意 JSON 查询或每种厂商字段的专用列。
- 腾讯直接读取 SDK 签名请求的 Raw JSON 响应，阿里/华为读取 SDK 签名请求的响应流，GCP 读取 REST JSON；均在解码到类型模型前提取完整单条对象。AWS 保留 OCSF document，Azure 保留原始 JSON 条目。未知字段和数值精度不经结构体裁剪；历史原始字节由修订 raw_url 提供并用 SHA-256 校验。
- 华为 Raw 新格式保留 ListAlertDetail 外层元数据和 data_object；GCP 保留 ListFindingsResult 的 finding 与 resource。历史未知字段若从未保存，不能靠重放恢复；开发阶段使用新数据库，不提供旧库迁移。
- 厂商独立详情接口、原生产品日志或附件接口中存在而列表没有返回的字段，不会凭空补全。当前没有逐条追加详情请求；大量告警下不能默认对每条记录再请求所有详情接口。

## 本次明确修复

1. 阿里云显式默认 Status=0；修正 EventStatus 的 2/4/8/16/32/64 等编码，未知值保留 status_N。厂商误报标签带 vendor 前缀，不形成归流判断。
2. AWS 类型不再优先显示 Create / Update 生命周期动作；保留全部 finding_info.types，支持 RFC3339 的 *_dt 时间字段；补采仅 modified_time 更新的记录。
3. GCP 新增 v2 与地域端点；保留 v1。无 location 时默认 global，区域使用 securitycenter.LOCATION.rep.googleapis.com。finding 身份保留厂商返回的完整名称及 location 路径，不改写原生 ID。
4. 华为/GCP 保留外层上下文；华为/Azure/阿里补全多资产，华为/GCP/Azure 补全多个明确地址的 observables。
5. 腾讯 ExtraInfo 全量作为厂商证据保存，包括进程、命令行、文件、HTTP、CVE、容器等返回字段。
6. Azure 普通 IP 实体保持中性 entity.ip，不推断为源地址；受影响主机不推断为 Actor，也不把主机名伪造为资产 ID。阿里资产公网/私网 IP 保持中性可观测对象；来源只认精确字段标签，不扫描文本推测方向。
7. Azure 技术与子技术、GCP 多个主技术全部保留；只有技术而没有战术时，详情仍展示。
8. 腾讯/阿里序列化失败不再静默 continue；腾讯/阿里/华为在仍有总数时收到空页会失败而非完成窗口，缺失实体也不会静默丢弃。
9. 六家 mapper 升级到 v5；腾讯随后因资产语义修正升级到 `tencent-csip/v6`：资产展示名纳入厂商声明的名称并标注 `resource.source`；腾讯新增 `Attacker.Address/Country`、`ProcessType` 的结构化投影（`source_location`、`source_country`、`response_action`），Azure 补资源所属订阅。腾讯 `Victim.Name` 原样保留为 `resource.declared_name`（语义以来源为准，不声称是实例名），`Victim.Account`（实测 AppID）不冒充账号 UID。

映射版本已升级。历史归一字段可通过 gl-cli replay 重放修正；旧记录中没有保存的信息需要重新拉取，重放不会主动补拉。

## 仍需真实数据核对的采集逻辑

- 固定时间窗口与重叠回看能减少漏读，但 Offset / PageNumber 接口在翻页期间发生上游变更时不提供数据库快照，不能数学上保证一次遍历完整。
- 腾讯按告警时间、阿里按最近发生时间、华为按搜索时间范围采集；仅修改很老告警的厂商状态是否进入当前窗口，需要对照厂商实际行为。Azure 虽然遍历全部页，窗口外的旧状态更新也可能被本地时间筛选排除。GCP event_time 按 SDK 定义包含更新/解决时间，但 mute/security marks 可能有独立更新时间。
- 尚无周期性历史全量对账或修复游标命令。若要求所有历史状态持续与云端完全一致，需要补明确范围的对账机制；当前不作此承诺。
- 没有逐产品、逐地域、逐账号的上游总数对账。真实验收应在相同入口、作用域、状态和绝对时间条件下对比上游总数、采集失败数和本地去重后的外部 ID。

## SDK 字段清单

以下为锁定 SDK 的导出字段名，不含递归子结构中的所有叶子字段。详情字段树会展开已保存对象的所有层级。空或上游未返回字段不会被编造。字段计数不是“全部已映射为通用列”的比例。

### 腾讯：AlertInfo（29 个字段）

SDK：`github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/csip v1.3.195`，源码 `v20221121/models.go`。

```text
ID, Name, Source, Level, Attacker, Victim, EvidenceData, EvidenceLocation, EvidencePath, CreateTime,
UpdateTime, Count, UrgentSuggestion, RemediationSuggestion, Status, ProcessType, Type, SubType,
ExtraInfo, Key, Date, AppID, NickName, Uin, Action, RiskInvestigation, RiskTreatment, LogType,
LogSearch
```

### 腾讯：AlertExtraInfo（90 个字段）

SDK：`同上`，源码 `v20221121/models.go`。

```text
RelateEvent, LeakContent, LeakAPI, SecretID, Rule, RuleDesc, ProtocolPort, AttackContent,
AttackIPProfile, AttackIPTags, RequestMethod, HttpLog, AttackDomain, FilePath, UserAgent,
RequestHeaders, LoginUserName, VulnerabilityName, CVE, ServiceProcess, FileName, FileSize, FileMD5,
FileLastAccessTime, FileModifyTime, RecentAccessTime, RecentModifyTime, VirusName, VirusFileTags,
BehavioralCharacteristics, ProcessNamePID, ProcessPath, ProcessCommandLine, ProcessPermissions,
ExecutedCommand, AffectedFileName, DecoyPath, MaliciousProcessFileSize, MaliciousProcessFileMD5,
MaliciousProcessNamePID, MaliciousProcessPath, MaliciousProcessStartTime, CommandContent,
StartupUser, UserGroup, NewPermissions, ParentProcess, ClassName, ClassLoader, ClassFileSize,
ClassFileMD5, ParentClassName, InheritedInterface, Comment, PayloadContent, CallbackAddressPortrait,
CallbackAddressTag, ProcessMD5, FilePermission, FromLogAnalysisData, HitProbe, HitHoneyPot,
CommandList, AttackEventDesc, ProcessInfo, UserNameAndPwd, StrategyID, StrategyName, HitStrategy,
ProcessName, PID, PodName, PodID, Response, SystemCall, Verb, LogID, Different, EventType,
Description, TargetAddress, MaliciousRequestDomain, RuleType, RequestURI, RequestUser,
RequestObject, ResponseObject, FileType, TIType, SourceIP
```

### 阿里：DescribeSuspEventsResponseBodySuspEvents（55 个字段）

SDK：`github.com/alibabacloud-go/sas-20181203/v3 v3.4.0`，源码 `client/client.go`。

```text
Advanced, AlarmEventName, AlarmEventNameDisplay, AlarmEventType, AlarmEventTypeDisplay,
AlarmUniqueInfo, AppName, AutoBreaking, CanBeDealOnLine, CanCancelFault, ContainHwMode, ContainerId,
ContainerImageId, ContainerImageName, DataSource, Desc, Details, DisplaySandboxResult, EventNotes,
EventStatus, EventSubType, HasTraceInfo, Id, ImageUuid, InstanceId, InstanceName, InternetIp,
IntranetIp, K8sClusterId, K8sClusterName, K8sNamespace, K8sNodeId, K8sNodeName, K8sPodName,
LargeModel, LastTime, LastTimeStamp, Level, MaliciousRuleStatus, MarkList, MarkMisRules, Name,
OccurrenceTime, OccurrenceTimeStamp, OperateErrorCode, OperateMsg, OperateTime, SaleVersion,
SecurityEventIds, SourceAliUid, Stages, TacticItems, UniqueInfo, Uuid, ClusterId
```

### 华为：ListAlertRsp（48 个字段）

SDK：`github.com/huaweicloud/huaweicloud-sdk-go-v3 v0.1.219`，源码 `services/secmaster/v1/model/model_list_alert_rsp.go`。

```text
Version, Id, DomainId, RegionId, WorkspaceId, Labels, Environment, DataSource, FirstObservedTime,
LastObservedTime, CreateTime, ArriveTime, Title, Description, SourceUrl, Count, Confidence,
Severity, Criticality, AlertType, NetworkList, ResourceList, Remediation, VerificationState,
HandleStatus, Sla, UpdateTime, CloseTime, IpdrrPhase, Simulation, Actor, Owner, Creator,
CloseReason, CloseComment, AlertList, IncidentList, IndicatorList, Malware, SystemInfo, Process,
UserInfo, FileInfo, OriginId, Ttd, Ttr, IsAutoClosed, SystemAlertTable
```

### GCP v1：Finding（55 个字段）

SDK：`cloud.google.com/go/securitycenter v1.48.0`，源码 `apiv1/securitycenterpb/finding.pb.go`。

```text
Name, Parent, ResourceName, State, Category, ExternalUri, SourceProperties, SecurityMarks,
EventTime, CreateTime, Severity, CanonicalName, Mute, FindingClass, Indicator, Vulnerability,
MuteUpdateTime, ExternalSystems, MitreAttack, Access, Connections, MuteInitiator, MuteInfo,
Processes, Contacts, Compliances, ParentDisplayName, Description, Exfiltration, IamBindings,
NextSteps, ModuleName, Containers, Kubernetes, Database, AttackExposure, Files, CloudDlpInspection,
CloudDlpDataProfile, KernelRootkit, OrgPolicies, Application, BackupDisasterRecovery,
SecurityPosture, LogEntries, LoadBalancers, CloudArmor, Notebook, ToxicCombination,
GroupMemberships, Chokepoint, ExternalExposure, Agent, AgentSessions, AgentAnomaly
```

### GCP v2：Finding（64 个字段）

SDK：`cloud.google.com/go/securitycenter v1.48.0`，源码 `apiv2/securitycenterpb/finding.pb.go`。

```text
Name, CanonicalName, Parent, ResourceName, State, Category, ExternalUri, SourceProperties,
SecurityMarks, EventTime, CreateTime, Severity, Mute, MuteInfo, FindingClass, Indicator,
Vulnerability, MuteUpdateTime, ExternalSystems, MitreAttack, Access, Connections, MuteInitiator,
Processes, Contacts, Compliances, ParentDisplayName, Description, Exfiltration, IamBindings,
NextSteps, ModuleName, Containers, Kubernetes, Database, AttackExposure, Files, CloudDlpInspection,
CloudDlpDataProfile, KernelRootkit, OrgPolicies, Job, Application, IpRules, BackupDisasterRecovery,
SecurityPosture, LogEntries, LoadBalancers, CloudArmor, Notebook, ToxicCombination,
GroupMemberships, Disk, DataAccessEvents, DataFlowEvents, Networks, DataRetentionDeletionEvents,
AffectedResources, AiModel, Chokepoint, VertexAi, Agent, AgentSessions, AgentAnomaly
```

### Azure：AlertProperties（27 个字段）

SDK：`github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity v0.15.0`，源码 `models.go`。

```text
ExtendedProperties, SupportingEvidence, AlertDisplayName, AlertType, AlertURI, CompromisedEntity,
CorrelationKey, Description, EndTimeUTC, Entities, ExtendedLinks, Intent, IsIncident,
ProcessingEndTimeUTC, ProductComponentName, ProductName, RemediationSteps, ResourceIdentifiers,
Severity, StartTimeUTC, Status, SubTechniques, SystemAlertID, Techniques, TimeGeneratedUTC,
VendorName, Version
```

### AWS：OCSF document

SDK：github.com/aws/aws-sdk-go-v2/service/securityhub v1.85.1；api_op_GetFindingsV2.go 的 Findings 是 document.Interface，不是拥有固定字段清单的 Alert struct。常见原始块包括 finding_info、metadata、cloud、resources、observables、evidences、remediation、compliance、vulnerabilities；不存在可从 Go struct 枚举的封闭告警类型清单。全部返回 document 保留为 Raw，通用模型只是其中一部分。

## 官方核对入口

- [腾讯 DescribeAlertList](https://intl.cloud.tencent.com/document/api/1008/80952)
- [阿里 DescribeSuspEvents](https://www.alibabacloud.com/help/en/security-center/developer-reference/api-sas-2018-12-03-describesuspevents)
- [华为 ListAlerts](https://support.huaweicloud.com/api-secmaster/ListAlerts.html)
- [AWS GetFindingsV2](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_GetFindingsV2.html) 与 [OCSF 日期过滤字段](https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_OcsfDateFilter.html)
- [GCP v2 迁移要求](https://docs.cloud.google.com/security-command-center/docs/migrate-v2-api) 与 [地域端点](https://docs.cloud.google.com/security-command-center/docs/regional-endpoints)
- [Azure 订阅告警列表](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/alerts/list?view=rest-defenderforcloud-2022-01-01)

验证覆盖：六家云请求/分页模拟测试、字段与多资产映射测试、新旧 GCP Raw 兼容测试、REST 详情资源测试、前端字段显示与转义测试。模拟测试验证本地请求/处理逻辑，不能证明云侧已开通、产品汇入或账户权限完整。
