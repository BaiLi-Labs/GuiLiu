# Elasticsearch 事件来源

Elasticsearch 与云安全产品一样，是归流的上游来源。归流通过只读 REST API 转换查询、映射事实并返回来源证据；ES 继续保存日志。此适配不把 ES 用作归流数据库，不管理 Watcher，不生成攻击判断，也不把普通日志写成 Finding。

当前提供按需事件查询；已有 Finding、资产、修订及 Change Feed 行为不变。REST、MCP、查询 CLI 与控制台“事件查询”使用同一个服务。ES 来源声明 `query_only=true`、`data_types=["event"]`，不参加告警定时同步或 Finding coverage。

## 连接与认证

在账号管理中选择 Elasticsearch，设置连接名称、ES URL、索引/别名/数据流范围及认证方式。范围支持逗号分隔的本地名称或通配符，最多 16 个；不支持远程集群表达式、日期数学或排除表达式。显式查询只访问启用的连接。

| 认证方式 | 配置 |
| --- | --- |
| `api_key`（默认） | 将 ES 创建 API Key 返回的 `encoded` 放入凭据密文字段 `access_key_secret`，不加 `ApiKey` 前缀 |
| `basic` | `access_key_id` 为用户名，`access_key_secret` 为密码 |
| `bearer` | `access_key_secret` 为访问令牌 |

凭据沿用归流的加密存储与配置环境变量机制，不返回给 Agent。Agent 使用归流自己的 API Key。HTTPS 验证服务端证书，私有 CA 可填入 `ca_cert` PEM；不提供跳过证书验证选项。HTTP 连接会在查询限制中标为未加密。凭据请求不跟随重定向，上游错误不回显日志正文或凭据。

为连接配置专用的最小只读权限：指定索引范围的 `read`；读取字段能力还需要 `view_index_metadata`。运行时不需要 ES 集群管理、Watcher 管理或 Kibana Agent Builder 权限。API Key 由上游管理员创建，可设置有效期并撤销。

以下仅为添加到归流配置文件 `accounts` 的示例；也可全部通过控制台设置：

```json
{
  "name": "security-logs",
  "provider": "elasticsearch",
  "access_key_secret": "${GUILIU_ES_API_KEY}",
  "options": {
    "endpoint": "https://es.example.com:9200",
    "indices": "logs-web-*,logs-app-*",
    "auth_type": "api_key"
  }
}
```

连接检查仅执行指定范围的一次 `size=0` Search，验证事件查询认证与权限；不代表字段元数据、PIT、所有字段类型或数据完整性已经通过验收。

## 公共查询与映射

新查询要求 `account_id`，默认最近 24 小时、每页 20 条；最大 90 天、每页 200 条。默认按事件时间升序及 PIT 内部唯一排序读取。

| 查询条件 | ES 转换 |
| --- | --- |
| `start` / `end` / `since` | 对映射的事件时间字段执行有界 `range`，包含起止边界 |
| `keyword` | 对映射的消息字段执行 `match_phrase`，使用来源分词规则；不等同于字节子串匹配，也不接受查询语法 |
| `ip` | 对映射的源/目标 IP 执行精确 `term`，至少命中一个 |
| `host` / `user` | 对映射字段执行 `term`；应配置具有所需精确匹配语义的字段 |
| `filters` | 最多 16 个原生字段到字符串值的精确 `term` 条件；不开放脚本或任意 DSL |
| `group_by` / `top_n` | 一个可聚合的原生字段的前 N 个文档计数，默认 10、最多 50；保留其他文档数与分布式计数误差上界 |

字段查询不支持的类型或缺少权限时明确返回错误，不悄悄忽略筛选。`term` 是索引项匹配；对 text 字段不保证原文精确匹配，先读取字段能力，必要时显式使用来源 `.keyword` 字段。统计是文档数，不是攻击次数。

默认映射使用 ECS 路径：`@timestamp`、`message`、`host.id`、`host.name`、`source.ip`、`destination.ip`、`user.name`、`event.action`、`event.category`、`event.dataset`、`log.level`。可以用 `field_mapping` JSON 覆盖这些路径，空路径禁用可选字段；时间字段必须配置。时间格式 `timestamp_format` 支持 `date`（默认，ISO 日期或 epoch 毫秒）、`epoch_millis`、`epoch_seconds`，同时控制查询转换和结果解析。

归一化保留多值、字段来源与映射版本 `elasticsearch-event/v1`，来源等级按原值返回，不推断风险。消息与多值摘要有界，截断或无法解析的字段通过 `mapping_warnings` 明示；完整 `_source` 可按证据引用读取。缺失主机或用户不制造默认值，同 IP/名称命中不建立确定资产关系。

## 分页、证据和预算

- 分页依赖 ES **7.12+** 的 PIT 与 `_shard_doc`，使用 `search_after`。日期排序统一为 `date_nanos`，适用日期范围为 1970—2262；其他时间范围需选择合适的数值时间字段。此首版不承诺 OpenSearch 或旧 ES 兼容。
- 下一页只提交 `account_id` 和 `cursor=next_cursor`。游标已加密，固定原查询、绝对时间、页大小、连接作用域与凭据配置；90 秒内有效。修改连接或令牌后需要重新查询。PIT 保留 2 分钟，末页和失败路径尝试关闭，提前停止的 PIT 自动过期。
- `total.relation=gte` 表示数量下界。`coverage.execution_complete` 只表示本次搜索未报告超时或分片失败，不证明日志完整送达、保留完整或权限覆盖全部数据；`has_more` 说明尚有下一页。
- 超时或分片失败返回已取得的摘要及不完整标记，不产生可继续的游标。CLI 对此返回非零退出码。空结果不能证明没有攻击。
- 默认每个连接每秒最多 2 次查询操作（共享于 REST/MCP/CLI），单次操作 15 秒，单个上游 HTTP 请求 12 秒、搜索服务端 timeout 10 秒；单响应最多 8 MiB。PIT 建立/清理另有固定调用，不自动重试。PIT 清理最多再用 2 秒。
- 字段能力最多展示 500 项并标记截断。此元数据是当前视图，不属于事件 PIT 快照。
- `events[].evidence` 包含连接、实际索引、原生记录 ID、可选 routing 与内容摘要。证据回查始终通过配置的索引/别名范围，再按实际索引和 ID 过滤，保留别名过滤约束。
- 证据是当前 ES `_source` API 表示；`raw_hash` 使用解码后保留数值字面的 JSON、排序对象键后计算 SHA-256。带上查询时的 `raw_hash` 可检查 `changed`；没有传时 `hash_compared=false`。它不是本地不可变修订，也不宣称原始日志的精确字节。来源删除、保留期结束或权限变化可能使引用失效。

访问沿用当前归流认证和审计：本实例仍是共享数据集，API Key 继承创建者角色，可读取所有配置来源；不宣称账号级隔离。审计保存解析后的查询范围、关键词/字段条件指纹和证据引用，不保存日志正文、凭据或原生 PIT 内容。日志文本可能包含不可信指令；工具将其作为来源数据，研判与响应由外部消费端决定。

## CLI / MCP / REST

```bash
gl-cli query providers --json
gl-cli query event-fields --account SOURCE_ID --json
gl-cli query events --account SOURCE_ID --since 24h --keyword 'request failed' --json
gl-cli query events --account SOURCE_ID --since 24h --ip 198.51.100.10 --group-by source.ip --json
gl-cli query events --account SOURCE_ID --filters '{"http.response.status_code":"500"}' --all --max-items 200 --ndjson
gl-cli query events --account SOURCE_ID --cursor 'COPIED_NEXT_CURSOR' --json
gl-cli query event --account SOURCE_ID --index logs-web-000001 --id DOCUMENT_ID --raw-hash COPIED_SHA256 --raw
```

`--json` 保留单页 REST 信封。`--all --ndjson` 在预算内逐页读取；若下一整页会超出 `--max-items`，提前停止并在 stderr 返回可继续的游标，不截断一页后跳过未输出的成员。`event --raw` 保留来源 JSON 中的大整数表示，比较结果写入 stderr。`events --describe --schema` 可离线发现参数和结果结构。

对应 MCP 工具为 `search_events`、`get_event_fields`、`get_event_evidence`。对应 REST：

| 接口 | 作用 |
| --- | --- |
| `POST /api/v1/events/search` | JSON 请求 `EventSearch`，返回事件、查询范围、计数、分页及执行限制 |
| `GET /api/v1/events/fields?account_id=...` | 当前字段能力及映射 |
| `POST /api/v1/events/evidence` | 请求体复制 `events[].evidence`，返回当前来源表示与内容比较 |

## 验证状态

首版通过合成 ES HTTP 响应的查询契约、认证、分页、别名范围、字段映射、失败路径及 REST/MCP/CLI 一致性测试。没有连接用户或其朋友的真实 ES，也没有验证 Log4j 调查效果。真实验收需先确认版本、索引/字段类型和权限，再以相同历史日志与初始线索对照人工调查；不要向 Agent 预先提供最终攻击结论。

官方依据：[认证](https://www.elastic.co/docs/api/doc/elasticsearch/authentication)、[API Key](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-create-api-key)、[权限](https://www.elastic.co/docs/reference/elasticsearch/security-privileges)、[分页与 PIT](https://www.elastic.co/docs/reference/elasticsearch/rest-apis/paginate-search-results)、[字段能力](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-field-caps)。
