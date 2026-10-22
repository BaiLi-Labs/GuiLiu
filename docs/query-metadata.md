# 查询元数据与统计契约

归流返回可验证的数据访问事实，由消费端决定是否满足调查需要。不输出“数据可用/不可用”、可信度评分、地理字段质量告警或安全研判结论。

## 响应结构发现

`guiliu query describe` 和 `guiliu query groups --describe` 可离线运行，返回命令参数、`response_schema`（完整响应的 JSON Schema）及支持 NDJSON 命令的 `ndjson_item_schema`（每行记录结构）。字段名直接来自公开 JSON 类型；来源载荷与动态 Map 保留开放结构，不宣称已经描述厂商所有原生字段。

分组成员数是 `groups[].finding_count`，来源标题样本是 `groups[].top_titles[].key/count`，等级上界是 `max_severity`。它们不是 `count`、`samples`，也不是攻击次数或平台风险评级。

资产和网络分组（`asset/name_asset/vpc/subnet/security_group/nic`）返回 `summary` 对象；`signature/source/type_asset` 的 `summary` 为 null。`limitations` 只列当前分组适用的限制，网络组才声明成员可重复落入多组。标题和资产样本最多 5 项，不代表完整成员清单。

## 采集进度与命中记录

Coverage 与查询共享过滤条件，`snapshot_sequence` 固定命中 Finding 的来源版本。本地标注与同步状态仍为当前状态。

| 字段 | 含义 |
| --- | --- |
| `query_window.start/end/time_field` | 请求的绝对时间戳范围与查询时间字段；未指定边界时为 null |
| `accounts[].time_basis` | 连接器实际使用的来源时间筛选依据；不强行等同事件时间 |
| `coverage_start` / `watermark` | 首次完成来源查询的起点 / 最近完整完成的查询终点；是采集边界，不是事件分布 |
| `observed_events.finding_count` | 相同过滤和快照下的本地 Finding 数量 |
| `observed_events.start/end` | 上述记录中已知事件时间的最小/最大值；没有已知时间则为 null |
| `outside_completed_windows[]` | 请求时间戳位于完成采集边界外的部分，带起止、`duration_seconds` 和 `reason` |
| `pending_window` | 仍在分页或中断等待续传的来源查询窗口；没有则为 null，不泄露分页 Token |
| `status/reasons/failed_records/last_source_error` | 当前同步状态及已记录的失败事实 |

例如，请求 `00:00..12:00 UTC`，来源已完成查询边界为 `04:00..10:00 UTC`，则返回边界外的 `00:00..04:00` 和 `10:00..12:00`。即使本地保存了 `02:00` 发生的事件，也不修改这些采集边界。事件可能按更新时间被后续查询返回。这里的 6 小时不是“缺少一半告警”，也不证明区间内一条数据都没有。

`complete` 只表达文档规定的窗口、启用状态和同步状态检查。来源授权、保留期限、交付延迟、上游翻页变动仍是限制；当前未完整记录每次采集的独立覆盖区间。无匹配记录不能用来补造采集覆盖，区间边界内也不宣称覆盖厂商全部产品。

## 有界字段分布

```bash
guiliu query stats --since 72h --top-by title,source_ip,source_country,severity_day --top-n 20 --json
```

REST 使用 `GET /api/v1/stats?top_by=title,source_ip&top_n=20`，MCP `get_alert_statistics` 使用相同的 `top_by` 字符串与整数 `top_n`。支持 `title/source_ip/destination_ip/source_country/severity/severity_day/provider/alert_type/rule_id`，默认维度为 `title,source_ip,source_country`；`top_n` 默认 20、上限 100。未知维度、非整数或越界数量会报错。

每个 `statistics.distributions.<维度>` 返回：

- `distinct_count`：非空原值的不同值数量。
- `missing_count`：字段未提供或为空字符串的 Finding 数量；不去掉来源字符串中的空白，不改大小写。
- `top[]`：`key/count`，按数量降序、原值升序稳定打破并列；`severity_day` 另带 `severity`。
- `top_n/has_more/other_count`：返回上限、有无未展示值、其对应的记录总量。`sum(top[].count) + other_count + missing_count = statistics.total`。

这些都是 Finding 记录数，不是修订数或来源发生次数。`severity_day` 的键是 UTC 日期，统计日期边界由 `day_timezone=UTC` 明示，`distinct_count` 计算日期与来源映射等级的组合。原有 `by_day` 同样按 UTC 事件时间计数。

`source_ip` 仅统计明确映射的源 IP 字段，不把所有 IP Observables 当成攻击源。`group_by=source` 仍然按源 IP 与告警类型分组，与单字段分布不同。相同值不建立持久资产身份；`source_country` 只有一个值也只返回数量，不判断字段正确性或可用性。

相同过滤、绝对时间窗和 `snapshot_sequence` 下，REST、MCP、CLI 返回相同事实。新增数据和来源修订不会改变固定快照的分布；当前本地标注状态沿用既有契约。计算在服务端完成，消费端无需导出全部原始记录。审计保存维度、上限和有效查询条件，不保存统计结果中的原始证据。

## 输出与资产缺失

```bash
guiliu query alerts --since 24h --all --max-items 1000 --ndjson \
  --fields id,title,event_time,resource.id,source_ip > findings.ndjson
```

NDJSON 投影使用真实 JSON 字段路径，保留嵌套对象；可选字段缺失时输出 null。数组、Map、原始载荷可整体选择，不支持下标、通配符或表达式。未知路径和父子路径重叠在请求前报错；整数和证据 JSON 保持精度。表格仍使用原有列名，`--json` 继续返回完整 REST 响应。表格时间明确标记 UTC，分页和采集范围元信息留在 stderr。

资产查询只读本地观测，不触发云 API。`lookup` 无本地观测时：未指定或未找到匹配连接返回 `reason=no_saved_observation_refresh_not_checked`；检查了连接但从未记录刷新时返回 `no_recorded_refresh`；有刷新失败则返回实际记录的失败原因与来源错误。它们不表示云资产不存在或 AK/SK 必然无权限。需要管理员显式刷新后才能增加观测；完整资产继续作为独立类型提供，不复制进每条 Finding。

本批测试使用合成来源、临时数据库和本地 HTTP 服务，未新增真实云账号验证。
