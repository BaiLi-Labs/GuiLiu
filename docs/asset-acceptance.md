# 资产阶段 B 真实账号验收

状态：腾讯云完成（2026-10-22）；其余五家待验证。合成响应的自动化验证不能替代本清单。

已执行：新建 schema 5 数据库，使用一个腾讯云真实账号（`ap-guangzhou`）同步 72 小时 CSIP 告警。同步分两轮、每轮 10 页，合计约 1991 条，状态为 `partial`（页面预算耗尽，窗口未完全覆盖）；在该数据集内选择一台有 4 条告警的主机，完成：

1. 刷新主机：`available`；
2. 资产：主机 + 4 个引用（VPC、子网、安全组、网卡），网卡 1 张；
3. 告警上下文：`available`，`matched_on` 含 provider/account UID/region/原生资源 ID；
4. 相关告警：4 条，与主机告警数一致；
5. 原始证据：`instance` 组件 1955 字节，`raw_hash` 与 `/raw` 的 SHA-256 一致；
6. REST 与 MCP：同一资产、上下文、NIC lookup、相关告警和证据结果一致；
7. 查询 CLI：`context`、`asset`、`findings`、`lookup`、`component` 与 REST 一致（CLI 组件输出末尾多一个换行，去掉后字节完全一致）。

Web 使用同一 REST 接口，未做浏览器视觉回归。

验收过程中发现并修复：资产组件原始字节在 JSON 存储时被 `encoding/json` 压缩，导致 `raw_hash` 与实际 `/raw` 字节不一致；现改为以 JSON 字符串保存精确字节，并新增回归测试。旧 schema 5 数据库中的历史资产组件仍是旧格式，重新刷新后生成的新修订使用新格式。

未执行：阿里云、华为云、AWS、GCP、Azure 的同路径真实账号验收。

范围：选**一个云、一个真实账号、一个明确地域**，完成“告警 → 主机资产 → 网卡/网络引用 → 同一资源身份的相关记录 → 原始证据”的 Web、REST、MCP 与查询 CLI 路径。当前优先腾讯云 CVM，其次阿里云 ECS、AWS EC2、Azure VM。

## 前置条件

- 一个启用的连接：真实账号 UID、地域、只读 AK/SK（GCP 为 Service Account JSON，Azure 为 Client ID/Secret + `subscription_id` + `tenant_id`）。
- 至少一条已采集告警，其主资源是目标主机；没有告警时也可直接刷新主机资产。
- 管理员身份（`POST /accounts/{id}/assets/refresh` 仅管理员可调用）。
- 新数据库或已确认 schema 的数据库；不要复用旧的合成资产数据作为验收证据。

## 验收步骤

1. **确认连接与范围**
   - `GET /api/v1/coverage` 或 `gl-cli query coverage`：确认账号启用、API 版本、地域/账号 UID。
   - `gl-cli query providers`：确认该 provider 的能力声明。
2. **显式刷新主机**
   - `POST /api/v1/accounts/{connection_id}/assets/refresh`，body 为 `{"resource_id":"<原生主机 ID>"}`；省略 `resource_type` 使用该 provider 的主机类型。
   - 记录 `status`、`attempt.status`、`related` 和耗时；期望 `available` 或带明确原因的 `partial`。
3. **检查主机资产**
   - `GET /api/v1/assets/{asset_id}`：核对实例原生 ID、账号 UID、地域、OS、规格、状态、公私网 IP、VPC/子网/安全组、标签、`mapper_version`、`observed_at`。
   - 组件 `instance` 与 `network_interfaces` 应有 `source_api`、`api_version`、`raw_hash`；`GET .../revisions/{revision}/components/{component}/raw` 读取精确字节并复核 SHA-256。
4. **检查网卡**
   - `GET /api/v1/assets?provider=...&account_uid=...&region=...&resource_type=nic`：期望返回主机显式引用的 ENI/NIC，数量与云控制台一致（最多 5 张）。
   - 每张网卡核对：原生 ID、名称、MAC、主网卡标识、私网 IP、来源提供的公网 IP、`belongs_to_vpc`、`in_subnet`、`attached_security_group`、`attached_to_host`。
   - 腾讯云/阿里云/AWS/Azure 应产生网卡资产；GCP 与华为云应明确没有 `nic` 资产，而不是伪造 ID。
5. **检查告警上下文**
   - `GET /api/v1/alerts/{alert_id}/asset-context` 与 MCP `get_alert_asset_context`：期望 `status=available`，`matched_on` 含 provider/account UID/region/原生资源 ID，`asset.references` 可继续 lookup。
   - 对没有显式主机引用的告警，期望 `no_explicit_primary_host_reference`，不能按 IP 或名称关联。
6. **检查同资源相关记录**
   - `GET /api/v1/assets/{asset_id}/findings` 与 MCP `list_asset_findings`：与 `GET /api/v1/alerts?resource=<原生主机 ID>` 的已保存记录一致；记录 `matched_on` 和分页游标。
7. **四入口一致性**
   - 对同一资产分别用 Web、REST、MCP、`gl-cli query asset/lookup/findings/component` 读取，比较资源身份、字段值、组件原始字节和分页结果。
8. **缺口与失败表达**
   - 明确授权拒绝：期望 `permission_denied` 或带组件失败的 `partial`；凭据认证失败为 `authentication_failed`，原因不明确的访问拒绝为 `access_denied`。核对 `source_error` 的 SDK 原错误码和实际 API，不能静默成功。参见 [来源错误契约](source-errors.md)。
   - 不存在的资源 ID：期望 `not_found_or_not_visible`，不能解释为已删除。
   - 缓存：5 分钟内重复刷新期望 `cached`，不产生新的云请求。
   - 过期：超过本地观测时效期望 `stale`。
   - 重启后：刷新冷却与本地观测仍在；GET 不触发云 API。
9. **对账与记录**
   - 在同一账号、地域、API 与绝对时间范围内与云控制台核对主机数量、网卡数量、安全组/VPC/子网引用。
   - 记录：provider、账号 UID、地域、API 版本、刷新时间、请求数、`status`、失败原因、NIC 数量、告警 ID 和资产 ID。
   - 将结果标记为“真实账号已验证”；未执行的部分保持“合成验证”。

## 通过标准

- 同一调查路径在 Web、REST、MCP、CLI 返回一致的事实与证据。
- 主机、网卡、安全组、VPC、子网的身份和关系来自来源明确字段。
- 缺失、未授权、未采集、过期、冲突和身份不明确都有明确表达。
- 网卡 IP 与安全组不被合并成“开放端口”或“可达性结论”。
