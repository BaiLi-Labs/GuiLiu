# GuiLiu · 归流

**把多家云的安全告警，汇成一份可查询、可追溯、可交给 Agent 使用的数据。**

GuiLiu 接入腾讯云、阿里云、华为云、AWS、Google Cloud 的安全告警，统一转换成 OCSF Detection Finding，保留厂商原始 JSON，并提供控制台、REST API 和只读 MCP。

> 不替代云安全产品，不做 SIEM，不做 SOAR，也不内置 Agent。  
> 只解决四件事：**可靠接入、字段归一、统一查询、同步健康**。

---

## 它能做什么

- **一个入口看多云告警**：腾讯云 CSIP / 阿里云 SAS / 华为云 SecMaster / AWS Security Hub / GCP SCC。
- **字段统一**：等级、状态、资产、IP、账号、ATT&CK 等映射到 OCSF `class_uid=2004`。
- **证据可追溯**：每条告警保留原始厂商 JSON、`mapper_version` 和完整证据，可重放映射。
- **增量同步**：时间窗口、重叠回看、分页游标、去重 upsert、页级断点续传。
- **失败可恢复**：单条记录失败会持久化原始 payload，先重试再推进游标，不把漏数伪装成同步成功。
- **给人和 Agent 同一份数据**：控制台查询，REST API，以及 8 个只读 MCP 工具。
- **离线可演示**：`make mock` 内置五家云、42 条合成告警，不需要任何云账号。

## 支持的云

| 厂商 | 产品 / API | 接入状态 |
| --- | --- | --- |
| 腾讯云 | 云安全中心 CSIP `DescribeAlertList` | 已用真实账号验证 |
| 阿里云 | 云安全中心 SAS `DescribeSuspEvents` | 连接器完成，待真实 AK 校准 |
| 华为云 | 安全云脑 SecMaster `ListAlerts` | 连接器完成，待真实账号校准 |
| AWS | Security Hub `GetFindingsV2`（OCSF） | 连接器完成，待真实账号校准 |
| Google Cloud | Security Command Center `ListFindings` | 连接器完成，待真实账号校准 |

Azure / Microsoft Defender 尚未接入。

## 控制台

- 概览：告警总量、等级分布、厂商分布、最近告警、账号健康
- 统一告警：厂商 / 等级 / 状态 / 时间 / IP / 关键词筛选，详情抽屉，生命周期操作
- 云账号：接入、检测、同步、停用、编辑、删除；华为云 `project_id` / `workspace_id`、GCP `parent` 等厂商字段按连接器动态渲染
- 接入状态：账号游标、连续失败、限流 / 续传状态、最近同步运行
- MCP：API Key 创建 / 吊销、HTTP / stdio 配置、工具清单
- 深浅色自动跟随浏览器主题，也可手动锁定

品牌图标使用开源 [theSVG](https://github.com/glincker/thesvg)（MIT），内置在 React 工程中，不依赖外部 CDN。

## 快速体验

不需要云账号，直接看合成数据：

```bash
make mock
# 打开 http://127.0.0.1:8081
```

Mock 模式会启动 5 个厂商、42 条告警，关闭登录和定时同步，使用内存数据库。只用于本地开发和演示。

## 生产运行

环境要求：Go 1.26+、Node.js 20+。

```bash
make build

cp configs/guiliu.example.json guiliu.json
export GUILIU_ADMIN_PASSWORD='a-long-initial-password'
./bin/guiliu serve
```

打开 <http://127.0.0.1:8080>，用 `admin` + `GUILIU_ADMIN_PASSWORD` 登录，然后进入「云账号」接入厂商。

也可以使用 Docker：

```bash
docker build -t guiliu:dev .

docker run --rm -p 8080:8080 \
  -v "$PWD/data:/data" \
  -e GUILIU_ADMIN_PASSWORD='a-long-initial-password' \
  guiliu:dev
```

配置、部署、API、连接器开发和故障排查见 [开发与运维文档](docs/development.md)。

## 接入 MCP

登录控制台后进入「MCP」，创建 API Key，然后把配置粘贴到支持 Streamable HTTP 的 MCP 客户端：

```json
{
  "mcpServers": {
    "guiliu": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp",
      "headers": { "Authorization": "Bearer <API_KEY>" }
    }
  }
}
```

当前提供 8 个只读工具：账号列表、告警查询、告警详情、证据、按 IP / 资产检索、统计、接入健康。

## 安全模型

- Argon2id 密码哈希，HttpOnly Session Cookie
- API Key 支持创建、吊销、过期；服务端只保存 SHA-256 哈希
- 云账号 AK/SK 与 GCP Service Account JSON 使用 AES-256-GCM 加密存储
- 生产模式默认必须登录；`make dev` / `make mock` 关闭认证，只能绑定本机
- Cookie 写操作校验同源；登录接口限流
- MCP 只读，不暴露 SQL、云 API 凭据或封禁能力

## 架构

```text
腾讯云 / 阿里云 / 华为云 / AWS / GCP
              │
              ▼
      Connector 插件层
      认证 · 分页 · 限流 · 重试 · 原始 JSON
              │
              ▼
      Normalize / OCSF
      统一等级 · 资产 · IP · 证据 · mapper_version
              │
              ▼
      SQLite（Store 接口可替换 PostgreSQL / ClickHouse）
              │
        ┌─────┴─────┐
        ▼           ▼
   React 控制台   REST API / MCP
```

技术栈：Go、React 18、Tailwind CSS、Vite、SQLite、OCSF 1.6。前端源码在根目录 `web/`，构建产物由 Go `embed` 打进单个二进制。

## 当前状态

- 腾讯云：真实账号完成 24h 回填、增量同步、限流与断点续传验证
- 同步可靠性：单条失败原始 payload 持久化、失败记录优先重试、游标不越过未落库数据
- 五家云：统一 mapper、离线 Mock、单元测试和 UI 已完成
- 下一步：用真实凭据校准华为云 / AWS / GCP / 阿里云字段；补 Azure；做跨厂商同资产告警聚合

## 文档

- [开发与运维文档](docs/development.md)：配置、构建、API、MCP、部署、验证
- [连接器开发指南](docs/connector-guide.md)：新增云厂商、mapper、分页、错误分类
- [Mock 数据说明](internal/mock/README.md)：fixture 格式、脱敏规则、增加样本

## License

Apache License 2.0，见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。

厂商名称与 Logo 归各自所有者所有；本项目的许可证不授予其商标使用权。

---

如果这个项目对你有帮助，欢迎提交 Issue 或 PR。
