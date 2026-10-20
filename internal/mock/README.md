# Mock fixtures

`make mock` registers the `tencent-mock` connector and starts GuiLiu with in-memory
storage, no login, and this fixture set. It reuses the production Tencent mapper,
so the data goes through the same normalization and OCSF path as real alerts.

## 文件

- `fixtures/tencent.json`：数组，每个元素是一条腾讯云 CSIP `AlertInfo` 原始 JSON。
- 时间字段在加载时会自动改写为相对当前时间，避免 mock 数据过期后从默认时间窗消失。
- `Uin` / `AppID` / `NickName` / IP / 域名 / 资产 ID / 文件名全部为虚构值。

## 脱敏规则

新增样本时必须遵守：

- 外部 IP 使用文档保留段：`203.0.113.0/24`、`198.51.100.0/24`、`192.0.2.0/24`。
- 内网 IP 使用 `10.0.0.0/24` 或 `172.16.0.0/12`。
- UIN 使用 `100000000001`，AppID 使用 `1300000000`，账号名使用 `Mock Corp`。
- 域名使用 `example.com` 子域。
- 资产 ID 使用 `ins-mockNNNN`。
- 文件路径使用 `/tmp/mock/` 或 `/var/www/html/mock-*`。
- 不要包含真实客户名、真实公网 IP、真实账号、真实凭证、真实主机名。

## 增加样本

直接在 `tencent.json` 里追加对象即可。建议覆盖：

- `Source`: `CFW` / `WAF` / `CWP` / `CSIP`
- `Type` / `SubType`: 漏洞利用、SQL 注入、命令注入、反弹 Shell、Webshell、暴力破解、弱口令、端口扫描、CC
- `Level`: 1–5
- `Status`: 0 未处置 / 1 已忽略 / 2 已处置
- 有/无 `EvidenceData`、域名为资产、IP 为资产、容器资产

## 增加其他云

参照 `internal/mock/mock.go`：

1. 新建 `fixtures/<cloud>.json`，保存该厂商的原始告警数组。
2. 实现一个 mock connector，`Fetch` 分页返回原始数组，`Normalize` 直接调用该厂商的**生产 mapper**。
3. 在 `mock.Register` 中注册多个 provider。
4. 在 `configs/mock.json` 的 `accounts` 中增加对应 mock 账号。

这样 mock 数据永远和生产映射逻辑保持一致，不会出现“mock 能跑、真实数据不能跑”的分叉。
