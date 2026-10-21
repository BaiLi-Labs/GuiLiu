# 新增一个云连接器

GuiLiu 的接入层是插件化的：每个云厂商一个 package，实现四个方法并注册即可。核心代码不需要改动。

## 1. 契约

```go
type Connector interface {
	Info() Descriptor
	Check(ctx context.Context) error
	Fetch(ctx context.Context, q Query) (Page, error)
	Normalize(raw json.RawMessage) (model.Alert, error)
}
```

| 方法 | 职责 | 不应该做的事 |
| --- | --- | --- |
| `Info` | 静态描述：厂商、产品、API 版本、mapper 版本、凭据字段、子产品 | 发网络请求 |
| `Check` | 用最小代价验证 AK/SK 与只读权限（通常拉 1 条最近 1 小时的告警） | 大量拉取数据 |
| `Fetch` | 拉取**固定时间窗**内的一页原始数据，返回下一页 token | 做字段映射、写数据库 |
| `Normalize` | 把一条原始 JSON 转成厂商无关的 `model.Alert` | 访问网络、依赖全局状态 |

`Fetch` 返回的 `RawAlert.Raw` 必须是厂商响应的 JSON 序列化。它会被完整入库，并在未来用于重放映射。

`Normalize` 必须是纯函数：同一个 `raw` 永远得到同一个 `model.Alert`。OCSF 组装由 ingest 引擎统一完成，连接器不 import `internal/normalize`。

## 2. 目录与注册

```
internal/connector/acme/
├── acme.go          # Descriptor / New / Check / Fetch
├── mapper.go        # Normalize
├── acme_test.go     # 用离线样本测试 Normalize
└── testdata/
    └── alert.json   # 真实脱敏样本
```

在 `acme.go` 中：

```go
func init() {
	connector.Register(descriptor(), New)
}
```

并把 package 加入 `internal/connector/all/all.go` 的 blank import。

## 3. Descriptor

```go
func descriptor() connector.Descriptor {
	return connector.Descriptor{
		ID:            "acme",
		Name:          "ACME Cloud",
		Vendor:        "ACME",
		Product:       "ACME Security Center",
		ProductUID:    "acme.securitycenter",
		APIVersion:    "2026-01-01",
		MapperVersion: "acme-security/v1", // 映射变更时递增
		Credential: []connector.CredentialField{
			{Name: "access_key_id", Label: "Access Key", Required: true},
			{Name: "access_key_secret", Label: "Secret Key", Required: true, Secret: true},
		},
		Products: []connector.Product{{Code: "SC", Name: "Security Center"}},
	}
}
```

约定：

- `ID` 是稳定的短标识，出现在 URL、MCP 参数、数据库里，不要随 UI 改名。
- `MapperVersion` 写入每条告警与 OCSF `unmapped`。映射语义变化时递增，便于按版本重放。
- 凭据字段名由 `CredentialField` 声明，API 与 Web 控制台按 name 原样收集。AK/SK 厂商沿用 `access_key_id` / `access_key_secret` / `session_token`；GCP 使用 `service_account_json`，并设置 `Multiline: true`。
- 非凭据配置用 `OptionFields` 声明，例如华为云的 `project_id` / `workspace_id`、GCP 的 `parent`。这些值进入 `account.options`，不做加密；不要把 Secret 放进 OptionFields。
- 连接器如果持有需要释放的客户端（如 GCP gRPC），实现 `Close() error`；引擎、API 探测和 CLI 会调用 `connector.Close`。

## 4. New：客户端与限速

```go
func New(cfg connector.AccountConfig) (connector.Connector, error) {
	if cfg.Credential.AccessKeyID == "" || cfg.Credential.AccessKeySecret == "" {
		return nil, connector.ConfigError(providerID, "AK/SK are required")
	}
	client := newSDKClient(cfg.Credential, cfg.Region, cfg.Options["endpoint"])
	return &Connector{
		client:   client,
		limiter:  connector.NewLimiter(connector.OptionFloat(cfg.Options, "rate_limit", 3)),
		pageSize: connector.OptionInt(cfg.Options, "page_size", 100),
	}, nil
}
```

- 每个请求前调用 `limiter.Wait(ctx)`。云安全 API 的 QPS 往往很低（腾讯云旧接口约 3/s）。
- 支持账号级 `endpoint` 覆盖，便于私有化 / 测试环境。
- 不要在 `New` 里发请求；连接校验交给 `Check`。

## 5. Fetch：分页与时间窗

```go
func (c *Connector) Fetch(ctx context.Context, q connector.Query) (connector.Page, error) {
	page := 1
	if q.Token != "" {
		page, _ = strconv.Atoi(q.Token)
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return connector.Page{}, err
	}
	req := buildRequest(q.Start, q.End, page, q.PageSize)
	resp, err := c.client.Query(ctx, req)
	if err != nil {
		return connector.Page{}, connector.Classify(providerID, err)
	}
 // resp.Items must be []json.RawMessage extracted before SDK model decoding.
 raws := make([]connector.RawAlert, 0, len(resp.Items))
 for _, raw := range resp.Items {
  if !json.Valid(raw) || string(raw)=="null" {return connector.Page{},fmt.Errorf("invalid source record")}
  raws=append(raws,connector.RawAlert{Raw:append(json.RawMessage(nil),raw...)})
 }

	next := ""
	if page*pageSize < resp.Total && len(raws) > 0 {
		next = strconv.Itoa(page + 1)
	}
	return connector.Page{Records: raws, NextToken: next, Total: resp.Total}, nil
}
```

要求：

- `Query.Start` / `End` 是一个固定窗口。分页期间不要重新计算时间。
- token 必须自包含（页号 / offset / 厂商游标），不能依赖进程内状态，否则进程重启会丢进度。
- 返回总数字段（如果厂商提供），引擎用它判断是否还有下一页；没有总数时，以本页是否为空作为结束条件。
- 引擎按页保存 token，并默认每轮最多 10 页。页数预算用尽不是错误，而是 `partial` 暂停，下一轮自动从断点继续。连接器不需要感知这一点，若 token 会失效，应保留原始错误码/文本，便于引擎识别并从固定窗口重新读取。
- 时间参数按厂商要求格式化。中国区厂商通常使用东八区 `2006-01-02 15:04:05`，可用 `connector.FormatBeijing`。
- 使用响应流或 `json.RawMessage` 在类型解码前保留未知字段与精确数值；SDK 结构体的 `json.Marshal` 不能作为原始数据保真机制。
- 来源缺失的身份和时间保持未知，不以内容哈希或窗口末尾冒充。更新 `MappingFor` 与 Mapper 版本，并验证 `provenance` 指向实际来源路径。
- 原始数据必须是**厂商字段**，不要提前裁剪成内部结构，否则以后修复映射需要重新调用云 API。

## 6. 错误分类

```go
return connector.Page{}, connector.Classify(providerID, err)
```

`Classify` 根据厂商错误码 / 文本归类：

| Kind | 引擎行为 |
| --- | --- |
| `throttled` | 指数退避重试 |
| `transient` | 指数退避重试 |
| `auth` | 不重试，API 返回 422，提示检查凭据/权限 |
| `config` | 不重试，启动或请求参数问题 |
| `permanent` | 不重试，记录到同步错误 |

如果厂商 SDK 有结构化错误码，优先在连接器内判断后构造 `connector.Error`，不要只依赖字符串匹配。

## 7. Normalize：映射到领域模型

```go
func (c *Connector) Normalize(raw json.RawMessage) (model.Alert, error) {
	var item acme.Alert
	if err := json.Unmarshal(raw, &item); err != nil {
		return model.Alert{}, fmt.Errorf("decode acme alert: %w", err)
	}
	alert := model.Alert{
		ExternalID:       item.ID,
		Title:            item.Title,
		Description:      item.Description,
		Severity:         mapSeverity(item.Level),
		OriginalSeverity: item.Level,
		VendorStatus:     item.Status,
		EventTime:        parseTime(item.OccurredAt),
		Product:          item.Product,
		AlertType:        item.Type,
		SourceIP:         item.SourceIP,
		DestinationIP:    item.DestinationIP,
		Resource:         model.Resource{ID: item.AssetID, Name: item.AssetName, Type: "host"},
		Observables:      observables(item),
		Evidences:        evidences(item),
		Unmapped:         map[string]any{"acme": extraFields(item)},
		Raw:              append(json.RawMessage(nil), raw...),
	}
	return alert, nil
}
```

### 必须遵守

1. **不丢原始等级**：`Severity` 映射到 OCSF 1–6，同时填 `OriginalSeverity`。
2. **时间统一 UTC**：厂商无时区的时间按厂商本地时区解析，再转 UTC。缺失时留给引擎用窗口末尾兜底。
3. **`ExternalID` 稳定**：优先厂商告警 ID；没有时用 `connector.HashRaw(raw)`。不要用数组下标。
4. **资产与 IP 尽力而为**：宁可留空，也不要猜测错误的值。无法确定的字段放 `Unmapped`。
5. **证据截断**：大字段（如 base64 证据）用 `connector.Truncate` 限制在 16KB 左右；完整内容仍在 `raw`。
6. **多值字段**：ATT&CK `Tactic` / `Technique` 可用逗号分隔多个值，统一序列化层会拆为独立对象；无法确定的矩阵版本应留空。多资产可填写 `Resources` 并将资源 ID / 名称加入 `Observables`（type_id 10 / 38），以供统一检索。

### 不要做

- 不要在连接器里组装 OCSF（会导致每家 Schema 漂移）。
- 不要在这里访问数据库 / 网络。
- 不要读取全局配置或时间，否则无法重放历史数据。
- 不要把厂商状态直接映射为平台状态（`model.StatusOpen` 等）。平台状态由分析人员管理。

## 8. 测试

最小要求：用真实脱敏样本测 `Normalize`。

```go
func TestNormalize(t *testing.T) {
	raw, _ := os.ReadFile("testdata/alert.json")
	c := &Connector{}
	alert, err := c.Normalize(raw)
	if err != nil { t.Fatal(err) }
	if alert.ExternalID == "" { t.Fatal("missing external id") }
	if alert.Severity != model.SeverityCritical { t.Fatalf("severity = %v", alert.Severity) }
	if alert.EventTime.IsZero() { t.Fatal("missing event time") }
}
```

建议覆盖：

- 正常告警；
- 缺失字段 / 空响应；
- 各等级映射；
- 时间格式（含时区、毫秒时间戳）；
- 多值 tactic / 证据截断；
- 原始 JSON 能被 `json.Unmarshal` 回 SDK 结构（保证 raw 可重放）。

接入流程测试：

```bash
go test ./internal/connector/acme -run TestNormalize -v
./bin/guiliu probe -account acme-prod -since 1h -limit 3 -raw | jq .
./bin/guiliu probe -account acme-prod -since 1h -limit 3 -mapped
```

`probe` 直连厂商，不写数据库；这是确认权限、时间参数与分页行为的最快方式。

## 9. 检查清单

- [ ] `Info()` 字段完整，`MapperVersion` 已定义。
- [ ] 凭据字段命名与通用约定一致。
- [ ] 每个请求都经过 limiter。
- [ ] `Fetch` 的 token 可在进程重启后继续使用。
- [ ] 错误经过 `connector.Classify`。
- [ ] `Normalize` 是纯函数，保留 `Raw`。
- [ ] 严重等级保留原始值。
- [ ] 时间统一为 UTC。
- [ ] 有脱敏样本与映射单测。
- [ ] 已加入 `internal/connector/all`。
- [ ] 已用 `probe -raw` 与 `-mapped` 对照真实数据。
- [ ] 更新 README 的映射表与支持厂商列表。
