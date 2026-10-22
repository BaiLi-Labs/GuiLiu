# 版本管理

当前版本由 [`internal/version/VERSION`](../internal/version/VERSION) 定义。项目在开发期使用 `0.x.y`；`1.0` 留到有持续真实使用、核心数据访问契约稳定、升级与运维流程经过验证后，再明确决定发布。

## 编号约定

| 变化 | 示例 | 要求 |
| --- | --- | --- |
| 开发快照 | `0.2.0-dev` | 尚未发布，不作为稳定性或真实云验证承诺 |
| 发布候选 | `0.2.0-rc.1` | 功能范围收敛，进入发布前验证 |
| 日常开发迭代 | `0.3.0-dev` → `0.3.1-dev` | 同一阶段内的功能完善、优化与修正默认递增第三段，不因新增一个功能就递增第二段 |
| 明确阶段里程碑 | `0.2.0` → `0.3.0` | 明确切换产品阶段时才递增第二段；普通功能增加不自动视为里程碑，同时记录契约与升级影响 |
| 已发布版本的问题修复 | `0.2.0` → `0.2.1` | 修复问题，不额外扩大功能范围 |

每个提交不必升版。完成一批可验证的改动时更新版本与日志；修复、功能和不兼容变化都应有面向使用者的说明。`0.x` 阶段可以调整契约，但变更日志必须说明影响，不应以“仍在开发”为由遗漏记录。

产品版本、REST `/api/v1`、数据库 schema、OCSF schema 与各来源 `mapper_version` 是不同的编号。产品升版不会自动改变其余编号；Mapper 转换规则或数据契约变化仍需单独维护相应版本。

## 更新版本

在仓库根目录执行：

```bash
make version
make version-set NEXT_VERSION=0.3.1-dev
```

升版命令同步修改版本源、`web/package.json` 与 lockfile 的根包版本，不创建 Git 标签、不提交、不推送。随后整理 [`CHANGELOG.md`](../CHANGELOG.md) 中的具体版本条目，再执行：

```bash
make version-check
make test
make vet
make build
./bin/gl-cli version
```

检查要求版本源、前端包及 lockfile 版本一致，并且变更日志存在同版本条目。Make 构建/测试和前端 `npm test`、`npm run build` 都会执行检查，版本或日志遗漏会导致失败。单独执行 `go test ./...` 不替代这项仓库元数据检查。

开始下一轮开发时，可以先把变更记入 `Unreleased`；确定批次后再升版归档。形成发布候选或发布版本时，将对应开发条目整理为最终版本，写明日期、已验证范围和已知限制，不把合成数据验证写成真实账号验证。

## 构建与展示

Go 直接嵌入版本源，因此 `go run`、普通 `go build`、Make 与 Docker 默认使用相同的产品版本。前端显示后端 `/api/v1/meta` 返回的版本；MCP 初始化的 `serverInfo.version` 和 CLI `gl-cli version` 使用同一值。

Git 提交号和构建时间独立显示为 `commit`、`build_date`。Make 注入提交号与 UTC 构建时间；已跟踪文件未提交时提交号带 `-dirty`。普通 Go 构建未注入这些字段时会保留 `dev`/空时间，不伪造构建来源。Docker 直接构建时提交号默认 `dev`，使用 `make docker` 会传入提交号和构建时间，并使用当前产品版本作为镜像标签。

## 发布记录

修改本地版本号和变更日志不代表已经发布。真正发布时，应先完成检查与必要的真实来源验证，将对应改动提交后，再明确创建 `v0.x.y` 标签和发布说明。开发快照不自动打标签，也不为过去未发布的提交补造正式发布历史。

## Tag 自动构建与发布

[发布工作流](../.github/workflows/release.yml) 仅监听推送 `v*` 标签，不响应普通分支 push 或 PR，也不自动创建标签。标签必须是合法的 `v` 前缀 SemVer，且与 `internal/version/VERSION`、前端元数据及变更日志一致，否则直接失败。版本例如 `v0.3.3`；带 `-dev`、`-rc.1` 等后缀的标签会创建 GitHub prerelease。

工作流先执行 Go 测试/vet、前端测试/构建和打包测试，再交叉构建六个平台；全部成功后才发布 GitHub Release 与 `SHA256SUMS`：

| 平台 | 架构 | 压缩包示例 |
| --- | --- | --- |
| Linux | amd64 / arm64 | `guiliu-linux-amd64-v0.3.3.tar.gz` |
| macOS | amd64 / arm64 | `guiliu-mac-arm64-v0.3.3.tar.gz` |
| Windows | amd64 / arm64 | `guiliu-windows-arm64-v0.3.3.zip` |

每包有单独顶层目录，包含 `gl-cli`（Windows 为 `gl-cli.exe`）、`skills/`、中英文 README、LICENSE、NOTICE、更新日志、公共文档与配置示例。使用显式文件范围，不打包运行数据、真实配置、密钥、日志、采集导出或整个工作目录。包名保留产品名 `guiliu`；配置文件、环境变量与服务标识也继续使用 GuiLiu 名称。

完成版本整理并提交后，维护者主动创建、推送标签，例如（这里只是发布步骤，不由升版命令代做）：

```bash
git tag -a v0.3.3 -m "Release v0.3.3"
git push origin v0.3.3
```

本地检查全部打包目标（不上传、不创建标签）：

```bash
make web
python3 scripts/package_release.py --tag "v$(cat internal/version/VERSION)" --all
python3 scripts/release_manifest.py --tag "v$(cat internal/version/VERSION)" --directory bin/release --notes bin/release-notes.md
```

只构建一种平台时使用 `--goos darwin --goarch arm64` 替代 `--all`。版本信息不会通过链接参数伪装成另一版本。本地有未提交改动时提交元数据带 `-dirty`。产物使用 `CGO_ENABLED=0` 与 `-trimpath`，并检查目标可执行文件格式/架构，在与构建机相同的平台执行版本和离线命令发现检查；交叉编译不等于在六种操作系统/架构上均已运行验证。macOS 产物暂不签名或公证，Windows 暂无代码签名。
