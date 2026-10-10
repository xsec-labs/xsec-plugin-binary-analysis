# 二进制分析公共 UI

工作台使用 `@xsec/ui-react` 0.1.7、`@xsec/design-tokens` 0.1.2 与 React 18.3.1。公共组件覆盖页面标题、按钮、输入、选择、Tabs、Drawer、状态、空态和错误反馈；Host 外观设置同步明暗、密度、字号和减少动效。

## 行为与所有权

`frontend-src/controller.ts` 是工作台业务状态的唯一所有者。组件保留输入中的表单值，项目或会话绑定变化时清空。跨上下文回执由 epoch 拒绝；详情关闭与分析结果切换分别增加版本，防止已关闭的 Drawer 或旧列表被迟到结果恢复。释放时清除任务观察计时器及上下文、主题订阅。

样本导入通过真实 Host 文件选择器、审批和不可变样本存储。默认完整分析，快速分析需要显式选择。分析状态每 1.2 秒观察一次，观察窗口 15 分钟；请求失败立即停止观察，用户可显式读取。函数、字符串和导入保留 50 条分页与覆盖信息。详情通过公共 Drawer 呈现，Escape 关闭并恢复触发控件焦点。

22 项 RPC 使用 manifest 的固定映射。注释、证据、补丁和签名参数通过 JSON 输入及 MCP schema 校验。调试控制保留停止态版本校验；写入完成后读取真实快照。样本、调试进程、审批、签名及审计由 Host 所有；分析任务、不可变结果和注释由 Sidecar 所有。

分析服务由 manifest 的 stdio MCP 注册交给 Fabric 管理，保持一个进程与数据目录所有者。官方插件目录登记明确安装入口；每个项目会话经真实 capability binding 取得分析服务。

用户操作记录稳定事件、operation_id 和生命周期，参数与样本内容不进入前端业务日志。错误显示原始边界的安全说明和可复制操作编号。

## 构建与依赖

TypeScript 和 CSS 源码位于 `frontend-src/`，生成入口为 `com.xsec.desktop/frontend/index.js`。`scripts/build.mjs` 打包生产 React、公共组件与主题，生成第三方声明和 CycloneDX SBOM；`scripts/check-generated.mjs` 校验生成一致性。vendor 的两个公共包及锁文件固定版本与摘要。开发时复用现有依赖和统一构建缓存。

通过 Desktop 资源控制器记录 status、changed plan 后执行相关命令：

```sh
rtk npm run typecheck
rtk npm run build
rtk npm run check:generated
rtk npm run verify:frontend
rtk python3 -B -m unittest discover -s tests -v
```

## 当前验证

类型、生成一致性、入口语法、22 项 RPC / 18 个公共组件及许可 / SBOM / 锁文件检查、10 项真实文件契约已通过。macOS arm64 引擎使用固定 radare2 6.2.2 与 r2ghidra 源码及许可证清单，原生包大小为 94,336,784 bytes，包含 1,135 个文件，通过 Host 包校验。前端 SHA-256 为 `197a05b8f944fb89478148c7c5cb480d27591dd5955c7751d1afe52c0ae369b7`，SBOM 有 18 项依赖组件；候选与生成入口已回读一致。

真实 macOS arm64 隔离 Host 已完成插件检查、声明权限附加、两个隔离 ACP 会话、系统 Open 选择器导入和真实 SQLite / MCP 分析。配对 loopback Chromium 通过 18 项读取与生命周期、7 项完整分析 / 反编译 / 注释 / 证据 / 补丁 / 签名流程、重复完整分析及 50→100→140 条分页。最新 Host 通过 4 项真实附加 / 分离与目标自主退出检查，以及 11 项调试流程。原生页面截图已目视检查。Host 通过 626 项 Desktop 测试，2 项既有 ignored 保留；签名迁移与受影响消费者此前通过 2,925 项测试，4 项既有 ignored 保留。

证据目录：`/Users/xiaosong/.codex/visualizations/2026/10/02/01a0faad-6517-7cd3-90b5-b818bc64660d/plugin-binary-analysis-ui`。关键回执为 `frontend-v4-checks-report.json`、`persistence-checks-v2-report.json`、`browser-read-v7-report.json`、`browser-advanced-v4-readback-report.json`、`browser-full-pagination-v1-report.json`、`native-import-v12-report.json`、`browser-attach-v3-report.json`、`browser-debug-v4-report.json` 和 `final-host-checks-v2-report.json`。本地集成、主仓摘要及任务资源清理由 `local-integration-final.json` 维护。

## 性能决定

同一 Host、Sidecar、样本和真实分析的 ABBA 测量，首个 block 预热后保留 12 个样本。就绪中位数 81.20→114.75 ms，100 行分页 93.35→98.05 ms，详情打开 102.80→126.20 ms，滚动 36.10→37.20 ms。Host 页面与 iframe 分别在独立 CDP target 上 GC 后相加；100 行总堆 13,046,890→17,547,260 bytes，详情总堆 13,095,602→18,033,376 bytes。关闭 iframe 后父页面堆增量 328,488 bytes，有限样本继续保留长会话验证边界。

前端 gzip 5,675→115,737 bytes。生产 minify / tree shaking 的原始输出归因中，React DOM 为 130,748 bytes，Base UI 为 119,291 bytes；原始字节归因不能转换为各依赖的 gzip 贡献。Base UI 负责 Select / Tabs / Drawer、焦点和关闭语义，Floating UI 负责定位；ControlThemeProvider 使用 Host 外观，Motion 未进入本批输出。单模块沙箱、50 条分页和公共控件契约沿用当前实现。

超过 10% 的指标已完成调查，技术状态为 `INVESTIGATE`。按用户授予的自主实现与本地集成授权，接受本批实测绝对成本，决定为 `ACCEPTED_WITH_MEASUREMENT_LIMITS`。性能只覆盖本机生产 Chromium，包含定位器观察与两帧；JavaScript 堆不能代表 OS RSS。详见 `performance-real-v3-report.json`、`performance-real-v3-summary.json`、`bundle-size-analysis-v1-report.json` 和 `performance-decision-v1.json`。

## 回滚与边界

回滚本批前端源码、锁文件、vendor 与生成入口。22 项 RPC 沿用基线。代码回滚保留已导入样本、分析缓存、审计、证据及补丁导出记录。Windows、Linux、macOS Intel、发布签名和部署需各自验收。

### 分析结果迁移

真实 Host 重复快速分析同一样本时，稳定的分析版本触发 `snapshots.revision_id` 全局主键冲突；结果保存失败未进入任务失败处理，任务持续显示运行中。

Sidecar 启动在事务中把旧结果表迁移为 `(assignment_id, revision_id)` 复合主键，保留每条结果的 JSON、样本归属与创建时间。相同任务的重复分析逐字段比较已有不可变结果，一致时复用；不同任务各自保存。结果与任务完成状态在同一事务中提交，未授权或保存失败时回滚。分析或保存错误均进入失败终态；失败状态也无法持久化时同时报告原始错误和状态保存错误。已完成的任务保持终态。

迁移前应停止 Sidecar 并备份 `PLUGIN_DATA/binary-analysis.sqlite`。迁移失败时事务保留旧表；旧代码可按任务读取新表。回到旧版本会重新出现重复分析的限制；需要恢复旧表结构时，必须恢复停机备份，并单独保留迁移后新增的数据。不能把多个任务的同版本结果直接压成全局唯一记录。

真实 SQLite 与当前原生测试可执行文件覆盖重复分析、任务隔离、授权失败回滚、结果冲突、数据库写入失败、双重错误传播、旧表迁移、迁移失败回滚和终态保护。前端生成的地址及证据/补丁参数按声明省略缺省可选字段。

### 完整分析进程输出

真实完整分析中，radare2 输出的 70,085 字节超过本机 65,536 字节管道容量。旧实现等待进程退出后才读取 stdout，子进程等待写入空间，双方无法继续。`engine_process.rs` 在进程运行时同时读取 stdout 和 stderr；分别限制为 32 MiB 与 256 KiB，并保留 120 秒总超时。超限或超时会终止并回收子进程，等待两个读取线程，保留终止、回收或读取中的错误。

真实子进程回归覆盖双路输出超过管道容量、输出超限终止和超时回收。macOS arm64 验收样本的完整分析已返回 143 个函数、140 个字符串和 2 个导入，并完成 r2ghidra 反编译。

### Host 签名与调试

签名模板迁移 SQL 已存在于 Host 源码，但未登记到迁移序列，新库与升级库缺少保存所需的四个字段。Host 追加登记并在同一事务执行 SQL 与版本更新，保持历史位置。真实 SQLite 验证新库读写、旧配置升级保留、重复打开、冲突回滚及全部迁移文件登记完整性。

调试控制曾在运行态通过 `threads` 查询暂停目标，真实页面返回 `notStopped`；控制请求还留下已处理的 `continued` 事件，使后续观察把暂停后的目标投影回运行态。Host 保存已选中的线程 ID，用其暂停运行目标，并按顺序消费控制请求的 `continued` 和 `stopped` 事件。退出时清除线程选择。真实 LLDB-DAP 回归以目标 stdout 的就绪标记证明程序已进入 main，再继续、暂停、回读寄存器、检查事件队列并终止；原实现的队列断言失败，修复后通过。

附加后运行态快照还曾重复请求 LLDB-DAP 的线程基线，真实回归返回 `notStopped`。停止态才查询线程；运行态明确返回 `threads.available=false` 与空 items，暂停后读取真实线程和寄存器。模块仍通过真实查询返回，查询失败继续传播。修复后 19 项适配器回归通过，完整 Desktop 格式、fail-fast、Clippy 和 626 项 lib 测试通过。真实页面附加后成功回读，分离保留目标存活，目标按自身程序期限正常退出。

原生验证通过临时、仅 Debug 的装配建立隔离项目，最终 Host 入口已恢复已提交装配。快照启动回执的 `spawned` 早于 bridge listener 发布；验收在有界就绪阶段核对实际 listener 与拥有者后继续。隔离快照的官方默认插件初始化返回 `expected 8 plugins, got 0`，正式 marketplace 安装流程仍需其环境验证。浏览器的 Sentry 请求尝试被验收路由阻止；Cloud 认证和同步未在本批验收。
