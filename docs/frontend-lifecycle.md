# 二进制分析插件前端生命周期

本次修改以 `6fb5ee8de16761768f9ad06705e198f5bae88d78` 为基线。原 controller 缺少
`update`，`mount` 吞掉首次样本读取错误；view 释放后，异步结果仍可修改 DOM，旧控件
仍可发请求。动态 Host 方法调用也无法通过 Factory 前端源码门禁。

`activate` 现在返回 `mount/update/dispose`。每个 view 独占监听器的 `AbortController`
和轮询计时器；更新先释放旧 view，再读取当前 context 的样本。`perform` 在调用前后
核对 view 是否已释放，过期失败保留 `cause` 并按取消处理，活跃 view 的失败继续传播。

前端改为 22 个显式字面量 `host.request` 方法，沿用 manifest 权限与参数契约；分页
输入校验覆盖 `items/nextCursor/truncated/coverage`。运行时依赖、插件引擎/MCP 的 Rust
实现与持久化格式保持不变。测试增加 Python 标准库 HTTP 服务及 Rust helper，后者
依赖 Desktop 已有的 `xsec-storage/anyhow/serde_json`，复用锁文件与离线共享缓存。

## 验证与边界

证据目录：`/Volumes/xsec-build/evidence/2026-10-20-binary-frontend-lifecycle`。

`browser-results.json` 记录六场景基线全部失败、修复全部通过：context 更新、读取
挂起时 dispose、读取挂起时 update、Repository 首次读取失败、dispose 后旧控件操作、
update 后旧读取失败。测试使用真实浏览器、loopback HTTP 和 Desktop Repository，
覆盖 SQLite 迁移及项目、样本写入读取。运行方法见
[浏览器检查说明](../tests/browser_lifecycle/README.md)。

| 检查入口 | 结果 |
| --- | --- |
| `rtk python3 -m unittest discover -s tests -p test_frontend_contract.py -v` | 1 项通过 |
| 证据目录 `check-browser.py` | 精确 hash、6+6 场景结果及真实浏览器回执通过 |
| 证据目录 `check-frontend.py` | Node ESM 语法及 Factory 完整前端门禁通过 |

外置 `validate.mjs` 经共享构建控制器执行，最终 run
`ee7f121c-017e-4af3-aa0a-226997be1b65` 通过，`sourceChanged=false`。
实际命令、argv、输入 hash 与资源采样分别记录在 `validation-plan.json`、
`validation-report.json`、`browser-tested-inputs.json` 和对应资源回执中。

| 执行项 | 耗时 | 峰值 RSS | 磁盘增量 |
| --- | --- | --- | --- |
| storage helper | 8.893 秒 | 666894336 B | 49078272 B |
| browser | 28.363 秒 | 79233024 B，未含浏览器进程 | 1445888 B |
| source check | 6.007 秒 | 采样未捕获 | 32768 B |

各次 swap 均未增加，最终为 2289565696 B。缓存位于
`/Volumes/xsec-build/.worktree-cache/build-resources/targets`。测试服务器已退出，
构建租约已释放；证据数据库保留在外接盘。

本次证据尚未覆盖 Desktop 授权、MCP、Native 引擎，以及分析任务轮询、结果分页、
调试、补丁导出、签名、Native 日志和跨平台验收；同一 view 内并发操作顺序也仍需
实际业务验收。Factory pin 仍指向基线，尚未发布。

回滚使用 `rtk git revert <本次提交>`；本次不涉及数据迁移，测试数据库仅位于证据目录。
