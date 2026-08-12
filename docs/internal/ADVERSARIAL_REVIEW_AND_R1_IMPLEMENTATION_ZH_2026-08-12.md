# Rust Security Auditor：对抗复核与 R1 实施记录

- 日期：2026-08-12
- 仓库：`/Volumes/GF/kaiyuan/rust-security-auditor`
- 审查基线：`9ad37e7`（工作开始时干净）
- 范围：C1 Git 路径身份、R2 review decision 优先级、suppression 性能缓存、R1 本地 checkout 安装路径
- 外部动作：无推送、无 tag、无 npm publish、无真实 Codex/Claude 配置写入

## 结论

1. Claude 对 C1 的 POSIX 主策略成立：Git 解码后的字面反斜杠是文件名的一部分，不能改写成 `/`。保留它能正确扫描 `src\\alias.rs`，而不是误扫 `src/alias.rs`。
2. 但 Windows 保护原先只拒绝反斜杠，不足以覆盖会被 Windows 重解释的 `:`、保留设备名与末尾点/空格。本轮已扩展为拒绝所有这些 component；这类 diff 在 Windows 会在产生任何 review decision 前返回 `UNSUPPORTED_GIT_PATH`。
3. R2 已正确保持 block 优先级。JSON、summary、`safeToCommit` 与 Markdown 都从同一个 `reviewDecision` 推导，没有第二条会降低结论的生产路径。
4. 性能瓶颈不是 canonical root 解析。每次 suppression 处理的 per-file comment/lexing 缓存已消除 findings × lines 的平方项；原计划中的 root cache 已取消。测试观察计数器也已从公开 scanner barrel 收窄为测试直接导入。
5. R1 已以本地 checkout 为唯一主路径：`npm ci`、`npm run build`，客户端运行 `node /absolute/path/to/rust-security-auditor/dist/src/mcp/server.js`。npm/npx 保留为未来发布后可选路径；`verify:package` 明确定位为该发布路径的本地回归保护，而非主安装指引。

## C1：独立复现与路径边界

### POSIX 字面反斜杠

临时 Git 仓库同时创建 `src/alias.rs` 与字面文件 `src\\alias.rs`，只向后者加入 `pub static mut EVIL: u64 = 0;`。

- 当前实现：`status: block`、`safeToCommit: false`、changed file 为 `src\\alias.rs`，finding 为 `RSA-UNSAFE-STATIC-MUT @ src\\alias.rs`。
- `9ad37e7` 的父版本：同一用例返回 `pass`、`safeToCommit: true`、changed file 被误报为 `src/alias.rs`、findings 为空。

这证明“停止反斜杠改写”是正确且必要的修复，不应改成 POSIX 一律拒绝。

### `posix.normalize`、Unicode 与大小写

MCP 的输入来自本地 `git diff`，不接收任意外部 patch 文本。用 Git index 的 `--cacheinfo` 分别尝试 `src//alias.rs`、`src/./alias.rs`、`src/../alias.rs`，均被 Git 拒绝；它们不会成为本工具真实 Git 输出中的可区分路径。

代码也不对 Unicode 或大小写做归一化，所有 diff/path/coverage 键按精确字符串匹配。在大小写或 Unicode 归一化的文件系统上，若 Git 路径与 discovery 返回的当前文件名不完全一致，`scanRustProjectFiles` 不会把它当作同一文件，`markDiffCoverage` 会记录 `missing_current_input`；current-diff 结论因覆盖不完整变为 `needs_attention`，不会得到 false `pass`。

### Windows

`isPlatformAddressableGitPath(path, "win32")` 现在按 component 拒绝：反斜杠、`< > : " | ? *`、控制字符、末尾点/空格、`CON`/`PRN`/`AUX`/`NUL`、`COM1`–`COM9` 和 `LPT1`–`LPT9`（含对应上标数字及扩展名）。这些名称可能分别映射为目录分隔符、alternate data stream、去尾的同名文件或设备，而不是 Git 的精确对象；不能把“可能能读到”当作安全。

`requireAddressableDiffPaths()` 位于 `readGitDiff()` 后、`currentScannableDiffFiles()`、Rust 文件扫描、coverage 标记、finding enrich、`inferReviewDecision()` 和报告构造前。`ProjectScanner` 的只读 discovery 已发生，但没有规则扫描或 decision；错误由 `runTool()` 返回为 MCP input error，输出不含 `reviewDecision`。

## R2：结论一致性

真实临时 diff 同时含：

- added `static mut`（high/high confidence blocker）；
- 一个已跟踪、已修改且超过 2 MiB 的 `.rs`（`file_too_large`）。

JSON 返回 `block`、`safeToCommit: false`，reason 同时包含 blocker 与 `not fully scanned: src/oversize.rs (file_too_large)`；`diffReview.conclusion` 为 `Block before commit`、summary `blockingCount` 为 1。以 Markdown 输出重复运行，`BLOCK` 和 `not fully scanned` 均存在。

生产点审计结果：

- `safeToCommit: true` 只在 `inferReviewDecision()` 的最终 `pass` 分支创建；有 blocker、人工复核或 incomplete coverage 的每条分支均为 `false`。
- `conclusionFromReviewDecision()` 是 status 的穷尽映射；没有独立优先级。
- `summarizeDiffReviewMetrics()` 仅从同一 decision 的 id 集合计数；不改变 status。
- Markdown 直接渲染同一 `reviewDecision` 的 label、safe flag、reason 和数量。

回归可信度：在隔离 worktree 故意把 incomplete coverage 分支放在 blocker 前，已有测试 `keeps a hard block when a required diff input was not fully scanned` 失败，实际值为 `needs_attention`、期望为 `block`。

## 性能缓存与公开 API

`applySuppressions()` 内部创建 `Map<string, Promise<readonly string[] | undefined>>`。其生命周期只覆盖一次 `finalizeScannerResult()`：不跨工具调用，也不缓存结果到模块全局。Promise 缓存同时去重同文件的读取和 `maskRustSource()`。

三个 scanner 并行调用 `finalizeScannerResult()` 时各有自己的 map，这是正确的结果隔离；它们共享当前工具调用的 `SafeSourceReader`，所以仍共享受限读取与 coverage。代价只是不同行 scanner 都在同一文件有 finding 时各做一次 lexing，结果没有不一致或泄漏风险。没有 profile 证据支持牺牲这种隔离以换取更大共享。

`maskRustSourceInvocations()` 现在只由测试从 `rustLexer.js` 深导入。公开 `./scanners` barrel 不再导出它，避免把模块级可变计数器暴露给生产调用方；生产代码不读取该计数器。

## R1：本地 checkout 安装路径

README 的通用、Claude Code、Codex、Cursor、VS Code 五个配置块和两个机器可读示例均已改为：

```text
node /absolute/path/to/rust-security-auditor/dist/src/mcp/server.js
```

主流程为：

```text
git clone …
cd rust-security-auditor
npm ci
npm run build
```

直接以该 node 命令启动后，实际完成 `initialize`、`notifications/initialized`、`tools/list`（5 个工具）、`rust_audit_project`，且 stdout 全为 JSON-RPC 帧。当前环境的 `codex mcp add --help` 和 `claude mcp add --help` 均确认了文档中的 stdio 命令形状；这仍只是配置参考，未声称真实客户端 UI 已验收。

`npm run verify:package` 保留：它制作本地 tarball、fresh install、通过 `node_modules/.bin` 运行并做 MCP 握手。这是未来 npm 发布路径的回归保护，不意味着源码 checkout 自身存在根包 `.bin` 或 npm 已发布。

新增 `test/localCheckoutDocs.test.ts` 把 README 和两个示例中的主入口绑定到上述 built checkout 路径；修改前该测试因 README 只有 `npm ci && npm test` 且配置指向根包 `.bin` 而失败。

## 可选推广项：扫描范围与真实项目叙事

复现 `BurntSushi/memchr` 当前 tip：默认 `rust_audit_project` 报 1721 条、`high_risk`，其中 1346 条来自 `benchmarks/`，仅 `benchmarks/haystacks/code/rust-library.rs` 就有 1311 条。这确实会损害首次印象。

本轮未把它改成简单的目录黑名单：Cargo 的 `tests`、`benches`、`examples` 和非 workspace member 的精确定义依赖 manifest、显式 target、workspace member glob/default-members 与发布策略。无条件跳过任意同名目录会静默降低安全扫描覆盖，并可能让 current-diff 的 coverage 语义变得不诚实。建议另立一个 scope 设计批次：先定义 `rust_audit_project` 的默认产品范围、`--include-development-targets` 选择项、manifest target 解析与可见 coverage/exclusion 报告，再添加 fixture 和真实项目对照。

`tokio-rs/bytes` 当前 tip `d5c8ad3` 的独立复现也与原描述不同：未修改时本工具返回 0 findings；在 `src/lib.rs` 加入四行 `static mut`/unsafe probe 后返回 2 条 introduced、0 条同 unsafe-site context、0 条 hidden pre-existing。因没有复现“246/76/1+1”数据，本轮没有把该数字写入 README；避免把不可重复的营销案例当作事实。

## 验证记录

修复前的明确失败：

- C1 父版本的 POSIX alias PoC 返回 false `pass`。
- 新增 Windows path、公开计数器、R1 文档三项回归断言先运行均失败。
- R2 在隔离 worktree 还原错误优先级后，目标测试失败并显示 `needs_attention`。

修复后的检查（最终全量门仍以本轮末尾执行记录为准）：

```text
npm run typecheck
npm test
git diff --check
npm run verify:package
```

## 未完成门

- 没有实际修改或验证 ChatGPT/Codex app 与 Claude client 的用户配置；README 正确保留“configuration reference only”。
- 扫描范围优化需要单独的产品/安全范围决定，尚未实现。
- 推送、tag、npm 发布和公开 release 仍由 owner 单独决定。
