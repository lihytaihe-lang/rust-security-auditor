# Codex 安全修复方案的独立审查记录

- 日期：2026-08-11
- 审查对象：`improve/public-readiness` 分支上**未提交**的工作区改动（Codex 依据 `PUBLIC_READINESS_SECURITY_REMEDIATION_PLAN_ZH_2026-08-11.md` 实施的 F1–F7 修复）
- 基线：`c8f79ad`（本分支最后一个提交）
- 审查者：Claude（本轮改动的前一作者，非中立方，见文末「利益相关声明」）
- 改动规模：43 个文件，约 +1707 / −2221 行；新增 `src/release/`、`scripts/verify-public-package.mjs`；删除全部 hosted MCP 代码

结论：**整体质量高，F1/F4/F5/F6 是真实问题且修得正确，其中 F5 是前一轮（我）引入的 bug。但有 2 处必须修复后才可提交，1 处需要 owner 拍板。**

---

## 1. 已执行的验证

| 项目 | 命令 | 结果 |
| --- | --- | --- |
| 类型检查 | `npm run typecheck` | 通过 |
| 测试 | `npm test` | 99/99 通过，18 suites |
| 依赖审计 | `npm audit --audit-level=high` | 0 vulnerabilities |
| 包边界与安装 | `npm run verify:package` | 通过（tarball 边界 / 全新安装 / .bin 启动 / stdio 握手） |
| 误报回归 | 对 `fp-probe` 夹具复跑 `rust_audit_project` | 精度无回退，13 条发现与修复前一致 |

上述均在 macOS 26.5.2 / Node 25.9.0 下执行。

---

## 2. 必须修复（阻塞提交）

### R1：README 的主安装路径不可达（用户可见的功能缺陷）

**现象**：`npx` 被全部移除，五个客户端配置块统一指向
`/absolute/path/to/node_modules/.bin/rust-security-auditor`，但全文没有任何一步会产生该路径：

- 无 `npx`
- 无 `npm install rust-security-auditor`
- 无 `npm install -g`
- 唯一的获取方式「From a local checkout」是 `npm ci`

**验证**：在本仓库执行 `npm ci` 后，`node_modules/.bin/` 下不存在 `rust-security-auditor`
（npm 不会把根包自身的 `bin` 链入自身的 `node_modules/.bin`）。

**附带矛盾**：「From a local checkout」一节又指示使用 `npm --silent run mcp`，与上方五个配置块给出的命令不一致，读者无法判断该用哪个。

**建议**：恢复 `npx -y rust-security-auditor@latest` 作为主路径（可标注「发布后可用」），
或至少补充 `npm install -g rust-security-auditor`，并让配置块与获取方式一一对应。

---

### R2：覆盖不完整会把 `block` 降级为 `needs_attention`（与 fail-closed 意图相反）

**位置**：`src/mcp/reviewDecision.ts`，`incompleteCoverage` 分支排在 `blockingFindingIds` 分支**之前**。

**复现**：构造一个 git 仓库，同一 diff 中同时包含

1. 新增 `pub static mut COUNTER: u64 = 0;`（`RSA-UNSAFE-STATIC-MUT`，high，introduced_by_diff）
2. 一个被跟踪且被修改的 `src/generated.rs`，大小 2,520,015 字节（超过 2 MiB 上限）

执行 `rust_review_current_diff` 得到：

```json
{
  "status": "needs_attention",
  "reason": "Required current-diff inputs were not fully scanned: src/generated.rs (file_too_large).",
  "blockingFindingIds": ["RSA-UNSAFE-STATIC-MUT-49F4B9D5"],
  "safeToCommit": false
}
```

**影响**：`safeToCommit: false` 与 `blockingFindingIds` 均保留，信息未丢失；
但**扫描越不完整、结论反而越轻**。按 `status === "block"` 判断的 agent 或 CI 会被误导。

**建议**：将 `incompleteCoverage` 分支移到 blocking 判断之后，或在 block 分支的 `reason` 中合并覆盖信息。改动量约一行。

---

## 3. 建议修复（非阻塞）

### R3：扫描性能退化约 5.5 倍

合成项目：800 个 Rust 文件，5 层目录深度，每文件 24 个发现点。纯扫描耗时（已排除 build）：

| 版本 | 三次测量 |
| --- | --- |
| 基线 `c8f79ad` | 0.54s / 0.55s / 0.60s |
| Codex 工作区 | 3.05s / 3.07s / 2.93s |

**成因**（`src/scanners/scannerUtils.ts` 的 `SafeSourceReader`）：

- `resolveRootPath()` 每读一个文件都重做 2×`lstat` + 1×`realpath`
- `inspectPath()` 每文件调用 3 次（open 前、open 后、read 后）
- `hasSymbolicLinkComponent()` 逐路径组件 `lstat`

一个 5 层深的文件仅 `lstat` 就 20 次以上。

**评估**：真正阻断符号链接逃逸的是「发现阶段跳过符号链接 + `O_NOFOLLOW` + dev/ino 复核」，
这三者都是廉价操作；逐组件复查与发现阶段高度重叠。

**建议**：root realpath 只解析一次并缓存；逐组件符号链接检查在发现阶段做一次而非每次读都做。
预期可收回大部分开销，安全性基本不损失。真实大型 workspace（数千文件）当前可能需要十几秒，
会影响「每次 commit 前跑」的可用性。

### R4：对外文档混入了内部审计口吻

- `CHANGELOG.md` 标题：`## [0.1.2] - 2026-08-11 (publication status: owner verification required)`，
  正文「do not treat this entry as a publication claim」
- `README.md` 兼容性表：各客户端标注「Configuration reference from official docs only」，
  Claude Desktop 标「Unverified」，并声明「not a support certification」

**评估**：「不声称未验证的事」这一原则本身正确且应当保留。问题是**位置和口径**——
这是内部核查笔记的语气，出现在 README/CHANGELOG 会读作心虚而非严谨。
MCP 是协议，提供各家配置格式属正常文档，不需要免责声明。

**另一处**：`0.1.1` 的 changelog 条目被回改为「Historical hosted experiment; it is deliberately absent…」。
已发布版本的历史条目不应回改——0.1.1 当时确实包含 hosted 代码。现状说明应写在 0.1.2 条目内。

### R5：隐私测试中硬编码维护者本机路径

`test/artifactPrivacy.test.ts` 多处写入 `/Volumes/GF/kaiyuan/rust-security-auditor`。
功能上无误（仅作函数入参），但这是**专门检测路径泄漏的测试**，将本机目录结构提交进公开仓库有自相矛盾之嫌。
该文件不在 npm tarball 的 `files` 内，但在公开 GitHub 仓库中可见。
建议改用 `/home/example/workspace/project` 之类的合成路径。

### R6：旗舰示例未重新生成

`examples/reports/rust_review_current_diff.json` 不在本次改动中，而工具现已新增 `scanCoverage` 字段，
该示例与实际输出已不一致。它正是 README 开头展示的工具。
`scripts/regenerate-examples.mjs` 也未覆盖它（需要临时 git 仓库支持）。

---

## 4. 需要 owner 拍板的范围决定

**hosted MCP 原型被整体删除**：`src/mcp/hostedServer.ts`、`hostedTools.ts`、`hostedFixtures.ts`、
`scripts/smoke_hosted_mcp.ts`、`test/hostedMcp.test.ts`，约 1500 行；`ROADMAP.md` 的 Stage 2 章节
相应改写为边界声明。

**评估**：改动自洽，已核查无悬空引用；收窄发布面确实降低风险。
但这是**产品决定而非缺陷修复**：此前 Stage 2.4 的状态是「阻塞于 ChatGPT Developer Mode 入口不可见」，
而非「放弃」。代码可从 git 历史恢复，但当前分支不再包含。

需 owner 明确确认是否接受。

---

## 5. 认可并建议保留的部分

### 5.1 F5 多行字符串 —— 前一轮引入的真实 bug

前一轮实现在每行末尾重置字符串状态，注释为「普通字符串不跨行」。**该前提错误**：
Rust 的普通字符串字面量可以包含字面换行。原实现会把跨行字符串的后续内容当作代码扫描。

Codex 移除了该重置，并在 EOF 未闭合时回退为「不掩码字面量」的保守策略
（`withoutLiterals: [...withoutComments]`），方向正确——宁可多报不可漏报。

### 5.2 F1 伪造 SAFETY 注释

新增 `commentsOnly` 视图后，`findNearbySafetyComment` 只消费词法确认的注释。
此前 `let s = "SAFETY: ok";` 可将 unsafe block 的 confidence 由 high 降为 medium，属真实的语义伪造面。

### 5.3 F6 `cfg(test)` 作为证明义务

`any(test, feature=...)`、`cfg_attr`、否定形式均不再触发降级，因为它们可能编入生产构建。逻辑严密。

**已实测的代价**：

| 写法 | 严重度 |
| --- | --- |
| 裸 `#[tokio::test]` | medium（生产级） |
| `#[cfg(test)] mod` 内的 `#[tokio::test]` | low |
| 裸 `#[test]` | low |

即 `tests/` 目录下的异步集成测试会按生产严重度上报。影响有限但真实。

**补充建议**：Cargo 约定 `tests/` 与 `benches/` 不参与发布，将这两个目录直接视为测试代码是廉价且准确的补充。

### 5.4 F4 `toolScopes` 取代规则 ID 前缀匹配

此项修正了前一轮遗留的弱点：前一轮为容纳 `RSA-CARGO-` 规则而放宽了测试断言的前缀白名单，
Codex 改为显式作用域声明，是正确做法。

### 5.5 `scripts/verify-public-package.mjs` —— 本轮最有价值的新增

打包 → 解 tar → 断言无 hosted 残留与路径泄漏 → 全新安装 → 驱动真实 binary 完成 stdio 握手 →
断言 stdout 仅含 JSON-RPC 帧。

**前一轮的符号链接入口判断 bug（`c8f79ad^` 修复的那个），如果当时存在此脚本会被自动拦截。**
已实测通过，且已接入 CI。

### 5.6 制品隐私的接入边界正确

`sanitizeArtifactValue` / `findArtifactPathLeaks` 仅接在示例生成与打包校验上，
**未**接入实时工具输出。若接入，用户扫描自有项目时会看到 `<local-path>` 取代真实路径。此边界划分正确。

---

## 6. 建议的提交边界

1. 先修 R1、R2（纯缺陷，改动小），与 Codex 现有改动一并提交
2. R3 性能优化单独一个提交（会调整 `SafeSourceReader` 结构，便于单独 review 与回滚）
3. R4 文档口吻、R5 合成路径、R6 示例重新生成可合为一个文档整理提交
4. hosted 删除待 owner 确认后再决定是否保留在本分支

---

## 7. 利益相关声明

本审查由 `improve/public-readiness` 分支前四个提交的作者执行，非中立第三方。
被 Codex 判定为缺陷的 F5（多行字符串）、F4（前缀匹配）确实源于前一轮实现，本记录已如实标注。
性能对比中的「基线」即本人提交的版本，读者应据此判断 R3 的立场偏差风险；
测量方法与数据已在上文列出，可独立复现。
