# Rust Security Auditor：Claude + Codex 合并后修复方案

- 日期：2026-08-11
- 工作区：`<repo>`
- 基线：`c8f79ad56e5153f8e76365d1a1651f26a672426b` 上的现有未提交改动
- 输入：Claude 独立审查 `CODEX_REMEDIATION_REVIEW_ZH_2026-08-11.md`（R1–R6），以及本轮已封存的 Codex 安全复核（2 项发现）
- 当前发布门：`HOLD`
- 本文性质：实施与验收方案；不授权提交、推送、发布、修改 ChatGPT/Codex 或 Claude 的真实用户配置。

## 1. 已锁定的产品边界

本项目的 v0.1.x 交付物是开源、本地运行的 stdio MCP server：用户下载源码，在本机构建，然后接入 **ChatGPT/Codex 客户端** 和 **Claude 客户端**。不做 ChatGPT App、远程/hosted MCP、HTTP 服务、SaaS、代码上传或账号体系。

因此：

- 已删除的 hosted MCP 保持删除，不恢复；这是已确认的产品决定，不再作为待决事项。
- 不把 `npx`、全局安装或 npm 发布当作主使用路径；它们未来可以是可选分发方式，但不能解决本地源码用户的主流程。
- 主文档必须以可从 clone 后实际启动的本地命令为准；已发布包的 `.bin` 路径只能在确有“安装该包”步骤的文档中出现。

## 2. 合并后的优先级和完成定义

| 优先级 | 编号 | 问题 | 完成定义 |
| --- | --- | --- | --- |
| P0 | C1 | 字面反斜杠 Git 文件名可别名到无害同名文件，得到 false `PASS` / `safeToCommit: true` | 任何含歧义 Git 路径的 current-diff 审查必须明确拒绝或 fail closed；绝不能返回 `pass`。 |
| P0 | R1 | clone + `npm ci` 后 README 指向的根包 `.bin` 不存在 | 文档和机器可读示例均按本地 checkout 真正可启动的入口配置；从干净 clone 完成 stdio 握手。 |
| P1 | R2 / C2 | incomplete coverage 的分支优先于 hard block | 同时存在 blocker 与 incomplete coverage 时状态必须为 `block`，并同时保留覆盖原因。 |
| P2 | R5 | 路径泄漏测试硬编码维护者本机目录 | 所有公开测试改用合成路径，测试语义不变。 |
| P2 | R6 | `rust_review_current_diff` 旗舰示例缺失且生成器未覆盖 | 生成器可确定性产出该示例，字段与真实输出同步。 |
| P2 | R4 | README/CHANGELOG 混入内部审核口吻，并回写历史发布事实 | 保留事实边界，但改为用户文档语言；不改写已发布版本历史。 |
| P3 | R3 | 安全读取器使合成扫描约慢 5.5 倍 | 以 profile 为准处理真实热点；不得假定 canonical root 解析是主瓶颈。 |

除 C1、R1、R2 外，不允许把发布门从 `HOLD` 改为可提交复核。

## 3. 实施批次 A：修复 current-diff 的安全决策

### A1. C1：保持 Git 路径身份，拒绝歧义路径

**根因**：`src/git/diffParser.ts` 与 `src/mcp/tools.ts` 把字面 `\\` 改成 `/`；POSIX 上 `src\\alias.rs` 与 `src/alias.rs` 是两个不同文件，但覆盖记录被合并。

**设计**：

1. Git diff 解析保留已解码的 POSIX 相对路径身份，不把字面反斜杠转成目录分隔符。
2. 为 current-diff 解析结果增加可表达的“不支持/歧义路径”状态，不能仅静默丢弃该 diff 文件。
3. 在调用扫描器前，遇到无法安全映射到当前平台文件系统的 Rust/Cargo 输入时，**固定返回**明确的 `UNSUPPORTED_GIT_PATH` 类 MCP input error；不创建 review decision，因而不可能输出 `pass` 或 `safeToCommit: true`。这是比“带 incomplete coverage 继续产出部分结果”更清楚且跨平台一致的主策略。
4. `currentScannableDiffFiles`、`markDiffCoverage`、Rust context 读取和 finding 路径比较必须共享同一条“保留身份或 fail closed”的路径规则，禁止各自二次 normalize。
5. Windows 上同样不得把从 Git 获得的字面反斜杠路径悄悄解释为普通目录路径；若该名称不能无歧义表示，则拒绝本次 diff 审查。

**回归测试**：

- POSIX 临时 Git 仓库同时包含 `src/alias.rs` 和字面 `src\\alias.rs`，只改后者为 `static mut` 或其它 high finding；结果必须为明确错误或 `needs_attention`/`block`，绝不能 `pass`。
- 覆盖 JSON、Markdown、`safeToCommit` 和 `scanCoverage`，证明无害 sibling 不会被标为 changed input。
- 普通 Unix 路径、改名、删除、staged/unstaged diff 保持现有行为。
- Windows 专用测试验证不把异常 Git 路径转换成可扫描的普通路径。

### A2. R2/C2：hard block 的状态优先级

**设计**：先计算 `blockingFindingIds`；若非空，始终返回 `status: "block"` 与 `safeToCommit: false`。若还有 incomplete coverage，将文件/原因合并进 block 的 `reason` 或单独字段，而不是降低状态。

**回归测试**：在同一 diff 中放入 high/high-confidence finding 与超限/不可读的必要输入，断言：

- `status === "block"`；
- `safeToCommit === false`；
- blocker ID 保留；
- coverage 不完整的具体原因仍输出；
- JSON、Markdown 和 summary 三者一致。

## 4. 实施批次 B：让本地源码用户真实接入客户端

### B1. 唯一主启动路径

主流程固定为：

```bash
git clone <repository-url>
cd rust-security-auditor
npm ci
npm run build
```

随后 MCP server 的主进程入口为：

```text
node /absolute/path/to/rust-security-auditor/dist/src/mcp/server.js
```

它避免 `npm` 生命周期输出污染 JSON-RPC stdout，也不依赖根包自身不存在的 `.bin` shim。`npm --silent run mcp` 可保留为开发便利命令，但不作为客户端配置的主推荐。

### B2. 文档和示例改造

- README 的“通用 stdio 模型”、ChatGPT/Codex、Claude 配置块和 `examples/mcp-client-config.json` / `examples/codex-plugin-config.json` 全部使用上述 `node + 绝对 dist 路径` 主路径。
- 配置中不把 Rust 项目路径伪装成 server 的工作目录要求；用户在调用 MCP tool 时传入实际 `projectPath`。
- 已发布 npm 包场景若未来要保留，单设“可选安装方式”小节，并同时给出会创建 `.bin` 的明确安装命令；不得与源码路径混用。
- 文案只承诺“本地 stdio MCP”；ChatGPT/Codex 与 Claude 的具体配置格式以验收时对应客户端版本为准，不再扩展到未实际验证的宿主。

### B3. 客户端验收门

先在隔离/可撤销的配置副本上验证，未经所有者确认不改真实日常配置：

1. 从干净源码 checkout 运行 build 后，用 `node dist/.../server.js` 完成 `initialize`、`tools/list`、`rust_audit_project` 与 `rust_review_current_diff` 的 stdio 握手。
2. 在 ChatGPT/Codex 客户端按其当日可用的本地 MCP 配置接入同一 checkout，实际看到五个工具并调用一个 fixture；记录客户端版本、系统、日期和配置形状。
3. 在 Claude 客户端以其当日支持的 stdio MCP 流程做同样验证；若 Claude Desktop 的该版本只允许扩展包或另有格式，文档明确其限制，不伪造“已支持”。
4. 只有两端均有可见工具和真实 `tools/call` 记录，README 才可标为“端到端验证”；否则只写“配置参考”。

## 5. 实施批次 C：发布资料与公开仓库卫生

### C1. R5：测试数据去标识化

将 `test/artifactPrivacy.test.ts` 中所有 `<repo>` 改为合成 repository root，例如 `/home/example/workspace/project`；断言仍应覆盖 POSIX、`/tmp`、`/root`、`/srv`、Windows drive、UNC 和 JSON 转义值。

### C2. R6：确定性 current-diff 示例

- 让 `scripts/regenerate-examples.mjs` 通过临时 Git fixture 生成 `examples/reports/rust_review_current_diff.json`；fixture 必须在脚本完成后清理。
- 样例应包含 `scanCoverage`、review decision、changed-file relation 与无绝对路径输出。
- 添加校验：重新生成后工作树无差异；或在 CI 中将生成结果与受跟踪示例比较。

### C3. R4：对外文案与历史事实

- README 保留“实测 / 配置参考 / 未验证”的证据分级，但采用面向用户的短句，不把内部审计免责声明作为正文。
- `CHANGELOG` 的 0.1.1 条目恢复当时的历史事实；“当前 v0.1.x 不含 hosted runtime”写在 0.1.2 的 changed/security 边界，而非回改历史。
- 不新增任何“已发布”“已上架”“已支持某客户端”的事实声明，除非对应外部事实或端到端证据已由所有者核准。

## 6. 实施批次 D：性能单独优化（R3）

### 2026-08-12 对抗复核更新：取消 canonical-root 缓存方向

该方向不再排期。复核确认实际爆炸项是同一文件的 suppression 查找按 finding 重复执行 `maskRustSource`，而不是 `SafeSourceReader` 的 canonical root 解析：6000 findings 单文件的复杂度曾是 findings × lines。现有修复将 comment-only 词法结果以每次 `applySuppressions` 调用、每个文件独立缓存，消除了该平方项；测试也验证计数器不再作为公开 scanner API 导出。

因此：

1. 不实现仅回收约 4% 的 root-resolution cache，也不放宽逐组件 `lstat`、`O_NOFOLLOW`、打开后身份复核或 coverage fail-closed 语义。
2. 三个 scanner 各自的缓存是有意的调用级隔离；它们共享同一 `SafeSourceReader`，不共享可变的 suppression 结果。
3. 如将来有新的 profile 证据，再单独提出性能变更，并先重跑符号链接、ancestor-swap、超限、并发和 coverage 回归。

若出现新的、有证据的性能热点，该批次必须在 A–C 通过后独立进行。

1. 先保留 Claude 的 800 文件/5 层目录基准并记录环境和三次结果；性能数字只用于比较，不作为安全通过证据。
2. 不缓存可被路径替换影响的被读取文件身份；每次读取仍保留 `O_NOFOLLOW`、打开前/后身份复核及 coverage fail-closed 行为。
3. 调整后重新跑符号链接、ancestor-swap、超限、并发和 coverage 测试；安全回归优先于性能数字。
4. 若优化需放宽逐组件检查，必须先用对抗测试证明发现阶段检查、descriptor check 和后置身份复核共同覆盖该竞态；否则不合入。

## 7. 提交边界和验证门

建议每批可独立回滚，测试与修复同提交：

1. `fix(diff): fail closed on ambiguous Git paths and preserve block priority`（C1、R2 和对抗测试）
2. `docs(mcp): document runnable local checkout configuration`（R1、ChatGPT/Codex 与 Claude 配置示例、checkout 启动验证）
3. `docs(release): regenerate diff example and remove local test paths`（R4、R5、R6）
4. `perf(scanner): cache suppression lexical views per file without changing read checks`（R3，已有实现；后续仅接受新的 profile 驱动改动）

每个实现批次至少执行：

```bash
npm run typecheck
npm test
git diff --check
npm run verify:package
```

批次 1 还必须执行 C1/C2 的专门回归；批次 2 还必须执行干净 checkout 启动和两种目标客户端的人工可见验收；批次 3 还必须执行示例再生成一致性检查；批次 4 必须附带安全回归与性能前后数据。

## 8. 最终放行条件

仅在下列条件全部成立时，状态才从 `HOLD` 变为 `GO_FOR_OWNER_REVIEW`：

- C1、R1、R2 已修复并有对应自动化测试；
- README 与机器可读配置均可由干净源码 checkout 真实启动；
- ChatGPT/Codex 和 Claude 各有一次本地 stdio 工具可见及实际调用证据，或文档诚实降级为未验证参考；
- hosted HTTP runtime 未重新进入 package、bin、export、tarball 或示例；
- R4–R6 完成，R3 若未做则以明确性能债记录，不伪装为已优化；
- 所有验证命令通过，且所有者完成发布事实、版本、tag、npm 和公开操作的最终复核。

`GO_FOR_OWNER_REVIEW` 不是公开发布授权；提交、推送、打 tag、npm 发布和市场提交仍由所有者单独决定。
