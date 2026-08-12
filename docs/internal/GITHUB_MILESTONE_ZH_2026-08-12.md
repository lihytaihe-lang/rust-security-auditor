# GitHub 阶段收尾记录

- 日期：2026-08-12
- 状态：**GitHub 平台的工作已收口**。下一阶段是 npm 发布，再往后是 `cargo audit` 集成。
- 参与：Claude 与 Codex 交替实施与对抗复核，过程记录见本目录其余文档。

---

## 1. 产品定位（本阶段确认）

**这个工具解决的是「你写进 Rust 项目的代码」的安全问题**，不解决「你引入的依赖有没有已公开漏洞」。

起因是 AI 辅助开发写 Rust 的速度超过了人工审查速度：生成的模块为了快用上 `get_unchecked`，生成的 `build.rs` 调外部命令，生成的 `Cargo.toml` 把依赖钉成 `*`——每一行编译器都接受。

安全问题有两个来源，本工具覆盖第一个：

| 来源 | 覆盖 | 说明 |
| --- | --- | --- |
| 自己（或 AI）写的代码引入的风险 | **覆盖** | unsafe / FFI / build.rs / cargo 配置 / 运行时进程执行，25 条规则 |
| 引入的第三方代码带的已知漏洞 | **不覆盖** | 无 RustSec / CVE 查询，明确指向 `cargo audit`、`cargo deny` |

对外表述不使用「覆盖 70%」这类比例说法，而是「一个划清的边界 + 指明补位工具」。前者听起来像半成品，后者是专业判断，且是实话。

### 两种用法并列（曾经写偏过）

README 一度出现「**它审查的是改动，不是代码库**」的表述，与实际能力矛盾——五个工具里三个是全项目的。根因是把「降噪成果」当成了「产品定位」来写。已在 PR #6 修正为：

- **审计整个项目**：接手 crate、评估依赖、发版前
- **审查这次改动**：每次提交前，尤其 agent 刚生成完代码

两者跑同一套规则。全项目审计说明现在站在哪，diff 审查防止往回滑。

---

## 2. 仓库当前状态

| 项 | 值 |
| --- | --- |
| main | `965d25d` |
| Release | [v0.1.2](https://github.com/lihytaihe-lang/rust-security-auditor/releases/tag/v0.1.2)（Latest） |
| CI | Node 20/22/24 × Linux/macOS/Windows + CodeQL + npm audit + 打包校验，全绿 |
| 测试 | 116 个 |
| 待处理 PR | 0 |
| npm | 未发布（名称 `rust-security-auditor` 经查可用） |

**描述**：`Audit Rust projects for unsafe, FFI, and supply-chain risk — a local, read-only MCP server for your coding agent.`

**topics**：`rust` `security` `security-audit` `unsafe-rust` `supply-chain` `static-analysis` `code-review` `mcp` `model-context-protocol` `claude-code` `codex` `cursor` `qoder` `zcode` `kimi-code`

**仓库设置**：Private vulnerability reporting 已开启（`SECURITY.md` 与 issue 模板都指向它），Dependabot 安全更新已开启并已产出并合并过一个 PR。

**文档**：`README.md`（英文，默认）+ `README.zh-CN.md`，顶部互链，结构逐节对齐，测试会在任一份缺失规则 id 或工具名时失败。

---

## 3. 本阶段修复的实质问题

按严重度排列，每一条都有回归测试，且都验证过「没有修复时测试会失败」。

### 3.1 假 PASS（最严重）

Git 的路径分隔符永远是 `/`，unquote 之后残留的反斜杠属于文件名。此前代码把它改写成 `/`，导致两个不同文件映射到同一个 key：仓库里同时存在 `src/alias.rs` 和字面名为 `src\alias.rs` 的文件时，只改后者并加入 `static mut`，工具报告的是前者（无害）的结果——`status: pass`、`safeToCommit: true`、`findings: []`、`coverage: complete`。

修法是**停止改写**而非一律拒绝：POSIX 上 `src\alias.rs` 是合法真实文件，正确行为是扫描它。仅当平台无法无歧义寻址时（Windows 的反斜杠、`:`、保留设备名、末尾点/空格）在产生任何 review decision **之前**抛 `UNSUPPORTED_GIT_PATH`。

### 3.2 安装后的可执行文件什么都不做

入口判断用 `resolve(process.argv[1]) === fileURLToPath(import.meta.url)`，未解析符号链接——而 npm、`npx`、`npm link` 全都通过软链调用 bin。进程启动、比较失败、静默退出。改为两侧都走 `realpath`。

### 3.3 README 的安装路径不可达

五个客户端配置块全部指向 `node_modules/.bin/rust-security-auditor`，而全文没有任何一步产生该路径（实测 `npm ci` 后不存在——npm 不把根包自身的 bin 链入自身）。已改为本地 checkout 主路径：`npm ci && npm run build`，客户端跑 `node <abs>/dist/src/mcp/server.js`。新增测试把文档里的入口绑定到真实路径，防止再次漂移。

### 3.4 覆盖不完整会削弱结论

`incompleteCoverage` 分支排在 blocking 判断之前，导致「有真实阻塞项 + 有读不了的输入」时结论从 `block` 降为 `needs_attention`——扫描越不完整结论反而越轻。已改为覆盖原因追加进 reason，不替换状态。

### 3.5 单文件 O(n²) 停顿

抑制查找在逐 finding 循环里对整个文件重新做词法分析。274 KiB / 6000 findings 的单文件耗时 **69.56 秒**，而这个爆炸项是 findings × lines，**per-file 字节上限挡不住**。按文件记忆化后 **0.19 秒**；800 文件基准 2.97s → 0.86s，产出逐条一致，峰值内存反而下降。

排查过程值得记录：最初（包括 Codex 的批次 D 方案）都认为瓶颈在新增的安全读取器。实测缓存 canonical root 只回收 4%，去掉全部路径检查也只有 8%，CPU profile 里 `lstat` 仅占 2.0%。真因靠计数暴露：`maskRustSource` 调用数 1602 → 40002，而 40002 ≈ 1602 + 38400（finding 总数）。

### 3.6 其它

- 跨行普通字符串曾被错误重置状态（Rust 的普通字符串可以跨行），会把字符串内容当代码扫
- `SAFETY:` 注释可被字符串伪造，进而降低 unsafe block 的置信度
- `#[cfg(any(test, ...))]`、`cfg_attr`、否定形式曾被当作「仅测试」而降级，但它们可能编入生产
- 规则到工具的归属曾依赖 rule id 前缀匹配，已改为显式 `toolScopes`
- hosted MCP 原型已从源码、导出、构建产物和 tarball 中移除
- Windows CI 首次运行即暴露两个缺陷：测试硬编码 POSIX 分隔符；`verify:package` 因 Node 禁止直接 spawn `.cmd`（CVE-2024-27980 加固）而 `spawn EINVAL`

---

## 4. 扫描范围收敛（对推广影响最大）

`BurntSushi/memchr` 的默认审计曾报 **1721 条 / high_risk**。分桶后发现噪声与 `tests/`、`benches/` 无关：

| 类别 | 数量 | 占比 |
| --- | --- | --- |
| 完全不是 Cargo 目标（永不编译） | 1345 | 78.2% |
| 非 workspace 成员的独立 crate | 2 | 0.1% |
| 根 crate 真实源码 | 374 | 21.7% |

其中 **1311 条来自单个文件** `benchmarks/haystacks/code/rust-library.rs`——1.6 MB 的基准测试**输入数据**，其上没有任何 Cargo.toml 将其纳入 target。

实现不是目录黑名单，而是结构归属：每个 `.rs` 归到最近的祖先 manifest，再按 Cargo 可达性分类为 `shipped` / `build_script` / `development` / `unreferenced`，广度审计只读前两类。**排除永不静默**，每份报告说明排除了多少、属于哪类，`includeNonShippedSources` 可全部纳入。`rust_review_current_diff` 不应用此过滤——diff 已经点名文件，改测试目标是有意为之。

效果：memchr 1721 → 396（374 条为真实源码），bytes 246 → 208，smallvec 232 不变。

---

## 5. 可复用的实测数据

推广文案可直接引用，均可复现。

**低噪声（`tokio-rs/bytes` @ `d5c8ad3`）**：全仓 246 条发现，`src/bytes.rs` 单文件 77 条。在该文件的 `impl Bytes {` 内插入一个含 `unsafe { *self.ptr.as_ptr() }` 的方法后，diff 审查报出 **1 条 introduced + 1 条同 unsafe-site 上下文，隐藏 76 条既有**，函数名解析正确。

> 注：此案例曾出现一次「未能复现」，原因是改的文件不同——`src/lib.rs` 几乎没有既有 unsafe，隐藏数自然为 0。引用时必须指明是 `src/bytes.rs`。

**范围收敛（`BurntSushi/memchr`）**：1721 → 396。

**性能**：800 文件 5 层目录合成项目 0.86s；单文件 274 KiB / 6000 findings 0.19s。

---

## 6. 下一阶段

### npm 发布（需要 owner 先行）

1. 在 https://www.npmjs.com/signup 注册账号
2. 终端执行 `npm login`（涉及账号密码，由 owner 本人操作）
3. 之后 `npm publish` 可代为执行；`prepack` 会自动构建，`npm run verify:package` 已在 CI 中保护该路径
4. 发布后把 README 主安装路径从 clone + build 切换为 `npx --yes rust-security-auditor`（四步变一行）

包名 `rust-security-auditor` 经查在 npm 上可用；`bin`、`files`、`publishConfig`、`prepack` 均已就绪。

### `cargo audit` 集成（功能开发，不阻塞推广）

设计已记录在 `ROADMAP.md`：检测本机是否安装 `cargo-audit` / `cargo-deny`，有则调用并把结果映射进现有 `Finding` schema，无则明确降级提示。**不内置数据库、不联网**，以保持「本地、只读」的定位。它的价值是「一次调用拿到完整图景」，属于体验提升而非从 0 到 1。

### 推广节奏建议

先找 3-5 个写 unsafe/FFI 的 Rust 开发者小范围试用一到两周，把遇到的误报补成夹具，再公开推广。理由不是工具不行，而是**零外部用户跑过**——这类工具只有一次第一印象。

---

## 7. 仍然开着的已知问题

- **风险等级反映数量与严重度，不反映可利用性。** memchr 真实源码 374 条发现仍被标为 `high_risk`，而 memchr 本身没问题。这是评分设计问题，不是噪声问题，需要单独讨论。已在两份 README 的「已知短板」中明示。
- 裸 `#[tokio::test]` 在 `cfg(test)` 模块外按生产严重度上报（`tests/` 目录下的异步集成测试会受影响）。
- 依赖审查读清单文件，不解析传递依赖、不查 yanked crate、不评估 feature 合并。
