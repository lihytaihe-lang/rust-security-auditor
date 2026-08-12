# Rust Security Auditor

[English](README.md) · **简体中文**

一个本地优先的 Rust 安全审查 MCP server，通过 stdio 通信。它审查 Rust 代码中的 unsafe、FFI 和供应链风险，告诉你的编码 agent 在提交前该看哪里。

它完全运行在你的机器上，读取本地 Cargo 项目，从不修改目标源码树，通过 stdio 向 Claude Code、Codex、Cursor 或任何 MCP 客户端暴露五个只读工具。

让 agent 审查你刚写的代码，返回的是这次改动里真正带风险的那部分——以下是真实输出的节选：

```markdown
# Rust Security Review: Current Diff

## Decision

NEEDS ATTENTION

- Safe to commit: No
- Reason: No hard blockers were found, but introduced findings or directly
  related same-function/same-unsafe-site context need human review before commit.
- Blocking findings: 0
- Manual review findings: 2

## Introduced by this diff

### Unsafe site at src/buffer.rs:11

- Location: `src/buffer.rs:11`
- Function/context: `read_fast`
- Diff relation: introduced_by_diff
- Findings:
  - Generic unsafe block (RSA-UNSAFE-BLOCK, medium severity/high pattern-detection confidence)
  - get_unchecked skips bounds checking (RSA-UNSAFE-GET-UNCHECKED, medium severity/high pattern-detection confidence)
```

同一文件里其它位置的既有 unsafe 代码会被单独归类，不会看起来像新增的阻塞项。

## 为什么这样设计

多数扫描器回答的是「这个代码库有什么问题」。对一个刻意使用 `unsafe` 的 crate 来说，那份答案就是一串你翻一次就再也不会打开的清单。这个工具围绕另外三个决定来构建。

**它审查的是改动，不是代码库。** [`tokio-rs/bytes`](https://github.com/tokio-rs/bytes) 全仓 246 条发现，仅 `src/bytes.rs` 一个文件就有 77 条。往这个文件里加五行、含一个 `unsafe` 块，审查报出的是**一条**新引入的发现，外加一条因为落在同一个 unsafe 块里、确实相关的既有发现——另外 76 条被隐藏。这才是你提交前真正能处理的数量。

**它只审 Cargo 会编译的代码。** [`BurntSushi/memchr`](https://github.com/BurntSushi/memchr) 的默认审计原本报 1721 条，其中 1311 条来自单个 1.6 MB 的基准测试**输入文件**——那个文件存在的目的是被搜索，不是被编译。现在文件按 Cargo 的可达方式分类，广度审计只读 `src/` 和 `build.rs`，数字变成 396，其中 374 条来自真实的 crate 源码。**排除永不静默**——每份报告都会说明排除了什么、为什么。

**看不到的时候，它拒绝说「通过」。** 如果你 diff 里的某个文件读不了、超限、或落在项目根之外，审查会明说，并且不给结论——而不是基于残缺的扫描报一个干净结果。同样的原则适用于当前平台无法无歧义寻址的 Git 路径：直接让调用失败，而不是去审查那个路径碰巧命中的文件。

一切都在你机器上运行。它只读本地路径，从不写入你的源码树，不发起任何网络请求。

## 安装

需要 Node.js 20 或更高版本。**不需要 Rust 工具链**——扫描器读源码和清单文件，不构建你的项目。

### 主路径：本地 checkout

克隆、安装依赖、构建一次：

```bash
git clone https://github.com/lihytaihe-lang/rust-security-auditor.git
cd rust-security-auditor
npm ci
npm run build
```

让 MCP 客户端直接指向这份 checkout 构建出的 server。它的标准输入输出保留给 JSON-RPC，日志走 stderr。

```json
{
  "command": "node",
  "args": ["/absolute/path/to/rust-security-auditor/dist/src/mcp/server.js"]
}
```

要审查的 Rust 项目通过工具参数 `projectPath` 传入绝对路径；server 进程本身不需要运行在那个项目目录下。

### 客户端配置

这个 server 讲的是标准 stdio MCP，所以下面的配置块到处都一样，区别只是放进哪个文件。CI 在 Linux、macOS 和 Windows 上都验证了 stdio 边界本身——握手、`tools/list`、以及一次真实的 `tools/call`。各客户端的配置格式来自各家官方文档，没有逐一在宿主 UI 里实际跑过，所以如果哪家改了格式，以它的文档为准。

Claude Desktop 是唯一需要单独说明的：它当前的流程期待的是 Desktop Extension，而本项目不提供 `.mcpb`，所以暂时没有针对 Desktop 的配置可给。

**Claude Code**

```bash
claude mcp add --transport stdio rust-security-auditor -- node /absolute/path/to/rust-security-auditor/dist/src/mcp/server.js
```

**Codex CLI / app / IDE 扩展**

```toml
# ~/.codex/config.toml 或某个可信项目的 .codex/config.toml
[mcp_servers.rust_security_auditor]
command = "node"
args = ["/absolute/path/to/rust-security-auditor/dist/src/mcp/server.js"]
```

对应的 Codex CLI 命令：

```bash
codex mcp add rust-security-auditor -- node /absolute/path/to/rust-security-auditor/dist/src/mcp/server.js
```

**Cursor**

```json
{
  "mcpServers": {
    "rust-security-auditor": {
      "command": "node",
      "args": ["/absolute/path/to/rust-security-auditor/dist/src/mcp/server.js"]
    }
  }
}
```

Cursor 的配置块放进项目的 `.cursor/mcp.json`，或用户级的 `~/.cursor/mcp.json`。

**VS Code / Copilot**

```json
{
  "servers": {
    "rustSecurityAuditor": {
      "command": "node",
      "args": ["/absolute/path/to/rust-security-auditor/dist/src/mcp/server.js"]
    }
  }
}
```

VS Code 的配置块放进 `.vscode/mcp.json`，或通过 **MCP: Open User Configuration** 打开的用户级 `mcp.json`。

机器可读版本见 [`examples/mcp-client-config.json`](examples/mcp-client-config.json) 和 [`examples/codex-plugin-config.json`](examples/codex-plugin-config.json)。

### npm

尚未发布。发布之后，`npx --yes rust-security-auditor` 就能取代整个 clone + 构建的步骤。打包配置已经就绪，CI 每次都会验证——`npm run verify:package` 会打出 tarball、全新安装、并通过安装好的可执行文件完成一次 MCP 握手——所以发布时这条路是通的。

不接客户端、只想调试 checkout 的话，`npm --silent run mcp` 会重新构建并启动。

## 五个工具

| 工具 | 用途 |
| --- | --- |
| `rust_review_current_diff` | 这次改动引入了什么？提交前、开 PR 前、以及 agent 生成代码之后跑。 |
| `rust_audit_unsafe` | unsafe 块和函数、FFI 边界、裸内存原语、unsafe Send/Sync。 |
| `rust_audit_dependencies` | Cargo 清单、锁文件、构建脚本、git/path 依赖、过程宏、`.cargo/config.toml`。 |
| `rust_audit_project` | 覆盖全部规则的本地广度扫描。 |
| `rust_list_accepted_risks` | 已接受风险的抑制注释清单，含已过期和无效的。 |

用自然语言调用即可——「提交前审一下当前 diff」「审查 unsafe」「检查依赖」「列出已接受的风险」——也可以直接传参：

```json
{
  "projectPath": "/absolute/path/to/rust/project",
  "baseRef": "main",
  "headRef": "HEAD",
  "staged": false,
  "includePreExisting": false,
  "nearChangedLineWindow": 3,
  "outputFormat": "markdown",
  "pathMode": "relative",
  "reportMode": "compact"
}
```

每个工具都接受 `projectPath`、`outputFormat`（`markdown` | `json`）、`pathMode`（`relative` | `absolute`）和 `reportMode`（`compact` | `full`）。默认是 `relative` 和 `compact`——这样你粘进 PR 的内容里不会带上本机绝对路径。

各工具的脱敏示例输出见 [`examples/reports/`](examples/reports)。

## 能检出什么

**Unsafe 与 FFI** — `RSA-UNSAFE-BLOCK`、`RSA-UNSAFE-FN`、`RSA-UNSAFE-IMPL-SEND`、`RSA-UNSAFE-IMPL-SYNC`、`RSA-FFI-EXTERN-C`、`RSA-FFI-CSTR-FROM-PTR`、`RSA-UNSAFE-TRANSMUTE`、`RSA-UNSAFE-MAYBEUNINIT`、`RSA-UNSAFE-FROM-RAW-PARTS`、`RSA-UNSAFE-SET-LEN`、`RSA-UNSAFE-BOX-FROM-RAW`、`RSA-UNSAFE-GET-UNCHECKED`、`RSA-UNSAFE-UNCHECKED-CALL`、`RSA-UNSAFE-STATIC-MUT`、`RSA-UNSAFE-RAW-PTR-ACCESS`

**供应链与构建** — `RSA-DEP-GIT`、`RSA-DEP-PATH`、`RSA-DEP-PROC-MACRO`、`RSA-DEP-BUILD-DEPENDENCIES`、`RSA-DEP-LOCK-GIT`、`RSA-DEP-VERSION-UNBOUNDED`、`RSA-BUILD-SCRIPT`、`RSA-BUILD-COMMAND`、`RSA-CARGO-SOURCE-REPLACEMENT`、`RSA-CARGO-RUNNER`

**运行时执行** — `RSA-EXEC-COMMAND`

每条发现都带有规则 id、文件和行号、证据、为什么重要、一个具体的风险场景，以及建议的修复方式。发现按 `file + startLine + ruleId` 去重，并按严重度、置信度、位置排序。

扫描器会跟踪 Rust 的注释和字面量边界，所以块注释、文档示例或字符串字面量里的模式不会被上报。`#[cfg(test)]` 内的发现会降低严重度，因为测试代码不参与发布。

**置信度指的是模式检出的确定性，不是可利用性。** 高置信度的意思是「这个模式确实在那里」，不是「确认存在漏洞」。

### 扫描范围

广度审计读取 Cargo 真正会编译的内容：每个 crate 的 `src/`，加上 `build.rs`。它跳过 test、benchmark、example 目标，也跳过任何 Cargo 目标都到不了的 `.rs` 文件——样例输入、vendor 快照、临时草稿。永不参与编译的代码不可能带来运行时风险，扫描它只会把真正重要的发现淹没。

跳过永不静默。每份报告都会说明排除了多少文件、以及为什么：

```
Excluded 18 Rust file(s) from source scanning: 18 file(s) no Cargo target reaches.
Set includeNonShippedSources to include them.
```

给 `rust_audit_project` 传 `includeNonShippedSources: true` 就会把它们纳入。`rust_review_current_diff` 从不应用这个过滤——你改了测试目标，那是你有意改的，所以照审。

在 [`BurntSushi/memchr`](https://github.com/BurntSushi/memchr) 上，这让默认审计从 1721 条降到 396 条；被移除的 1325 条几乎全部来自那一个 Cargo 从不编译的 1.6 MB 基准测试**输入**文件。

## 能告诉你什么，不能告诉你什么

**它能告诉你**：一个 crate 的 unsafe 和 FFI 面在哪里、每个位置各自承担什么义务；某次具体改动引入了什么、以及哪些既有代码近到值得一并看；构建期和供应链的信任边界在哪——构建脚本、git 和 path 依赖、过程宏、registry 替换、自定义 target runner；以及有哪些风险是别人已经接受过的，包括那些已经过期的接受记录。

**它不能告诉你**某个 `unsafe` 块是否真的不健全。它指出那些「内存安全依赖于编译器不检查的不变量」的位置，把证据和问题交给你。证明那个不变量成立，仍然是你或你的评审者的工作。

### 已知短板

- **不查已知漏洞。** 没有 [RustSec advisory](https://rustsec.org) 或 CVE 查询，所以它永远不会告诉你某个依赖版本有已公开的安全公告。请配合 `cargo audit` 或 `cargo deny` 使用。（[已列入 roadmap](ROADMAP.md)）
- **带词法上下文的模式匹配，不是语义分析。** 没有 AST、类型信息、数据流或污点追踪。它知道某一行是代码而不是注释或字符串，也知道这一行落在哪个函数和哪个 unsafe 块里。但它不知道一个指针是从哪来的。
- **风险等级反映的是数量和严重度，不是可利用性。** 一个刻意使用 `unsafe` 的 crate——SIMD、分配器、FFI 绑定——会被标成 `high_risk`，因为它发现多，不是因为它危险。memchr 在真实源码里有 374 条发现；memchr 没问题。**看发现，别看那个标签。**
- **已经评审过、写了文档的 unsafe 块仍然会被报出来。** 附近的 `SAFETY:` 注释会降低置信度，但不会移除这条发现，因为工具无法检查那条注释说的是不是真的。这正是「已接受风险抑制」存在的意义。
- **裸 `#[tokio::test]` 会被当作生产代码**，除非它位于 `#[cfg(test)]` 模块内。只有 Rust 自带的 `#[test]`、以及确定要求 `test` 的 `cfg` 才会降低发现的严重度——其它任何属性路径都可能是一个在 release 构建里照样编译的宏。
- **依赖审查读的是清单文件，不是解析后的依赖图。** 它检查 `Cargo.toml`、`Cargo.lock`、`build.rs` 和 `.cargo/config.toml`，但不解析传递依赖、不检查被 yank 的 crate、不评估 feature 合并。
- 不是形式化验证、符号执行，也不能替代人工评审 unsafe 不变量。
- 不是托管服务、SaaS 扫描器或代码上传扫描器。它只读本地路径。
- 不是通用代码评审或风格检查工具。

## 当前 diff 审查

`rust_review_current_diff` 默认审查工作区；传 `staged: true` 审查 `git diff --cached`；同时给出 `baseRef` 和 `headRef` 时审查 `baseRef..headRef`。

每条发现按它与本次改动的关系分类：

| 关系 | 含义 |
| --- | --- |
| `introduced_by_diff` | 起始于新增行。 |
| `same_unsafe_site_context` | 既有代码，但与新增行处于同一个 unsafe 块。 |
| `same_function_context` | 既有代码，同一函数内，不同的 unsafe 位置。 |
| `nearby_legacy_context` | 行号接近新增行，但位于不同的函数或 unsafe 位置。 |
| `unrelated_nearby` | 行号接近新增行，但没有确认的关联。 |
| `pre_existing_in_changed_file` | 位于被改动的文件内，但在改动行窗口之外。 |

compact 输出显示 `introduced_by_diff`、`same_unsafe_site_context`，以及中高置信度下中等及以上严重度的 `same_function_context`。`nearby_legacy_context` 被隐藏，这样另一个函数里的老 unsafe 代码不会看起来像新的阻塞项——用 `reportMode: "full"` 可以看到它们，用 `includePreExisting: true` 可以把被改文件里的历史发现也纳入。如果附近的发现仍然吵，把 `nearChangedLineWindow` 降到 1 或 2。

工具还会返回一个 `reviewDecision`：

- `block` — 引入了非低置信度的 critical/high 发现。
- `needs_attention` — 引入了 medium 发现、直接相关的同 unsafe 位置或同函数上下文、低置信度的引入项，或存在已过期/无效的抑制。
- `pass` — 没有阻塞项，也没有需要人工复核的项。

结论主要由 `introduced_by_diff` 驱动。同一 unsafe 位置的 high 发现需要关注但不会硬阻塞；除非你显式要求纳入既有发现，否则 `nearby_legacy_context` 和 `unrelated_nearby` 不会影响结论。

## 已接受风险的抑制

抑制是「已评审的误报」或「有意接受的风险」的记录，不是用来藏掉未解决的阻塞项的。

```rust
pub fn read_byte(ptr: *const u8) -> u8 {
    // rust-security-auditor: ignore RSA-UNSAFE-BLOCK owner=@security ticket=SEC-123 until=2026-12-31 -- legacy FFI wrapper reviewed in host project
    unsafe { *ptr }
}
```

```rust
// rust-security-auditor: ignore RULE_ID -- reason
// rust-security-auditor: ignore RULE_ID until=YYYY-MM-DD -- reason
// rust-security-auditor: ignore RULE_ID owner=@name ticket=SEC-123 -- reason
```

- `--` 之后的理由是必填的，`RULE_ID` 必须是精确的规则 id。
- 不支持 `ignore all` 和 `ignore *`。
- 过期的抑制会重新上报；无效的抑制会被忽略并列出来待清理。
- 旧的 `rustsec-auditor:` 标记仍然可用但已废弃——它与无关的 [RustSec](https://rustsec.org) 项目撞名。请把已有注释改成 `rust-security-auditor:`；扫描器遇到旧写法时会给出警告。

用 `rust_list_accepted_risks` 可以在不跑完整扫描的情况下清点有效、过期和无效的抑制。它的 JSON 和 Markdown 输出都包含扫描覆盖信息；如果覆盖不完整，请把结果当作「不完整的清单」，而不是「不存在已接受风险」的证明。

## 报告模式

`compact`（默认）面向 agent 摘要和 PR 评论：总体风险、严重度与规则计数、首要发现、分组的审查信号、高优先区域，以及建议的后续提示词。JSON 里的 `findings` 数组始终是完整的。

`full` 保留每条发现的全部细节——证据、为什么重要、风险场景、建议修复、建议测试、参考资料、误报说明和抑制记录。适合审计笔记、交接归档和抑制复核。

当多条发现指向同一个 unsafe 位置时，Markdown 会把它们归到那个位置下。这只是显示层的分组，JSON 不变。

## 开发

```bash
npm ci
npm run typecheck
npm test
npm run check      # typecheck + 测试 + 空白字符检查
```

不接 MCP 客户端的本地调试：

```bash
npm run mcp:call -- rust_audit_project --projectPath test/fixtures/vulnerable-rust-project --outputFormat markdown
npm run mcp:call -- rust_review_current_diff --projectPath /absolute/path/to/rust/project --staged true
```

构建产物在 `dist/`，已被 git 忽略。新增规则的流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。

源码结构：

| 路径 | 内容 |
| --- | --- |
| `src/mcp/server.ts` | 本地 stdio MCP server |
| `src/mcp/tools.ts` | 由扫描内核支撑的工具处理函数 |
| `src/scanners/rustLexer.ts` | 注释/字面量遮罩与测试代码识别 |
| `src/scanners/unsafeScanner.ts` | unsafe、FFI 和裸内存规则 |
| `src/scanners/dependencyScanner.ts` | Cargo 清单、锁文件、构建脚本与 cargo 配置规则 |
| `src/scanners/sourceRiskScanner.ts` | 运行时进程执行 |
| `src/scanners/rules.ts` | 规则元数据：严重度、原理、修复建议 |
| `src/scanners/suppressions.ts` | 抑制解析与过期判定 |
| `src/git/diffParser.ts` | 统一 diff 解析器 |
| `src/reports/` | Markdown 与 JSON 渲染、发现的 schema |

## 安全模型

server 会校验 `projectPath` 存在且是本地目录，只在其内部扫描，把 git diff 路径过滤为安全的相对路径，拒绝可能被当作命令行开关解析的 git ref，并且在不经过 shell 的情况下调用 `git`。它不上传代码、不打包源码、不访问任何网络服务。

发现阶段会跳过 `.git`、`target`、`node_modules` 等目录，不跟随符号链接，在打开目录之后立即重新校验一次，并对单文件大小、文件数、目录数、总字节数和读取并发做上限。在返回源码字节之前，读取器会校验规范化后的包含关系、拒绝含符号链接的路径分量、确认路径名仍然解析到已打开的那个文件，并把读取长度限制在该文件描述符已验证的大小内。覆盖信息在一次工具调用内是单调的：可选的上下文提取不能把一个不完整的改动输入变成完整覆盖。畸形的 Rust 词法输入会禁用「仅测试代码」的严重度下调，并把覆盖标记为不完整。覆盖信息在 JSON 和 Markdown 中都是结构化的；当前 diff 若存在不完整的 Rust/Cargo 输入，会以 `needs_attention` 和 `safeToCommit: false` 失败关闭。

关于如何报告本工具自身的漏洞、以及什么在范围内什么不在，见 [SECURITY.md](SECURITY.md)。

## 状态

v0.1.x 本地优先 MCP 预览版，Apache-2.0 许可。本地、只读的 Rust 审查——不是托管扫描器、ChatGPT App 或市场产品。最新发布是 [v0.1.2](https://github.com/lihytaihe-lang/rust-security-auditor/releases/tag/v0.1.2)；尚未发布到 npm。计划中的内容和有意排除在外的内容见 [ROADMAP.md](ROADMAP.md)。
