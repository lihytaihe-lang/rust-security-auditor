# Rust Security Auditor — Codex / MCP 开发任务书

> 目标：开发一个面向 Codex / ChatGPT 调用场景的 Rust 安全审查 Agent。  
> 第一阶段不做独立 SaaS、不做上传代码包、不做泛用代码 review。  
> 核心目标是在当前 Rust 项目上下文中，通过 Codex Skill / MCP Server 被调用，完成当前 diff、unsafe、依赖供应链和深度安全审计。

---

## 0. 项目定位

项目名暂定：

```text
Rust Security Auditor
```

一句话定位：

```text
一个面向 Rust 项目的安全审查 Agent，可在 Codex / ChatGPT 项目上下文中被调用，用于审查当前 diff、unsafe 代码、依赖供应链和发版前深度安全风险。
```

它不是：

- 不是通用代码 review bot
- 不是代码风格检查器
- 不是性能优化助手
- 不是上传 zip 的网页工具
- 不是 cargo-audit / Snyk / Semgrep 的简单替代
- 不是自动乱改代码的修复器

它是：

- Rust 安全审查专家
- Codex 项目上下文内可调用 Agent
- 低噪声、高置信、可复查的安全审查工具
- 后续可打包为 Codex Plugin / ChatGPT App / MCP App 的能力内核

---

## 1. 第一阶段目标

请先实现一个最小可运行版本：

```text
V0.1 = 本地 MCP Server + Codex Skill 文档/命令约定 + Rust 项目扫描能力
```

V0.1 必须支持四个核心能力：

```text
review_current_diff
audit_unsafe
audit_dependencies
deep_audit
```

其中优先级：

1. `review_current_diff`
2. `audit_unsafe`
3. `audit_dependencies`
4. `deep_audit`

第一版不要求真正接入 OpenAI 商店分发，也不要求完整 ChatGPT App UI。  
第一版要求可以作为本地项目工具运行，并为后续 Codex Plugin / MCP App 打好结构。

---

## 2. 推荐技术栈

优先使用 TypeScript / Node.js 实现 MCP Server。

原因：

- MCP / Apps SDK / Codex 插件生态对 TypeScript 比较友好
- 后续接 ChatGPT App / MCP App 更自然
- 可以快速调用本地命令：`git`、`cargo`、`rg`
- 便于输出 JSON / Markdown 报告

建议结构：

```text
rust-security-auditor/
├── README.md
├── package.json
├── tsconfig.json
├── src/
│   ├── index.ts
│   ├── mcp/
│   │   ├── server.ts
│   │   └── tools.ts
│   ├── scanners/
│   │   ├── projectScanner.ts
│   │   ├── gitDiffScanner.ts
│   │   ├── cargoScanner.ts
│   │   ├── unsafeScanner.ts
│   │   ├── dependencyScanner.ts
│   │   ├── commandFsScanner.ts
│   │   ├── inputBoundaryScanner.ts
│   │   └── concurrencyScanner.ts
│   ├── analyzers/
│   │   ├── findingBuilder.ts
│   │   ├── riskScorer.ts
│   │   └── evidenceCollector.ts
│   ├── reports/
│   │   ├── markdownReport.ts
│   │   ├── jsonReport.ts
│   │   └── schemas.ts
│   ├── utils/
│   │   ├── shell.ts
│   │   ├── fs.ts
│   │   └── paths.ts
│   └── skills/
│       ├── review-current-diff.md
│       ├── audit-unsafe.md
│       ├── audit-dependencies.md
│       └── deep-audit.md
├── examples/
│   ├── vulnerable-rust-project/
│   └── reports/
└── docs/
    ├── PRODUCT.md
    ├── ARCHITECTURE.md
    ├── FINDING_SCHEMA.md
    └── CODEX_USAGE.md
```

---

## 3. MCP Tools 设计

请实现以下 MCP tools。  
每个 tool 都应该接收 `workspacePath`，默认为当前工作目录。

### 3.1 `rust_review_current_diff`

用途：

```text
审查当前 Git diff 是否引入 Rust 安全风险。
```

输入建议：

```ts
{
  workspacePath?: string;
  baseRef?: string;
  includeUnstaged?: boolean;
  includeStaged?: boolean;
  severityThreshold?: "low" | "medium" | "high";
}
```

行为：

- 读取当前 git diff
- 识别新增/修改的 Rust 文件
- 重点检查：
  - 新增 unsafe
  - 新增依赖
  - 新增 `std::process::Command`
  - 新增文件系统路径处理
  - 新增 `unwrap` / `expect` 是否在外部输入路径上
  - 新增 FFI / raw pointer
  - 新增 secret / token / API key 风险
- 输出 Markdown + JSON

### 3.2 `rust_audit_unsafe`

用途：

```text
深度审查 Rust 项目中的 unsafe / FFI / raw pointer 风险。
```

输入建议：

```ts
{
  workspacePath?: string;
  targetPath?: string;
  includeTests?: boolean;
  severityThreshold?: "low" | "medium" | "high";
}
```

行为：

扫描：

- `unsafe`
- `unsafe fn`
- `unsafe impl Send`
- `unsafe impl Sync`
- `extern "C"`
- `*const`
- `*mut`
- `std::mem::transmute`
- `MaybeUninit`
- `from_raw_parts`
- `set_len`
- `Pin`
- `ManuallyDrop`
- `Box::from_raw`
- `CString` / `CStr`
- `libc`

每个发现要说明：

- 安全不变量是什么
- 是否有注释说明
- 是否被外部输入影响
- 是否跨 FFI
- 是否跨线程
- 可能导致什么问题
- 建议如何修复或补测试

### 3.3 `rust_audit_dependencies`

用途：

```text
审查 Cargo 依赖和供应链风险。
```

输入建议：

```ts
{
  workspacePath?: string;
  includeCargoTree?: boolean;
  checkBuildScripts?: boolean;
  severityThreshold?: "low" | "medium" | "high";
}
```

行为：

读取：

- `Cargo.toml`
- `Cargo.lock`
- workspace 配置
- `build.rs`
- `cargo metadata`
- 可选：`cargo tree`

检查：

- git dependency
- path dependency
- 未锁版本
- proc-macro 依赖
- build script
- suspicious features
- 依赖数量异常
- 直接依赖和间接依赖变化
- 是否建议运行 `cargo audit` / `cargo deny`

注意：

第一版可以不接在线 CVE 数据库。  
但如果本地存在 `cargo audit` 或 `cargo deny`，可以调用并把结果纳入报告。

### 3.4 `rust_deep_audit`

用途：

```text
对 Rust 项目做发版前深度安全审查。
```

输入建议：

```ts
{
  workspacePath?: string;
  auditScope?: "release" | "unsafe" | "dependencies" | "full";
  severityThreshold?: "low" | "medium" | "high";
  maxFiles?: number;
}
```

行为：

按阶段执行：

1. 项目画像
2. 依赖供应链
3. unsafe / FFI
4. 外部输入边界
5. 命令执行 / 文件系统
6. 并发 / async / 资源安全
7. 报告汇总

输出：

- Executive Summary
- Risk Matrix
- High Confidence Findings
- Needs Manual Review
- Suggested Tests
- Suggested Fixes
- Release Gate Recommendation

最终给出结论：

```text
PASS
PASS_WITH_WARNINGS
NEEDS_FIX_BEFORE_RELEASE
MANUAL_SECURITY_REVIEW_REQUIRED
```

---

## 4. Finding Schema

每一个发现必须使用统一结构。

```ts
type Severity = "low" | "medium" | "high" | "critical";
type Confidence = "low" | "medium" | "high";
type Category =
  | "unsafe"
  | "ffi"
  | "dependency"
  | "supply_chain"
  | "command_execution"
  | "filesystem"
  | "input_boundary"
  | "concurrency"
  | "secret"
  | "panic_dos"
  | "manual_review";

interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: Category;
  file: string;
  startLine?: number;
  endLine?: number;
  evidence: string[];
  whyItMatters: string;
  riskScenario: string;
  suggestedFix: string;
  suggestedTests?: string[];
  falsePositiveNotes?: string;
  references?: string[];
}
```

报告里不要输出泛泛建议。  
如果没有足够证据，应该放入 `Needs Manual Review`，不要伪装成确定漏洞。

---

## 5. 输出风格要求

输出必须低噪声。

禁止输出：

- 代码风格建议
- “建议增加注释”这种泛泛建议
- 没证据的漏洞猜测
- 非安全相关重构建议
- 大量 low severity 噪声

优先输出：

- high / medium severity
- high confidence findings
- 可复查证据
- 最小修复建议
- 建议补充的测试
- 是否阻止 release / merge

Markdown 报告模板：

```md
# Rust Security Audit Report

## Summary

- Result: NEEDS_FIX_BEFORE_RELEASE
- High: 1
- Medium: 2
- Low: 0
- Manual Review: 1

## High Risk Findings

### RSA-001: Command injection risk in `src/runner.rs`

- Severity: High
- Confidence: High
- Category: command_execution
- Location: `src/runner.rs:42`

#### Evidence

...

#### Why it matters

...

#### Risk scenario

...

#### Suggested fix

...

#### Suggested tests

...

## Medium Risk Findings

...

## Needs Manual Review

...

## Release Gate Recommendation

...
```

---

## 6. 扫描实现建议

第一版可以采用“规则扫描 + LLM 可读报告结构”的方式，不要一开始就追求完整 AST。

建议优先用：

- `git diff`
- `rg`
- `cargo metadata`
- `cargo tree`
- 文件读取
- 简单正则/启发式规则

后续再考虑：

- tree-sitter-rust
- syn 解析器
- rust-analyzer
- cargo geiger
- cargo audit
- cargo deny
- semgrep rules

第一版扫描规则示例：

### unsafe 规则

匹配：

```regex
\bunsafe\b
unsafe\s+fn
unsafe\s+impl\s+(Send|Sync)
extern\s+"C"
std::mem::transmute
MaybeUninit
from_raw_parts
set_len
Box::from_raw
```

### 命令执行规则

匹配：

```regex
std::process::Command
Command::new
\.arg\(
\.args\(
sh\s+-c
cmd\s+/C
```

### 文件系统规则

匹配：

```regex
std::fs::
File::open
File::create
read_to_string
write\(
canonicalize
join\(
temp_dir
```

### 输入边界规则

匹配：

```regex
serde_json::from_str
serde_yaml
toml::from_str
env::args
std::env::var
Request
PathBuf
unwrap\(\)
expect\(
panic!
```

### 依赖规则

检查：

```text
Cargo.toml
Cargo.lock
build.rs
git =
path =
proc-macro = true
default-features = false
features = [...]
```

---

## 7. Codex Skill 文档要求

请在 `src/skills/` 或 `.codex/skills/` 下创建技能说明文档。

### `review-current-diff.md`

内容包括：

```md
# Review Current Rust Diff for Security Risks

Use this skill when the user asks to review the current Rust changes, current diff, or current PR for security risks.

Call the MCP tool `rust_review_current_diff`.

Focus only on security risks:
- unsafe
- FFI
- dependency changes
- command execution
- filesystem/path handling
- input handling
- secrets
- panic/DoS

Do not provide style review or generic refactoring advice.
```

### `audit-unsafe.md`

```md
# Audit Unsafe Rust

Use this skill when the user asks to audit unsafe Rust, FFI, raw pointers, unsafe impl Send/Sync, or memory safety invariants.

Call the MCP tool `rust_audit_unsafe`.

For each unsafe finding, explain:
- the safety invariant
- whether it is documented
- how it could fail
- whether external input can reach it
- what tests should be added
```

### `audit-dependencies.md`

```md
# Audit Rust Dependencies

Use this skill when the user asks to audit Cargo dependencies or supply-chain risk.

Call the MCP tool `rust_audit_dependencies`.

Focus on:
- Cargo.toml
- Cargo.lock
- build.rs
- git/path dependencies
- proc-macro dependencies
- suspicious features
- dependency drift
```

### `deep-audit.md`

```md
# Deep Rust Security Audit

Use this skill before release, before publishing a crate, or when the user asks for a full Rust security audit.

Call the MCP tool `rust_deep_audit`.

The report must include:
- executive summary
- risk matrix
- high-confidence findings
- manual review items
- suggested tests
- suggested fixes
- release gate recommendation
```

---

## 8. 开发阶段拆解

请按下面阶段执行，不要一次性做过度复杂实现。

### Phase 1：项目骨架

完成：

- 初始化 TypeScript 项目
- 配置 lint/typecheck/test
- 建立目录结构
- 建立 Finding schema
- 建立 Markdown/JSON reporter
- 建立 shell command 工具封装

验收：

```bash
npm install
npm run build
npm test
```

### Phase 2：基础扫描器

完成：

- ProjectScanner：识别 Rust 项目、workspace、Cargo 文件
- GitDiffScanner：读取 staged/unstaged/base diff
- UnsafeScanner：扫描 unsafe 相关风险
- DependencyScanner：读取 Cargo.toml/Cargo.lock/build.rs

验收：

- 能在 examples/vulnerable-rust-project 上生成发现
- 能输出 JSON 和 Markdown

### Phase 3：MCP Server

完成：

- 实现 MCP server
- 注册四个 tools
- 每个 tool 调用对应 scanner
- 返回结构化结果和 Markdown summary

验收：

- 本地能启动 MCP server
- 能手动调用 tools
- 错误处理清晰

### Phase 4：Codex Skill 文档

完成：

- 添加 skill 文档
- 添加 `docs/CODEX_USAGE.md`
- 给出用户调用示例

验收：

- 文档中明确如何在 Codex 中使用
- 明确不做泛用 review

### Phase 5：Deep Audit v0

完成：

- 组合多个 scanner
- 输出完整审计报告
- 加 release gate recommendation

验收：

- `deep_audit` 能生成完整报告
- 报告不包含泛泛代码风格建议

### Phase 6：示例项目和测试

完成：

- 创建一个小型 vulnerable Rust example
- 包含 unsafe、Command、path、Cargo git dependency 等样例
- 对 scanner 写单元测试

验收：

- 测试覆盖主要发现类型
- 输出报告可读

---

## 9. 关键质量标准

1. 宁可少报，不要乱报。
2. 所有 findings 必须有证据。
3. 所有 high severity 必须解释攻击/失败场景。
4. 所有 unsafe findings 必须讨论 safety invariant。
5. 所有 dependency findings 必须说明为什么是 supply-chain risk。
6. 工具输出必须适合 Codex 后续修复。
7. 不要把产品做成普通 lint。
8. 不要做上传代码包。
9. 不要做独立 SaaS 入口。
10. 优先保证 Codex / MCP / Skill 工作流。

---

## 10. 给 Codex 的执行提示词

你现在开始开发 `Rust Security Auditor` 项目。

请严格遵守本文件的产品边界和阶段拆解。  
不要把它做成通用代码 review bot，不要做网页上传工具，不要做 SaaS。

当前任务：

```text
从 Phase 1 开始，创建 TypeScript 项目骨架、Finding schema、报告模块、基础 scanner 接口和 README。
完成后停止，给出已创建文件、如何运行、下一阶段建议。
```

要求：

- 代码必须可运行
- 先小步提交，不要一次性实现所有功能
- 每个模块职责清晰
- 优先为后续 MCP Server / Codex Skill 做结构
- 保持报告格式稳定
- 所有实现都围绕 Rust 安全审查
