# Rust Security Auditor

Rust Security Auditor is a local MCP server for focused Rust security review. It runs on your machine, reads local Cargo projects, and exposes security review tools to Codex or any MCP client over stdio.

It is designed for first public preview use: quick local installation, clear MCP configuration, deterministic example reports, and a small set of maintainable heuristic checks for Rust security review.

## What It Is

- A local TypeScript scanner kernel plus stdio MCP server.
- A Codex/MCP client companion for reviewing local Rust projects.
- A heuristic static review layer for unsafe/FFI, Cargo dependency and supply-chain clues, build scripts, command execution, accepted-risk suppressions, and changed-line-aware current diff review.
- A read-only tool. It reports findings and suggested next prompts, but it does not modify code unless a separate human-directed agent action does so.

## What It Is Not

- Not a SaaS product.
- Not an uploaded code package scanner.
- Not a ChatGPT App.
- Not a generic code review or style review tool.
- Not full AST, data-flow, control-flow, or taint analysis.
- Not formal verification, symbolic execution, or a replacement for human security review.

## Core MCP Tools

| Tool | Use It For |
| --- | --- |
| `rust_review_current_diff` | Review findings introduced by or near the current Git diff before commit or PR. |
| `rust_audit_unsafe` | Review unsafe blocks, unsafe functions, FFI, raw-memory primitives, and unsafe Send/Sync impls. |
| `rust_audit_dependencies` | Review Cargo manifests, lockfiles, build scripts, git/path dependencies, proc macros, and build dependencies. |
| `rust_audit_project` | Run the broad local project scan across the current preview rule set. |
| `rust_list_accepted_risks` | Inventory `rustsec-auditor` accepted-risk suppression comments without running the full scanner. |

## Best Fit

- Before commit: run `rust_review_current_diff`.
- Before PR: run `rust_review_current_diff` against staged changes or an explicit base/head ref.
- After Codex-generated code: run `rust_review_current_diff` to catch newly introduced unsafe, dependency, or build-script risk clues.
- Before release accepted-risk review: run `rust_list_accepted_risks`, then use `rust_audit_project` when you want the broader local project scan.

## Quickstart

Prerequisites:

- Node.js 20 or newer.
- A local checkout of this repository.
- A local Rust Cargo project when you want to scan real code.

Install and verify the preview:

```bash
npm install
npm run typecheck
npm test
```

Start the local MCP server:

```bash
npm --silent run mcp
```

Use `--silent` for MCP stdio. MCP reserves stdout for JSON-RPC protocol frames, and normal npm lifecycle banners can break client initialization.

## MCP Client Config

Configure Codex or another MCP client to launch this repository as a stdio server:

```json
{
  "mcpServers": {
    "rust-security-auditor": {
      "command": "npm",
      "args": ["--silent", "run", "mcp"],
      "cwd": "/absolute/path/to/rust-security-auditor"
    }
  }
}
```

Use an absolute `cwd` for this repository. A fuller sample lives at `examples/mcp-client-config.json`, and a Codex-oriented sample lives at `examples/codex-plugin-config.json`.

## Calling Tools

The MCP client sends tool calls with local project paths. Example arguments:

`rust_review_current_diff`

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

`rust_audit_unsafe`

```json
{
  "projectPath": "/absolute/path/to/rust/project",
  "includeDocumentedUnsafe": true,
  "outputFormat": "json",
  "pathMode": "relative"
}
```

`rust_audit_dependencies`

```json
{
  "projectPath": "/absolute/path/to/rust/project",
  "outputFormat": "json",
  "pathMode": "relative"
}
```

`rust_audit_project`

```json
{
  "projectPath": "/absolute/path/to/rust/project",
  "outputFormat": "markdown",
  "pathMode": "relative",
  "includeSuppressed": false
}
```

`rust_list_accepted_risks`

```json
{
  "projectPath": "/absolute/path/to/rust/project",
  "includeExpired": true,
  "includeInvalid": true,
  "outputFormat": "markdown",
  "pathMode": "relative"
}
```

## CLI And Debug Helper

The supported preview path is MCP client usage. For local debugging, the repository also includes `npm run mcp:call`, which invokes the same tool handlers without starting an MCP client:

```bash
npm run mcp:call -- rust_audit_project --projectPath test/fixtures/vulnerable-rust-project --outputFormat markdown
npm run mcp:call -- rust_audit_unsafe --projectPath test/fixtures/vulnerable-rust-project
npm run mcp:call -- rust_audit_dependencies --projectPath test/fixtures/dependency-risk
npm run mcp:call -- rust_review_current_diff --projectPath /absolute/path/to/rust/project --outputFormat markdown --pathMode relative --reportMode compact
npm run mcp:call -- rust_review_current_diff --projectPath /absolute/path/to/rust/project --staged true --nearChangedLineWindow 2
npm run mcp:call -- rust_list_accepted_risks --projectPath test/fixtures/suppressed-rust-project --includeExpired true --includeInvalid true --outputFormat markdown
```

These commands build the TypeScript project first and print structured JSON to stdout. They are debugging helpers, not a full standalone CLI interface.

## Example Reports

Sanitized example outputs live in `examples/reports/`:

- `rust_review_current_diff.json`
- `rust_audit_project.json`
- `rust_audit_project.md`
- `rust_audit_unsafe.json`
- `rust_audit_dependencies.json`
- `rust_list_accepted_risks.json`
- `rust_list_accepted_risks.md`
- `mcp-tool-list.json`

The examples use placeholders such as `<repo>` and `/absolute/path/to/...`; they should not contain private machine paths.

## Codex Usage

Recommended natural-language entries:

| Codex request | MCP tool |
| --- | --- |
| `@Rust Security Auditor review current diff` | `rust_review_current_diff` |
| `@Rust Security Auditor check this Rust project before commit` | `rust_review_current_diff` |
| `@Rust Security Auditor audit unsafe` | `rust_audit_unsafe` |
| `@Rust Security Auditor audit dependencies` | `rust_audit_dependencies` |
| `@Rust Security Auditor audit project` | `rust_audit_project` |
| `@Rust Security Auditor list accepted risks` | `rust_list_accepted_risks` |
| `@Rust Security Auditor show suppressed risks` | `rust_list_accepted_risks` |
| `@Rust Security Auditor check expired suppressions` | `rust_list_accepted_risks` |
| `@Rust Security Auditor review accepted risk inventory before release` | `rust_list_accepted_risks` |

Codex should summarize tool results as security review output with an overall risk conclusion, blocking issues, recommended fixes, manual-review items, and false-positive or suppression notes. It should not output generic style advice, claim a complete audit, or silently add suppressions.

The Skill documentation lives in:

- `skills/rust-security-auditor/SKILL.md`
- `skills/rust-security-auditor/examples.md`
- `skills/rust-security-auditor/troubleshooting.md`

## Tool Behavior

`rust_review_current_diff` reviews the current Git diff for a local Cargo project or workspace. With no refs and no `staged`, it reviews `git diff`. With `staged: true`, it reviews `git diff --cached`. With both `baseRef` and `headRef`, it reviews `git diff baseRef..headRef`.

Diff findings are classified as:

- `introduced_by_diff`: the finding starts on an added line.
- `near_changed_lines`: the finding is near an added line, using the default 3-line window. This is a context reminder, not proof that the current diff introduced the finding.
- `pre_existing_in_changed_file`: the finding is in a changed file but outside the changed-line window.

By default, current diff review returns only `introduced_by_diff` and filtered `near_changed_lines`. Near-changed findings are shown only for medium-or-higher severity with medium/high confidence. If lightweight function or unsafe-site context shows the nearby finding belongs to a different function/site, it is downgraded to a non-blocking note. Set `includePreExisting: true` to show historical findings in changed files.

Diff review report options:

- `pathMode`: defaults to `relative`. Use `relative` for PR comments or shared reports so Markdown does not leak local absolute paths. JSON still keeps the resolved `projectPath`.
- `reportMode`: defaults to `compact`. Compact mode is intended for Codex and PR comments; use `full` when you need changed-file lists, non-blocking notes, accepted/suppressed risk details, and full evidence blocks.
- `nearChangedLineWindow`: defaults to `3`; reduce it to `1` or `2` when nearby pre-existing findings are too noisy, or increase it only when surrounding invariants matter.

When multiple findings point at the same unsafe site, Markdown uses a grouped view. For example, a generic `RSA-UNSAFE-BLOCK` and a specific `RSA-UNSAFE-TRANSMUTE` on the same unsafe block are displayed under one unsafe site. This is a UX grouping only; the JSON `findings` array remains unchanged and each rule still represents its own review signal.

`rust_review_current_diff` also returns a `reviewDecision`:

- `block`: introduced critical/high findings with non-low confidence, or nearby high-confidence critical/high findings that remain in the same lightweight function/unsafe-site context.
- `needs_attention`: medium findings, nearby findings, low-confidence findings, expired suppressions, or invalid suppressions need human review.
- `pass`: no blocking or manual-review findings were reported.

Low-confidence findings are review targets, not confirmed vulnerabilities.

## Accepted Risk Suppressions

Inline suppressions are accepted-risk records for reviewed false positives or intentionally accepted risks. They are not meant to hide unresolved blockers.

```rust
pub fn read_byte(ptr: *const u8) -> u8 {
    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK owner=@security ticket=SEC-123 until=2026-12-31 -- legacy FFI wrapper reviewed in host project
    unsafe { *ptr }
}
```

Supported formats:

```rust
// rustsec-auditor: ignore RULE_ID -- reason
// rustsec-auditor: ignore RULE_ID until=YYYY-MM-DD -- reason
// rustsec-auditor: ignore RULE_ID owner=@name -- reason
// rustsec-auditor: ignore RULE_ID ticket=SEC-123 -- reason
```

Rules:

- The reason after `--` is required.
- `RULE_ID` must be the exact returned rule id.
- Broad `ignore all` or `ignore *` directives are not supported.
- `owner`, `ticket`, and `until` are optional but recommended.
- Expired suppressions are shown again.
- Invalid suppressions are ignored and reported for cleanup.

Use `rust_list_accepted_risks` to inventory active, expired, and invalid suppression comments without running the full scanner.

## Public Modules

- `src/mcp/server.ts`: local stdio MCP server.
- `src/mcp/tools.ts`: testable MCP tool handlers backed by the scanner kernel.
- `src/mcp/debug.ts`: local tool debug entrypoint.
- `src/scanners/rustProjectScanner.ts`: combined Rust project scan entrypoint.
- `src/scanners/unsafeScanner.ts`: unsafe, FFI, and raw-memory primitive scanner.
- `src/scanners/dependencyScanner.ts`: Cargo/build.rs dependency risk clue scanner.
- `src/scanners/acceptedRiskInventory.ts`: standalone accepted-risk suppression inventory.
- `src/scanners/suppressions.ts`: shared `rustsec-auditor` suppression parser and expiry checks.
- `src/git/diffParser.ts`: unified git diff parser for hunks and changed line numbers.
- `src/reports/markdownReport.ts`: Markdown report renderer.
- `src/reports/jsonReport.ts`: JSON report renderer.
- `src/reports/schemas.ts`: Finding schema, validation, and summary helpers.

## Current Rule Set

Unsafe and FFI:

- `RSA-UNSAFE-BLOCK`
- `RSA-UNSAFE-FN`
- `RSA-UNSAFE-IMPL-SEND`
- `RSA-UNSAFE-IMPL-SYNC`
- `RSA-FFI-EXTERN-C`
- `RSA-UNSAFE-TRANSMUTE`
- `RSA-UNSAFE-MAYBEUNINIT`
- `RSA-UNSAFE-FROM-RAW-PARTS`
- `RSA-UNSAFE-SET-LEN`
- `RSA-UNSAFE-BOX-FROM-RAW`

Dependency and build:

- `RSA-DEP-GIT`
- `RSA-DEP-PATH`
- `RSA-DEP-PROC-MACRO`
- `RSA-DEP-BUILD-DEPENDENCIES`
- `RSA-DEP-LOCK-GIT`
- `RSA-BUILD-SCRIPT`
- `RSA-BUILD-COMMAND`

Findings are deduplicated by `file + startLine + ruleId` and sorted by severity, confidence, file, then line. Every emitted finding includes `ruleId`, `file`, severity, confidence, category, evidence, why it matters, risk scenario, and suggested fix.

## Development

Common checks:

```bash
npm run typecheck
npm test
git diff --check
```

Build output goes to `dist/` and is intentionally ignored by Git.

## Security Model And Limits

Rust Security Auditor is a local, heuristic static scanner. It does not upload repositories, package source bundles, or scanned code to an external service. The MCP server validates that `projectPath` exists and is a local directory, resolves it, scans within that directory, filters Git diff paths to safe relative paths, and returns structured errors for invalid input.

The current preview does not build a full Rust AST, execute semantic data-flow or taint analysis, prove unsafe invariants, or provide a formal security guarantee. Treat findings as focused review targets with concrete evidence, especially around unsafe invariants, FFI boundaries, build-time execution, and supply-chain trust boundaries.
