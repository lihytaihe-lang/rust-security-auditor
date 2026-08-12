# Rust Security Auditor

**English** · [简体中文](README.zh-CN.md)

A local-first security review server for Rust projects, spoken over MCP. It audits `unsafe` and FFI surface, Cargo supply-chain and build-time trust boundaries, and process execution — as a whole-project audit, or scoped to the change you are about to commit.

It runs entirely on your machine, reads local Cargo projects, never modifies the target source tree, and exposes five read-only tools to Claude Code, Codex, Cursor, or any other MCP client.

Agent-assisted development writes Rust faster than anyone reviews it. A generated module reaches for `get_unchecked` because it is faster, a generated `build.rs` shells out to a tool, a generated `Cargo.toml` pins a dependency to `*`. Each is a normal line of Rust that a compiler accepts. This finds them and tells you what each one obliges you to prove.

## Two ways to use it

**Audit a whole project** — when you take over a crate, evaluate a dependency, or prepare a release. `rust_audit_project` runs every rule across the code Cargo builds; `rust_audit_unsafe` and `rust_audit_dependencies` narrow that to one surface. You get the full inventory: where the unsafe is, what each site obliges, which trust boundaries exist at build time.

**Review the current change** — before every commit, and especially right after an agent generates code. `rust_review_current_diff` reads `git diff` and separates what this change introduced from what was already there. On a crate with hundreds of pre-existing findings, that is the difference between a list you ignore and a list you act on.

Both work on the same rule set. The whole-project audit tells you where you stand; the diff review keeps you from sliding backwards.

Here is the second one on a real change — actual output, abridged:

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

Pre-existing unsafe code elsewhere in the file is classified separately and does not look like a new blocker.

## What keeps the output usable

A security tool that reports everything gets read once. Three design decisions keep the output at a size you act on, each with the measurement behind it.

**Only code Cargo builds is audited.** A default audit of [`BurntSushi/memchr`](https://github.com/BurntSushi/memchr) used to report 1,721 findings; 1,311 came from a single 1.6 MB benchmark *input* file that exists to be searched, not compiled. Files are classified by how Cargo reaches them, and a whole-project audit reads `src/` and `build.rs`. The count is 396, of which 374 are real crate source. Nothing is skipped silently — every report states what was excluded and why, and one flag brings it all back.

**A diff review separates introduced from pre-existing.** [`tokio-rs/bytes`](https://github.com/tokio-rs/bytes) has 246 findings across the crate and 77 in `src/bytes.rs` alone. Add five lines with one `unsafe` block to that file and the review reports **one** introduced finding, plus one pre-existing finding that shares the same unsafe block because it is genuinely relevant — and hides the other 76.

**It refuses to say "pass" when it could not look.** If a file in your diff was unreadable, too large, or outside the project root, the review says so and withholds the verdict rather than reporting a clean result over a partial scan. The same applies to a Git path this platform cannot address unambiguously: the call fails instead of reviewing whatever that path happens to hit.

Everything runs on your machine. It reads local paths, never writes to your source tree, and makes no network requests.

## What It Catches

**Unsafe and FFI** — `RSA-UNSAFE-BLOCK`, `RSA-UNSAFE-FN`, `RSA-UNSAFE-IMPL-SEND`, `RSA-UNSAFE-IMPL-SYNC`, `RSA-FFI-EXTERN-C`, `RSA-FFI-CSTR-FROM-PTR`, `RSA-UNSAFE-TRANSMUTE`, `RSA-UNSAFE-MAYBEUNINIT`, `RSA-UNSAFE-FROM-RAW-PARTS`, `RSA-UNSAFE-SET-LEN`, `RSA-UNSAFE-BOX-FROM-RAW`, `RSA-UNSAFE-GET-UNCHECKED`, `RSA-UNSAFE-UNCHECKED-CALL`, `RSA-UNSAFE-STATIC-MUT`, `RSA-UNSAFE-RAW-PTR-ACCESS`

**Supply chain and build** — `RSA-DEP-GIT`, `RSA-DEP-PATH`, `RSA-DEP-PROC-MACRO`, `RSA-DEP-BUILD-DEPENDENCIES`, `RSA-DEP-LOCK-GIT`, `RSA-DEP-VERSION-UNBOUNDED`, `RSA-BUILD-SCRIPT`, `RSA-BUILD-COMMAND`, `RSA-CARGO-SOURCE-REPLACEMENT`, `RSA-CARGO-RUNNER`

**Runtime execution** — `RSA-EXEC-COMMAND`

Every finding carries a rule id, file and line, evidence, why it matters, a concrete risk scenario, and a suggested fix. Findings are deduplicated by `file + startLine + ruleId` and sorted by severity, then confidence, then location.

The scanner tracks Rust comment and literal boundaries, so a pattern inside a block comment, doc example, or string literal is not reported. Findings inside `#[cfg(test)]` code are reported at reduced severity, because test code does not ship.

**Confidence means pattern-detection confidence, not exploitability.** A high-confidence finding says the pattern is definitely there, not that a vulnerability is confirmed.

### Scan scope

A broad audit reads what Cargo actually builds: each crate's `src/`, plus `build.rs`. It skips test, benchmark, and example targets, and skips `.rs` files that no Cargo target reaches at all — sample input, vendored snapshots, scratch material. Code that is never compiled cannot carry runtime risk, and scanning it buries the findings that matter.

The skip is never silent. Every report states how many files were left out and why:

```
Excluded 18 Rust file(s) from source scanning: 18 file(s) no Cargo target reaches.
Set includeNonShippedSources to include them.
```

Pass `includeNonShippedSources: true` to `rust_audit_project` to include them. `rust_review_current_diff` never applies this filter — if you changed a test target, you changed it on purpose, so it is reviewed.

## What it can and cannot tell you

**It can tell you** where a crate's unsafe and FFI surface is and what obligations each site carries; what a specific change introduced, and which pre-existing code is close enough to matter; where build-time and supply-chain trust boundaries sit — build scripts, git and path dependencies, proc macros, registry replacement, custom target runners; and which risks someone already accepted, including the acceptances that have expired.

**It cannot tell you** whether a particular `unsafe` block is actually unsound. It points at the places where memory safety depends on an invariant a compiler is not checking, and hands you the evidence and the question. Proving the invariant is still your job, or your reviewer's.

### Known limitations

- **No known-vulnerability check.** There is no [RustSec advisory](https://rustsec.org) or CVE lookup, so it will never tell you a dependency version has a published advisory. Run `cargo audit` or `cargo deny` alongside it. ([tracked in the roadmap](ROADMAP.md))
- **Patterns with lexical context, not semantic analysis.** There is no AST, type information, data flow, or taint tracking. It knows a line is code rather than a comment or a string, and it knows which function and unsafe block a line sits in. It does not know where a pointer came from.
- **Risk level tracks volume and severity, not exploitability.** A crate that uses `unsafe` deliberately — SIMD, allocators, FFI bindings — will read `high_risk` because it has many findings, not because it is dangerous. memchr reports 374 findings in real source; memchr is fine. Read the findings, not the label.
- **A reviewed, documented unsafe block is still reported.** A nearby `SAFETY:` comment lowers the confidence but does not remove the finding, because the tool cannot check whether the comment is true. That is what accepted-risk suppressions are for.
- **A bare `#[tokio::test]` counts as production code** unless it sits inside a `#[cfg(test)]` module. Only Rust's own `#[test]` and a `cfg` that definitely requires `test` lower a finding's severity — any other attribute path could be a macro that compiles in a release build.
- **Dependency review reads manifests, not the resolved graph.** It inspects `Cargo.toml`, `Cargo.lock`, `build.rs`, and `.cargo/config.toml`. It does not resolve transitive dependencies, check for yanked crates, or evaluate feature unification.
- Not formal verification, symbolic execution, or a replacement for human review of unsafe invariants.
- Not a hosted service, SaaS scanner, or uploaded-code scanner. It reads local paths only.
- Not a generic code review or style tool.

## Install

Requires Node.js 20 or newer. No Rust toolchain needed — the scanner reads source and manifests, it does not build your project.

### Primary path: local checkout

Clone, install dependencies, and build once:

```bash
git clone https://github.com/lihytaihe-lang/rust-security-auditor.git
cd rust-security-auditor
npm ci
npm run build
```

Point the MCP client directly at that checkout's built server. Its standard input and output are reserved for JSON-RPC; logs go to stderr.

```json
{
  "command": "node",
  "args": ["/absolute/path/to/rust-security-auditor/dist/src/mcp/server.js"]
}
```

Pass the Rust project as the tool's absolute `projectPath`; the server process does not need to run from that project directory.

### Client configuration

The server speaks plain stdio MCP, so the block below is the same everywhere; only the file it goes in differs. CI exercises the stdio boundary itself — handshake, `tools/list`, and a real `tools/call` — on Linux, macOS, and Windows. The per-client formats below come from each vendor's documentation and have not been run through every host UI, so if one of them has changed, check that vendor's docs.

Claude Desktop is the exception worth calling out: its current flow expects a Desktop Extension, and this project does not ship an `.mcpb`, so there is no Desktop-specific setup to give you yet.

**Claude Code**

```bash
claude mcp add --transport stdio rust-security-auditor -- node /absolute/path/to/rust-security-auditor/dist/src/mcp/server.js
```

**Codex CLI, app, and IDE extension**

```toml
# ~/.codex/config.toml or a trusted project's .codex/config.toml
[mcp_servers.rust_security_auditor]
command = "node"
args = ["/absolute/path/to/rust-security-auditor/dist/src/mcp/server.js"]
```

The equivalent Codex CLI command is:

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

Put the Cursor block in `.cursor/mcp.json` for a project or `~/.cursor/mcp.json` for a user configuration.

**VS Code/Copilot**

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

Put the VS Code block in `.vscode/mcp.json` or in the user `mcp.json` opened by **MCP: Open User Configuration**.

**Qoder, ZCode, and Kimi Code** take the same `mcpServers` block as Cursor — only the file differs:

| Host | Where the block goes |
| --- | --- |
| [Qoder](https://docs.qoder.com/user-guide/chat/model-context-protocol) | MCP settings → **+ Add** opens a JSON editor; paste the block and save |
| [ZCode](https://zcode.z.ai/en/docs/mcp-services) | `.zcode/config.json` — it can also import an existing Claude Code MCP config |
| [Kimi Code CLI](https://moonshotai.github.io/kimi-code/en/customization/mcp.html) | `~/.kimi-code/mcp.json`, or the project-local `.kimi-code/mcp.json`; `/mcp-config` adds it conversationally |

Host formats and configuration locations change independently, so recheck the [Claude Code docs](https://code.claude.com/docs/en/mcp), [Claude Desktop docs](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop), [Codex MCP docs](https://learn.chatgpt.com/docs/extend/mcp), [Cursor MCP docs](https://docs.cursor.com/context/model-context-protocol), [VS Code MCP reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration), and each vendor's page linked above before use.

Machine-readable versions of these blocks live in [`examples/mcp-client-config.json`](examples/mcp-client-config.json) and [`examples/codex-plugin-config.json`](examples/codex-plugin-config.json).

### npm

Not published yet. Once it is, `npx --yes rust-security-auditor` replaces the whole clone-and-build step. The packaging is already in place and CI verifies it on every run — `npm run verify:package` builds a tarball, installs it fresh, and completes an MCP handshake through the installed binary — so that path is ready when the release happens.

For debugging a checkout without a client, `npm --silent run mcp` rebuilds and launches in one step.

## Using it

Once the server is configured, you talk to your agent normally. It picks the tool and passes your project path; you read the findings. Three situations cover almost everything.

**Taking over a codebase, or evaluating one.** Ask for a full audit and give it the project path:

> Audit /path/to/my-rust-project for security risk.

You get an overall risk level, counts by severity and rule, the top findings, grouped review signals, and which areas deserve attention first. Start here when the code is new to you, when you are deciding whether to depend on a crate, or before a release.

**Before a commit, especially right after generating code.** With the project already open, just ask:

> Review my current changes before I commit.

You get a `block` / `needs_attention` / `pass` decision, what this change introduced, and any pre-existing code close enough to matter. This is the one to run every time — it stays quiet when a change is clean, so it costs nothing to keep in the loop.

**Before a release, on the risks you already accepted.** Suppressions carry an owner, a ticket, and an expiry date:

> List the accepted risks and show me anything expired.

### Reading a finding

Every finding answers four questions, so you can decide without opening the rule source: what was found and where, the evidence line, why it matters and what could go wrong, and a suggested fix. From there:

- **It is a real problem** — fix it. The suggested fix and suggested tests are a starting point, not a verdict.
- **It is fine and you can say why** — record that decision in the code rather than ignoring the finding:

  ```rust
  // rust-security-auditor: ignore RSA-UNSAFE-BLOCK owner=@you ticket=SEC-123 until=2026-12-31 -- pointer is validated by the caller, reviewed in PR #42
  unsafe { *ptr }
  ```

  The reason is required. It expires, and an expired acceptance comes back into the report — so this is an audit trail, not a mute button.
- **The tool is wrong** — that is a bug worth reporting. Open a [false positive issue](https://github.com/lihytaihe-lang/rust-security-auditor/issues/new?template=false-positive.yml) with the minimal snippet.

A `high_risk` label on a crate that uses `unsafe` deliberately means "many findings", not "dangerous". Read the findings.

## The Five Tools

| Tool | Use it for |
| --- | --- |
| `rust_review_current_diff` | What did this change introduce? Run before commit or PR, and after agent-generated code. |
| `rust_audit_unsafe` | Unsafe blocks and functions, FFI boundaries, raw-memory primitives, unsafe Send/Sync. |
| `rust_audit_dependencies` | Cargo manifests, lockfiles, build scripts, git/path deps, proc macros, `.cargo/config.toml`. |
| `rust_audit_project` | The broad local scan across every rule. |
| `rust_list_accepted_risks` | Inventory of accepted-risk suppression comments, including expired and invalid ones. |

Ask for them in plain language — `review current diff before I commit`, `audit unsafe`, `check dependencies`, `list accepted risks` — or call them directly:

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

Every tool takes `projectPath`, `outputFormat` (`markdown` | `json`), `pathMode` (`relative` | `absolute`), and `reportMode` (`compact` | `full`). Defaults are `relative` and `compact`, which keeps local absolute paths out of anything you paste into a PR.

Sanitized example outputs for each tool live in [`examples/reports/`](examples/reports).

## Current Diff Review

`rust_review_current_diff` reviews the working tree by default, `git diff --cached` with `staged: true`, and `baseRef..headRef` when both refs are given.

Each finding is classified by its relationship to the change:

| Relation | Meaning |
| --- | --- |
| `introduced_by_diff` | Starts on an added line. |
| `same_unsafe_site_context` | Pre-existing, but in the same unsafe block as an added line. |
| `same_function_context` | Pre-existing, in the same function, different unsafe site. |
| `nearby_legacy_context` | Line-near an added line, but in a different function or unsafe site. |
| `unrelated_nearby` | Line-near an added line with no confirmed tie. |
| `pre_existing_in_changed_file` | In a changed file, outside the changed-line window. |

Compact output shows `introduced_by_diff`, `same_unsafe_site_context`, and medium-or-higher `same_function_context` at medium/high confidence. Legacy nearby context is hidden so that old unsafe code in a different function does not look like a new blocker — use `reportMode: "full"` to see it, and `includePreExisting: true` to include historical findings in changed files. Lower `nearChangedLineWindow` to 1 or 2 if nearby findings are still noisy.

The tool also returns a `reviewDecision`:

- `block` — introduced critical/high findings with non-low confidence.
- `needs_attention` — introduced medium findings, directly relevant same-site or same-function context, low-confidence introduced findings, or expired/invalid suppressions.
- `pass` — nothing blocking or needing manual review.

The decision is driven by `introduced_by_diff`. Same-site high findings need attention but do not hard-block; `nearby_legacy_context` and `unrelated_nearby` never affect it unless you ask for pre-existing findings.

## Accepted Risk Suppressions

Suppressions are records of reviewed false positives or deliberately accepted risk — not a way to hide unresolved blockers.

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

- The reason after `--` is required, and `RULE_ID` must be an exact rule id.
- `ignore all` and `ignore *` are not supported.
- Expired suppressions are reported again; invalid ones are ignored and listed for cleanup.
- The older `rustsec-auditor:` marker still works but is deprecated — it collides with the unrelated [RustSec](https://rustsec.org) project. Rename existing comments to `rust-security-auditor:`; the scanner warns when it sees the old form.

Use `rust_list_accepted_risks` to inventory active, expired, and invalid suppressions without running the full scanner. Its JSON and Markdown output include scan coverage; treat an incomplete inventory as partial rather than as proof that no accepted risks exist.

## Report Modes

`compact` (default) is built for agent summaries and PR comments: overall risk, severity and rule counts, top findings, grouped review signals, high-priority areas, and suggested follow-up prompts. The JSON `findings` array always stays complete.

`full` preserves every per-finding detail — evidence, why it matters, risk scenario, suggested fix, suggested tests, references, false-positive notes, and suppression records. Use it for audit notes, handoff archives, and suppression review.

When several findings point at one unsafe site, Markdown groups them under that site. This is display only; the JSON is unchanged.

## Development

```bash
npm ci
npm run typecheck
npm test
npm run check      # typecheck + test + whitespace
```

For local debugging without an MCP client:

```bash
npm run mcp:call -- rust_audit_project --projectPath test/fixtures/vulnerable-rust-project --outputFormat markdown
npm run mcp:call -- rust_review_current_diff --projectPath /absolute/path/to/rust/project --staged true
```

Build output goes to `dist/` and is git-ignored. Adding a rule is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Source layout:

| Path | Contents |
| --- | --- |
| `src/mcp/server.ts` | Local stdio MCP server |
| `src/mcp/tools.ts` | Tool handlers backed by the scanner kernel |
| `src/scanners/rustLexer.ts` | Comment/literal masking and test-code detection |
| `src/scanners/unsafeScanner.ts` | Unsafe, FFI, and raw-memory rules |
| `src/scanners/dependencyScanner.ts` | Cargo manifest, lockfile, build script, and cargo config rules |
| `src/scanners/sourceRiskScanner.ts` | Runtime process execution |
| `src/scanners/rules.ts` | Rule metadata: severity, rationale, remediation |
| `src/scanners/suppressions.ts` | Suppression parsing and expiry |
| `src/git/diffParser.ts` | Unified diff parser |
| `src/reports/` | Markdown and JSON renderers, finding schema |

## Security Model

The server validates that `projectPath` exists and is a local directory, scans only within it, filters git diff paths to safe relative paths, refuses git refs that could be read as flags, and runs `git` without a shell. It does not upload code, package source bundles, or contact any network service.

Discovery skips `.git`, `target`, `node_modules`, and similar directories, does not follow symbolic links, verifies a directory again immediately after opening it, and caps per-file size, file count, directory count, total bytes, and read concurrency. Before returning source bytes, the reader verifies canonical containment, rejects symbolic-link components, checks that the pathname still resolves to the opened file, and limits the read to that descriptor's verified size. Coverage is monotonic within a tool call: optional context extraction cannot turn an incomplete changed input into complete coverage. Malformed Rust lexical input disables test-only severity reductions and marks coverage incomplete. Coverage is structured in JSON and Markdown; a current diff with an incomplete Rust/Cargo input fails closed as `needs_attention` with `safeToCommit: false`.

See [SECURITY.md](SECURITY.md) for reporting a vulnerability in this tool and for what is in and out of scope.

## Status

Apache-2.0. The latest release is [v0.1.3](https://github.com/lihytaihe-lang/rust-security-auditor/releases/tag/v0.1.3); not on npm yet. [ROADMAP.md](ROADMAP.md) covers what is planned and what is deliberately out of scope.
