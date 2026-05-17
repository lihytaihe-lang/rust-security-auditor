# Real Project Dogfood: Rust Downloader

Date: 2026-05-18

This dogfood run used Rust Security Auditor v0.1.0 against a local Rust downloader project. The run stayed local and read-only: no Rust Security Auditor core code was changed, no downloader code was changed, no code was uploaded, and no ChatGPT App work was performed.

The first similarly named local directory contained planning documents only. The Cargo workspace used for the test was the nested `Prj_rust_downloader` checkout, referred to below as `<rust-downloader>` to avoid recording private absolute paths.

## Invocation

The current built debug helper was used directly:

```bash
node dist/src/mcp/debug.js <tool> --projectPath <rust-downloader> --outputFormat json --pathMode relative --reportMode compact
node dist/src/mcp/debug.js <tool> --projectPath <rust-downloader> --outputFormat markdown --pathMode relative --reportMode compact
```

`rust_review_current_diff` was run because `<rust-downloader>` had an uncommitted working-tree diff.

## Project Signals

- Rust workspace: yes
- Uncommitted diff: yes, 7 files changed
- Unsafe: yes, 3 unsafe blocks in the macOS UI bridge
- FFI: no scanner findings; the unsafe sites are Objective-C/AppKit bridge code but were not reported as FFI
- `build.rs`: yes, 1 build script
- Git dependencies: no
- Path dependencies: yes, 9 workspace path dependency findings
- Proc macros: no
- Build dependencies: yes, 1 build-dependency section
- `build.rs` command execution: no
- Accepted risk suppressions: no

## Tool Results

| Tool | Result | Findings | High / Medium / Low | Notes |
| --- | --- | ---: | --- | --- |
| `rust_audit_project` | `needs_attention` | 14 | 0 / 5 / 9 | Broad scan surfaced 3 unsafe findings, 9 path dependency findings, and 2 supply-chain findings. |
| `rust_audit_unsafe` | `needs_attention` | 3 | 0 / 3 / 0 | All findings were generic unsafe-block review sites in `crates/app_ui/src/main.rs`. No unsafe fn, unsafe Send/Sync, raw-memory primitive, or FFI finding was reported. |
| `rust_audit_dependencies` | `needs_attention` | 11 | 0 / 2 / 9 | Reported 1 build script, 1 build-dependency section, and 9 path dependencies. No git dependency, lockfile git source, proc macro, or build-script command execution was reported. |
| `rust_review_current_diff` | `pass` | 0 visible | 0 / 0 / 0 | Safe to commit according to the tool. The diff touched 7 files and had 3 hidden pre-existing findings, but no introduced or related security findings. |
| `rust_list_accepted_risks` | inventory only | 0 records | n/a | No active, expired, or invalid accepted-risk suppressions were found. |

## Report Quality

The compact reports are much better suited to ChatGPT/Codex presentation than the full finding JSON. They lead with risk level, counts, grouped findings, and suggested next prompts, while keeping complete findings in JSON for drill-down.

Noise level is acceptable in compact mode, but not zero. The main noisy area is path dependencies: all 9 path dependency findings appear to be normal intra-workspace crate links. They are legitimate supply-chain review clues, but in a Cargo workspace they should probably be grouped as one low-priority workspace trust-boundary item rather than counted as 9 separate user-facing findings.

The unsafe findings are useful. They point to macOS Objective-C/AppKit integration where local invariants matter. The code already contains safety comments, so these are not obvious vulnerabilities, but they are real manual-review targets and appropriate for a security-focused Rust audit.

The build-script finding is true but low drama. The build script appears to compile UI assets through the build dependency rather than shell out. The report correctly showed no command execution. This is a good review prompt, not a blocker.

No obvious false positives were found in the sense of "the signal does not exist." The bigger issue is framing: path dependencies and documented unsafe blocks are real signals, but they need wording that makes clear they are review cues, not proven vulnerabilities.

## Compact Report Fit

Compact Markdown is suitable for ChatGPT users. The reports are short:

- `rust_audit_project`: 65 lines
- `rust_audit_unsafe`: 64 lines
- `rust_audit_dependencies`: 53 lines
- `rust_review_current_diff`: 54 lines
- `rust_list_accepted_risks`: 30 lines

For a ChatGPT App or Codex Plugin experience, the best default flow would be:

1. Run `rust_review_current_diff` first for day-to-day work.
2. Offer `rust_audit_unsafe` and `rust_audit_dependencies` as focused follow-ups.
3. Use `rust_audit_project` as a broader checkpoint, not as the first screen for every user.
4. Always keep path display relative or sanitized before showing shareable output.

## Real Value Found

The tool was useful on a real project because it quickly identified the security-relevant shape of the codebase:

- macOS unsafe bridge code exists and deserves explicit invariant review.
- build-time code exists, but no build-script command execution was detected.
- dependency review should focus on local workspace boundaries and build dependencies, not git dependency provenance.
- the current working-tree diff did not introduce new findings, which is exactly the kind of answer a developer wants before commit.

The strongest product signal is that diff review produced a clear PASS while the broader audits still exposed the existing review surface. That maps well to an assistant workflow: "your current change is clean; here are existing areas worth reviewing later."

## Biggest Issue

The largest issue for demo quality is severity and grouping, not scanner correctness. A real workspace with normal path dependencies can look busier than it is. Before a hosted or ChatGPT-facing demo, workspace-local path dependencies should be grouped or labeled more softly so the user does not read them as nine separate dependency problems.

A secondary issue is domain coverage. For a downloader, many important risks live in URL handling, filesystem boundaries, redirects, content validation, and cache cleanup. Rust Security Auditor v0.1.0 intentionally focuses on unsafe, FFI, dependencies, build scripts, and diff-aware security clues. That scope is useful, but it should not be presented as a complete downloader security audit.

## Demo Case Recommendation

This project is suitable as a ChatGPT App / Codex Plugin demo case if the demo goal is realistic local security triage:

- It has real unsafe code without being obviously broken.
- It has build-time trust-boundary signals.
- It has a non-trivial working-tree diff where current-diff review can pass cleanly.
- The compact reports are short enough for conversational presentation.

It is less suitable if the demo needs a dramatic high-severity vulnerability. The best demo story is practical and honest: changed-line-aware review plus focused follow-up audits.

## Hosted MCP Prototype Recommendation

Proceed toward a Hosted MCP Prototype after one small local polish pass:

- group workspace-local path dependencies in compact output;
- keep report scopes sanitized by default for shareable Markdown;
- tune wording so "high confidence" is clearly pattern confidence, not exploitability confidence;
- preserve `rust_review_current_diff` as the primary ChatGPT/Codex entry point.

With those adjustments, the core MCP capability looks useful enough to justify a hosted prototype.
