# Public Preview Checklist

Date: 2026-05-18

This checklist captures the Phase 15 public preview readiness review for the local Rust Security Auditor MCP server. The review stayed within documentation, examples, CI, packaging metadata, and release hygiene. It did not add scanner rules, deep-audit behavior, release gates, ChatGPT App behavior, SaaS/upload flows, or MCP server rewrites.

## Passed

- README first screen explains that Rust Security Auditor is a local MCP server for focused Rust security review in Codex and MCP clients.
- README explicitly says the project is not a SaaS product, not an uploaded code package scanner, not a ChatGPT App, not a generic code review tool, and not formal verification.
- Quickstart includes local install paths for `npm install` and `npm ci`, then `npm run typecheck`, `npm test`, and `npm --silent run mcp`.
- MCP client configuration example uses stdio with `npm --silent run mcp` and an absolute local `cwd`.
- The five MCP tools have example report artifacts under `examples/reports/`:
  - `rust_review_current_diff`
  - `rust_audit_project`
  - `rust_audit_unsafe`
  - `rust_audit_dependencies`
  - `rust_list_accepted_risks`
- JSON example reports parse successfully.
- Example reports and docs were checked for private machine paths, local home/mount prefixes, local usernames, and private project paths.
- Report examples use relative Markdown paths and compact report mode where applicable.
- Skill docs map natural language `@Rust Security Auditor ...` requests to the expected tool names.
- Skill docs and troubleshooting explain compact/full report mode, `pathMode: "relative"`, suppressions, and accepted-risk inventory behavior.
- CI exists at `.github/workflows/ci.yml`, uses `npm ci`, and runs whitespace check, typecheck, and tests without private local paths.
- `package.json` metadata points at the GitHub repository and marks the package as private to avoid accidental npm publishing.
- `npm pack --dry-run` was checked; package files now target `dist/src/` rather than compiled test output.

## Remaining Limits

- The scanner is heuristic static review, not a complete Rust parser, data-flow engine, taint analyzer, symbolic executor, formal proof, release gate, or supply-chain attestation system.
- Dependency audit does not query vulnerability databases; users should run `cargo audit` or equivalent separately.
- Unsafe findings identify review sites and invariants, but they do not prove undefined behavior or prove memory safety.
- Current diff review is changed-line aware, but still uses lightweight text and brace context rather than a full semantic model.
- Suppressions are accepted-risk records for traceability; they are not a mechanism to hide unresolved blockers.

## Release Todo

- Ensure the working tree is clean after Phase 15 changes are committed.
- Push the public preview branch to GitHub.
- Confirm GitHub Actions passes on the pushed commit.
- Create concise release notes that describe local-only MCP usage, compact/full report modes, limitations, and the five tools.
- Tag `v0.1.0` only after CI passes on GitHub.

## Recommended Next Stage

- Phase 16 should focus on public-preview feedback handling: issue templates, small documentation clarifications from first users, and fixture-backed bug fixes.
- Keep the preview scope narrow: no new broad scanner families, no Deep Audit/release gate mode, no SaaS/upload flow, and no ChatGPT App work.
