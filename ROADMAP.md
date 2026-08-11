# Roadmap

## Current Stage Alignment

Current stage as of 2026-08-11: v0.1.2 is a local-first MCP preview distributed on npm. Stage 2.3 repository-side hosted MCP validation was completed, but Stage 2.4 and any Codex plugin / ChatGPT App publication path remain deferred.

Historical stage tracking lives in `docs/internal/STAGE2_PROGRESS.md`.

## Public Preview Boundary

This public release is a local stdio MCP preview, not a Codex plugin publication effort or ChatGPT App release candidate.

It deliberately excludes:

- Codex plugin packaging and marketplace distribution.
- A hosted ChatGPT App, SaaS scanning, or persistent service.
- Private repository connection, source upload, or any API credential collection.
- Claims of full static analysis, formal verification, or automatic remediation.

Future hosted or private-code work needs its own product, privacy, security, and maintenance decision. It is not implied by this open-source release.

## Shipped

- Local stdio MCP server for Claude Code, Codex, and other MCP clients, installable with `npx`.
- Five read-only MCP tools.
- Heuristic Rust security scanner kernel with comment and literal awareness.
- Unsafe/FFI review, Cargo dependency, build-script, and `.cargo/config.toml` review.
- Changed-line-aware current diff review with review decisions.
- Accepted-risk suppression workflow and inventory.
- Markdown and JSON report output in compact and full modes.
- Documentation, sanitized examples, cross-platform CI, and contribution/security guidance.

## Current Focus

- Precision over coverage: fewer false positives per rule, clear evidence per finding.
- Low-noise review workflows before commit, before PR, after agent-generated code, and before release.
- Keeping example reports in `examples/reports/` regenerable via `npm run examples:regenerate`.

## Stage 2 Hosted MCP Alignment

- Stage 2.0 is complete: the hosted MCP / ChatGPT App prototype design exists in `docs/internal/STAGE2_HOSTED_MCP_DESIGN.md`.
- Stage 2.1 was merged into the design baseline: official-docs research and architecture confirmation are recorded in the design document.
- Stage 2.2 was merged into Stage 2.3: the hosted transport spike exists, but the practical milestone is now repository-side hosted MCP validation.
- Stage 2.3 is complete for repository-side validation:
  - fixture-safe Hosted MCP prototype
  - `scripts/smoke_hosted_mcp.ts`
  - local hosted `/mcp` smoke path
  - temporary HTTPS tunnel smoke evidence
  - fixture-safe sample outputs
  - ChatGPT App submission pack skeleton
- Stage 2.4 is blocked, not complete: retry is needed in a ChatGPT account, organization, or session where the Developer Mode connector creation entry is visible.

Stage 2.3 completion does not mean hosted deployment, ChatGPT App UI, OpenAI submission, private GitHub access, or private repository scanning.

## Next

- **Known-vulnerability coverage.** The scanner has no RustSec advisory or CVE lookup today, which is the most common expectation the project name sets. The intended shape is an optional integration: detect a local `cargo-audit` or `cargo-deny` installation, run it, and map its results into the existing `Finding` schema so advisories appear alongside heuristic findings; degrade with a clear message when neither tool is installed. Bundling or fetching the advisory database is explicitly not planned — that would turn a local, offline, read-only tool into something that needs network access and database maintenance.
- Cargo profile and lint review, such as `panic = "abort"` at an FFI boundary and `overflow-checks = false` in release.
- Reporting `#![forbid(unsafe_code)]` as a positive signal rather than staying silent.

## Deferred Work

- Stage 2 hosted MCP / ChatGPT App prototype path:
  - v0.1.x local MCP preview.
  - Stage 2.4 ChatGPT Developer Mode demo validation.
  - Future v0.2.0 hosted MCP prototype packaging, if the validation pass is accepted.
  - Future ChatGPT App submission preparation, after a real connector validation pass.
- AST-aware Rust parsing.
- Deeper unsafe invariant analysis.
- Release audit report output.
- Codex plugin packaging.
- ChatGPT App UI later, not in the local preview.

These items are intentionally deferred by the public-preview boundary above.

## Non-Goals For This Preview

- SaaS hosting.
- Uploaded code package scanning.
- Generic code review.
- Large new scanner rule families.
- Formal verification or full data-flow/taint analysis.
- Private GitHub access during Stage 2.3.
- OpenAI app submission during Stage 2.3.
- ChatGPT App UI component during Stage 2.3.
