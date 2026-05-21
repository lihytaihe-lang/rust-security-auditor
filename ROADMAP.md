# Roadmap

## Current Stage Alignment

Current true stage as of 2026-05-18: v0.1.1 remains the active local-first MCP preview, and Stage 2.3 repository-side hosted MCP validation is complete. The next gate is Stage 2.4, a real ChatGPT Developer Mode connection to an HTTPS `/mcp` endpoint.

Detailed progress tracking lives in `docs/STAGE2_PROGRESS.md`.

## v0.1 Local MCP Preview

- Local stdio MCP server for Codex and other MCP clients.
- Five read-only MCP tools.
- Heuristic Rust security scanner kernel.
- Unsafe/FFI review.
- Cargo dependency and build-script review.
- Markdown and JSON report output.
- Local debug helper with `npm run mcp:call`.
- Public preview documentation, examples, CI, and contribution/security guidance.

## Current Preview Focus

- Changed-line-aware current diff review with `rust_review_current_diff`.
- Accepted-risk inventory with `rust_list_accepted_risks`.
- Stable example reports in `examples/reports/`.
- Low-noise local review workflows before commit, before PR, after Codex-generated code, and before accepted-risk review.

## Stage 2 Hosted MCP Alignment

- Stage 2.0 is complete: the hosted MCP / ChatGPT App prototype design exists in `docs/STAGE2_HOSTED_MCP_DESIGN.md`.
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

## Future Work

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

## Non-Goals For This Preview

- SaaS hosting.
- Uploaded code package scanning.
- Generic code review.
- Large new scanner rule families.
- Formal verification or full data-flow/taint analysis.
- Private GitHub access during Stage 2.3.
- OpenAI app submission during Stage 2.3.
- ChatGPT App UI component during Stage 2.3.
