# Roadmap

## v0.1 Local MCP Preview

- Local stdio MCP server for Codex and other MCP clients.
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

## Future Work

- AST-aware Rust parsing.
- Deeper unsafe invariant analysis.
- Release audit report output.
- Codex plugin packaging.
- ChatGPT App later, not now.

## Non-Goals For This Preview

- SaaS hosting.
- Uploaded code package scanning.
- Generic code review.
- Large new scanner rule families.
- Formal verification or full data-flow/taint analysis.
