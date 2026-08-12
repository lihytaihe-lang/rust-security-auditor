# Roadmap

## Current Stage Alignment

Current stage as of 2026-08-11: local technical readiness work is in progress for v0.1.2 metadata. npm publication, Git tags/releases, and registry facts are **HOLD** until the owner verifies them from authoritative sources.

Historical stage tracking lives in `docs/internal/STAGE2_PROGRESS.md`.

## Public Preview Boundary

This public preview is a local stdio MCP package, not a Codex plugin publication effort or ChatGPT App release candidate.

It deliberately excludes:

- Codex plugin packaging and marketplace distribution.
- A hosted ChatGPT App, SaaS scanning, or persistent service.
- Private repository connection, source upload, or any API credential collection.
- Claims of full static analysis, formal verification, or automatic remediation.

Future hosted or private-code work needs its own product, privacy, security, and maintenance decision. It is not implied by this open-source release.

## Shipped

- Local stdio MCP server with client-configuration references. A host is only called supported after host/version/OS end-to-end evidence exists.
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

## Hosted and app boundary

Hosted MCP, HTTP transport, ChatGPT Apps, SaaS scanning, source upload, private-repository connection, telemetry, accounts, and marketplaces are outside the v0.1.x package. The prior hosted experiment is not part of this build or npm tarball. Any future hosted product needs a separate threat model, privacy design, owner authorization, and release plan.

## Next

- **Known-vulnerability coverage.** The scanner has no RustSec advisory or CVE lookup today, which is the most common expectation the project name sets. The intended shape is an optional integration: detect a local `cargo-audit` or `cargo-deny` installation, run it, and map its results into the existing `Finding` schema so advisories appear alongside heuristic findings; degrade with a clear message when neither tool is installed. Bundling or fetching the advisory database is explicitly not planned — that would turn a local, offline, read-only tool into something that needs network access and database maintenance.
- Cargo profile and lint review, such as `panic = "abort"` at an FFI boundary and `overflow-checks = false` in release.
- Reporting `#![forbid(unsafe_code)]` as a positive signal rather than staying silent.

## Deferred Work

- AST-aware Rust parsing.
- Deeper unsafe invariant analysis.
- Release audit report output.
- Codex plugin packaging.
- Host-specific MCP end-to-end evidence, after each host is verified against its official documentation and a real runtime.

These items are intentionally deferred by the public-preview boundary above.

## Non-Goals For This Preview

- SaaS hosting.
- Uploaded code package scanning.
- Generic code review.
- Large new scanner rule families.
- Formal verification or full data-flow/taint analysis.
