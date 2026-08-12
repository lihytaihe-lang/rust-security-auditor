# Roadmap

## Shipped

Released as [v0.1.3](https://github.com/lihytaihe-lang/rust-security-auditor/releases/tag/v0.1.3).

- Local stdio MCP server with five read-only tools, and configuration references for the common MCP clients.
- Heuristic Rust scanner with comment and literal awareness: 25 rules across unsafe/FFI, Cargo dependency and build-script review, `.cargo/config.toml`, and runtime process execution.
- Whole-project audits scoped to the code Cargo builds, with every exclusion reported.
- Changed-line-aware current diff review with `block` / `needs_attention` / `pass` decisions.
- Accepted-risk suppressions carrying an owner, ticket, and expiry, plus an inventory tool.
- Markdown and JSON output in compact and full modes.
- Cross-platform CI on Node 20/22/24 across Linux, macOS, and Windows, plus CodeQL and a real package-install check.

## Next

- **Known-vulnerability coverage.** There is no RustSec advisory or CVE lookup today, which is the most common expectation the project name sets. The intended shape is an optional integration: detect a local `cargo-audit` or `cargo-deny` installation, run it, and map its results into the existing `Finding` schema so advisories appear alongside heuristic findings; degrade with a clear message when neither is installed. Bundling or fetching the advisory database is explicitly not planned — that would turn a local, offline, read-only tool into one that needs network access and database maintenance.
- **Risk level that reflects exploitability, not volume.** A crate that uses `unsafe` deliberately reads `high_risk` because it has many findings. The label is currently misleading on exactly the crates most worth auditing.
- npm publication, so installation is one command instead of a clone and build.
- Cargo profile and lint review, such as `panic = "abort"` at an FFI boundary and `overflow-checks = false` in release.
- Reporting `#![forbid(unsafe_code)]` as a positive signal rather than staying silent.

## Deferred

- AST-aware Rust parsing and deeper unsafe invariant analysis. Today's rules are patterns with lexical context; going further means a real parser and a different cost model.
- A dedicated release audit report.
- Per-host end-to-end verification. Client configuration is documented from vendor docs; a host is only described as verified once there is a real run on a stated host version and OS.

## Out of scope

These are not "not yet" — they are deliberate boundaries for the project.

- Hosted or SaaS scanning, HTTP transport, source upload, private-repository connection, telemetry, or accounts. Everything runs locally and reads only local paths. Any future hosted product would need its own threat model, privacy design, and release plan, and is not implied by this one.
- Generic code review or style checking.
- Formal verification, symbolic execution, or full data-flow and taint analysis.
- Automatic remediation. Findings carry a suggested fix; applying it is a human decision.
