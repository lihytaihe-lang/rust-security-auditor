# Rust Security Audit

## Decision / Risk Level

- riskLevel: high_risk
- findingCount: 21
- High/medium/low: 1/19/1
- Critical/info: 0/0
- Suppressed findings: 0
- Scope: .
- Confidence: pattern-detection confidence, not exploitability confidence

## Top Findings

- High RSA-BUILD-COMMAND at `build.rs:4`: Build script spawns an external command (command-execution review signal, high pattern-detection confidence)
- Medium RSA-BUILD-SCRIPT at `build.rs:1`: Build script runs code during cargo build (supply-chain review signal, high pattern-detection confidence)
- Medium RSA-DEP-LOCK-GIT at `Cargo.lock:7`: Cargo.lock resolves a git-sourced package (supply-chain review signal, high pattern-detection confidence)
- Medium RSA-DEP-GIT at `Cargo.toml:13`: Git dependency requires supply-chain review (supply-chain review signal, high pattern-detection confidence)
- Medium RSA-DEP-PROC-MACRO at `Cargo.toml:17`: Proc-macro crate executes code during compilation (supply-chain review signal, high pattern-detection confidence)
- 15 additional medium finding(s) hidden from compact output.
- 1 low/info finding(s) hidden by default.

## Grouped Findings

### unsafe

- RSA-UNSAFE-BLOCK: 5
- RSA-UNSAFE-FN: 2
- RSA-UNSAFE-BOX-FROM-RAW: 1
- RSA-UNSAFE-FROM-RAW-PARTS: 1
- RSA-UNSAFE-MAYBEUNINIT: 1
- RSA-UNSAFE-SET-LEN: 1
- RSA-UNSAFE-TRANSMUTE: 1

### FFI

- RSA-FFI-EXTERN-C: 1

### dependency

- Workspace-local path dependencies: 1 item (low-priority trust-boundary signal; JSON and full Markdown keep each item).

### supply-chain

- RSA-BUILD-SCRIPT: 1
- RSA-DEP-GIT: 1
- RSA-DEP-LOCK-GIT: 1
- RSA-DEP-PROC-MACRO: 1

### command-execution

- RSA-BUILD-COMMAND: 1

### concurrency

- RSA-UNSAFE-IMPL-SEND: 1
- RSA-UNSAFE-IMPL-SYNC: 1

## High-Priority Areas

- Build scripts / command execution: 1
- Unsafe / FFI / concurrency: 15
- Dependencies / supply-chain review signals: 5
- Workspace-local path dependencies: 1 low-priority trust-boundary signal

## Recommended Next Actions

- Review or fix high/critical review signals first, especially build-time command execution.
- Manually review unsafe and FFI sites for pointer, aliasing, ownership, and unwind invariants.
- Audit `build.rs` and build-time dependency trust-boundary signals before release handoff.
- Review accepted risks with `rust_list_accepted_risks` when suppressions are present.
- Suggested next audits: `rust_audit_unsafe`, `rust_audit_dependencies`, `rust_review_current_diff`, `rust_list_accepted_risks`.

## Suggested Codex Review Prompts

- Run `rust_audit_unsafe` for this project and group unsafe findings by function/site; review pointer validity, aliasing, ownership transfer, Send/Sync invariants, and FFI boundaries.
- Run `rust_audit_dependencies` and review build.rs command execution, git/path dependencies, build dependencies, and proc-macro trust boundaries.
- Review the top project audit findings and propose the smallest safe fixes for high severity items before broader refactors.

## Hidden Details

Compact mode keeps the JSON findings complete but hides most per-finding evidence, why-it-matters text, suggested fixes, suggested tests, and low/info details from Markdown. Use `reportMode: "full"` to inspect all 21 finding detail block(s).

## Limitations

- Heuristic static review, not a release gate or formal security proof.
- Confidence values mean pattern-detection confidence, not exploitability confidence.
- Non-diff audits are not changed-line aware; use `rust_review_current_diff` for commit/PR focus.
- Findings are review signals and can require human confirmation before code changes.
