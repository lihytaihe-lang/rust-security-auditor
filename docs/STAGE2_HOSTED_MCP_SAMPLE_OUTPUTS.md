# Stage 2 Hosted MCP Sample Outputs

Date: 2026-05-18

These samples are fixture-safe hosted MCP outputs for the Stage 2.3 connection and submission pack. They use bundled public demo fixtures only. They do not read local project paths, private repositories, repository tokens, or complete private source trees.

The `structuredContent` examples are abbreviated to the stable review-facing fields needed for ChatGPT App review. Full tool responses include the same privacy block, confidence note, findings array, evidence snippets, limitations, and suggested next steps.

## `rust_audit_unsafe`

Input fixture:

```json
{
  "fixture_id": "unsafe_usage"
}
```

Markdown summary:

```markdown
# Rust Unsafe Audit Hosted Demo

## Summary

- Tool: rust_audit_unsafe
- Source: fixture_id=unsafe_usage
- Risk level: needs_attention
- Findings: 9
- Confidence: confidence is pattern-detection confidence, not exploitability confidence

## Findings

- medium RSA-UNSAFE-FN at src/lib.rs:1: Unsafe function requires a caller safety contract. Evidence: Line 1: pub unsafe fn read_byte(ptr: *const u8) -> u8 {
- medium RSA-UNSAFE-BLOCK at src/lib.rs:2: Unsafe block needs local invariant review. Evidence: Line 2: unsafe { *ptr }
```

`structuredContent`:

```json
{
  "tool": "rust_audit_unsafe",
  "sourceKind": "fixture",
  "fixture_id": "unsafe_usage",
  "riskLevel": "needs_attention",
  "summary": {
    "findingCount": 9,
    "suppressedCount": 0,
    "riskLevel": "needs_attention",
    "severityCounts": {
      "medium": 9
    },
    "categoryCounts": {
      "unsafe": 6,
      "ffi": 1,
      "concurrency": 2
    }
  },
  "findings": [
    {
      "id": "RSA-UNSAFE-FN-5D5D0CE5",
      "ruleId": "RSA-UNSAFE-FN",
      "title": "Unsafe function requires a caller safety contract",
      "severity": "medium",
      "confidence": "high",
      "category": "unsafe",
      "file": "src/lib.rs",
      "startLine": 1,
      "evidenceSnippets": [
        "Line 1: pub unsafe fn read_byte(ptr: *const u8) -> u8 {"
      ]
    }
  ],
  "confidenceNote": "confidence is pattern-detection confidence, not exploitability confidence",
  "privacy": {
    "doesNotReadLocalProjects": true,
    "doesNotAcceptPrivateRepoTokens": true,
    "doesNotPersistSource": true
  }
}
```

Limitations:

- Hosted MCP spike only scans bundled demo fixtures or explicitly pasted short snippets.
- It does not read local project paths, private repositories, repository tokens, or absolute paths.
- The scanner is heuristic static pattern detection, not full data-flow analysis, exploitability analysis, formal verification, or a complete security audit.

Suggested next steps:

- Review unsafe blocks and unsafe functions for pointer validity, aliasing, lifetime, ownership, and unwind invariants.
- Document Safety contracts next to each unsafe boundary.
- Use the local stdio MCP tools for real private project or working-tree review.

## `rust_audit_dependencies`

Input fixture:

```json
{
  "fixture_id": "dependency_manifest"
}
```

Markdown summary:

```markdown
# Rust Dependency Audit Hosted Demo

## Summary

- Tool: rust_audit_dependencies
- Source: fixture_id=dependency_manifest
- Risk level: high_risk
- Findings: 6
- Confidence: confidence is pattern-detection confidence, not exploitability confidence

## Findings

- high RSA-BUILD-COMMAND at build.rs:4: Build script spawns an external command. Evidence: Line 4: let _ = Command::new("sh").arg("-c").arg("echo building demo").status();
- medium RSA-BUILD-SCRIPT at build.rs:1: Build script runs code during cargo build. Evidence: Line 1: use std::process::Command;
```

`structuredContent`:

```json
{
  "tool": "rust_audit_dependencies",
  "sourceKind": "fixture",
  "fixture_id": "dependency_manifest",
  "riskLevel": "high_risk",
  "summary": {
    "findingCount": 6,
    "suppressedCount": 0,
    "riskLevel": "high_risk",
    "severityCounts": {
      "low": 1,
      "medium": 4,
      "high": 1
    },
    "categoryCounts": {
      "dependency": 1,
      "supply_chain": 4,
      "command_execution": 1
    }
  },
  "findings": [
    {
      "id": "RSA-BUILD-COMMAND-8C9A005B",
      "ruleId": "RSA-BUILD-COMMAND",
      "title": "Build script spawns an external command",
      "severity": "high",
      "confidence": "high",
      "category": "command_execution",
      "file": "build.rs",
      "startLine": 4,
      "evidenceSnippets": [
        "Line 4: let _ = Command::new(\"sh\").arg(\"-c\").arg(\"echo building demo\").status();"
      ]
    }
  ],
  "confidenceNote": "confidence is pattern-detection confidence, not exploitability confidence",
  "privacy": {
    "doesNotReadLocalProjects": true,
    "doesNotAcceptPrivateRepoTokens": true,
    "doesNotPersistSource": true
  }
}
```

Limitations:

- Hosted dependency review uses fixture or short pasted Cargo/build snippets only.
- It does not query vulnerability databases.
- Dependency manifests can reveal internal architecture in real projects, so private manifests stay on the local stdio MCP path.

Suggested next steps:

- Review git, path, build-dependency, proc-macro, and build.rs trust boundaries.
- Run `cargo audit` or a RustSec-compatible vulnerability database check separately.
- Use absolute tool paths or allowlisted commands in build scripts.

## `rust_list_accepted_risks`

Input fixture:

```json
{
  "fixture_id": "accepted_risk_suppression"
}
```

Markdown summary:

```markdown
# Rust Accepted Risk Inventory Hosted Demo

## Summary

- Tool: rust_list_accepted_risks
- Source: fixture_id=accepted_risk_suppression
- Risk level: needs_attention
- Findings: 3
- Confidence: confidence is pattern-detection confidence, not exploitability confidence

## Findings

- low RSA-UNSAFE-BLOCK at src/lib.rs:2: Accepted risk suppression. Evidence: // rustsec-auditor: ignore RSA-UNSAFE-BLOCK owner=@security ticket=SEC-101 until=2099-01-01 -- legacy FFI shim accepted for hosted demo
- medium RSA-UNSAFE-BLOCK at src/lib.rs:7: Expired accepted risk suppression. Evidence: // rustsec-auditor: ignore RSA-UNSAFE-BLOCK owner=@security ticket=SEC-102 until=2000-01-01 -- old acceptance that should be revisited
```

`structuredContent`:

```json
{
  "tool": "rust_list_accepted_risks",
  "sourceKind": "fixture",
  "fixture_id": "accepted_risk_suppression",
  "riskLevel": "needs_attention",
  "summary": {
    "findingCount": 3,
    "acceptedRiskCount": 1,
    "expiredCount": 1,
    "invalidCount": 1,
    "riskLevel": "needs_attention",
    "byRuleId": {
      "RSA-UNSAFE-BLOCK": 3
    },
    "byOwner": {
      "(missing)": 1,
      "@security": 2
    }
  },
  "acceptedRisks": [
    {
      "ruleId": "RSA-UNSAFE-BLOCK",
      "file": "src/lib.rs",
      "line": 2,
      "owner": "@security",
      "ticket": "SEC-101",
      "until": "2099-01-01",
      "isExpired": false,
      "isValid": true
    }
  ],
  "confidenceNote": "confidence is pattern-detection confidence, not exploitability confidence",
  "privacy": {
    "doesNotReadLocalProjects": true,
    "doesNotAcceptPrivateRepoTokens": true,
    "doesNotPersistSource": true
  }
}
```

Limitations:

- Suppression inventory reports accepted-risk comments; it does not prove that accepted risks are still justified.
- Owners, tickets, and dates in hosted fixtures are public demo metadata.
- Real private suppression comments may reveal internal risk decisions and should stay local unless explicitly pasted.

Suggested next steps:

- Re-review expired and invalid suppressions first.
- Confirm each active accepted risk has a current owner, ticket, rationale, and review date.
- Prefer fixing the underlying finding when the acceptance no longer has a clear business or compatibility reason.

## `rust_review_current_diff`

Input fixture:

```json
{
  "fixture_id": "fixture_diff"
}
```

Markdown summary:

```markdown
# Rust Current Diff Review Hosted Demo

## Summary

- Tool: rust_review_current_diff
- Source: fixture_id=fixture_diff
- Risk level: needs_attention
- Findings: 3
- Confidence: confidence is pattern-detection confidence, not exploitability confidence

## Findings

- medium RSA-FFI-EXTERN-C at src/lib.rs:9: C ABI boundary requires FFI safety review. Evidence: Line 9: pub extern "C" fn exported_len(ptr: *const u8, len: usize) -> usize {
- medium RSA-UNSAFE-BLOCK at src/lib.rs:10: Unsafe block needs local invariant review. Evidence: Line 10: unsafe { std::slice::from_raw_parts(ptr, len).len() }
```

`structuredContent`:

```json
{
  "tool": "rust_review_current_diff",
  "sourceKind": "fixture",
  "fixture_id": "fixture_diff",
  "riskLevel": "needs_attention",
  "summary": {
    "findingCount": 3,
    "introducedFindingCount": 3,
    "blockingCount": 0,
    "manualReviewCount": 3,
    "riskLevel": "needs_attention",
    "diffAffectedFiles": [
      "src/lib.rs"
    ],
    "parsedDiffFileCount": 1
  },
  "reviewDecision": {
    "status": "needs_attention",
    "safeToCommit": false,
    "blockingFindingIds": [],
    "needsManualReviewFindingIds": [
      "RSA-FFI-EXTERN-C-5709922A",
      "RSA-UNSAFE-BLOCK-8E702F88",
      "RSA-UNSAFE-FROM-RAW-PARTS-AF50114C"
    ]
  },
  "findings": [
    {
      "id": "RSA-FFI-EXTERN-C-5709922A",
      "ruleId": "RSA-FFI-EXTERN-C",
      "title": "C ABI boundary requires FFI safety review",
      "severity": "medium",
      "confidence": "high",
      "category": "ffi",
      "file": "src/lib.rs",
      "startLine": 9,
      "evidenceSnippets": [
        "Line 9: pub extern \"C\" fn exported_len(ptr: *const u8, len: usize) -> usize {"
      ]
    }
  ],
  "confidenceNote": "confidence is pattern-detection confidence, not exploitability confidence",
  "privacy": {
    "doesNotReadLocalProjects": true,
    "doesNotAcceptPrivateRepoTokens": true,
    "doesNotPersistSource": true
  }
}
```

Limitations:

- Hosted `rust_review_current_diff` is fixture-only in this spike.
- It does not read a local Git work tree or private repository.
- It is a heuristic changed-line-aware review, not a complete PR security review.

Suggested next steps:

- Manually review introduced or same-context findings before committing.
- For private code, run `rust_review_current_diff` through the local stdio MCP server instead of hosted MCP.
- Use FFI-safe types, validate nullable pointers before dereference, define ownership rules, and prevent unwinding across the boundary.
