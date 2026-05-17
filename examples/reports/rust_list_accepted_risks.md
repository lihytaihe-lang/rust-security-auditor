# Accepted Risk Inventory

## Summary

- Accepted risks: 4
- Expired: 1
- Invalid: 1
- Owners: (missing): 5, @security: 1
- Rule IDs: RSA-UNSAFE-BLOCK: 6
- Scope: <repo>/test/fixtures/suppressed-rust-project

## Active Accepted Risks

- RSA-UNSAFE-BLOCK at `src/lib.rs:2`; reason: legacy FFI wrapper reviewed in host project; owner: missing; ticket: missing; raw: `// rustsec-auditor: ignore RSA-UNSAFE-BLOCK -- legacy FFI wrapper reviewed in host project`
- RSA-UNSAFE-BLOCK at `src/lib.rs:12`; reason: reviewed wrapper owned by platform security; owner: @security; ticket: missing; raw: `// rustsec-auditor: ignore RSA-UNSAFE-BLOCK owner=@security -- reviewed wrapper owned by platform security`
- RSA-UNSAFE-BLOCK at `src/lib.rs:17`; reason: tracked accepted risk for compatibility; owner: missing; ticket: SEC-123; raw: `// rustsec-auditor: ignore RSA-UNSAFE-BLOCK ticket=SEC-123 -- tracked accepted risk for compatibility`
- RSA-UNSAFE-BLOCK at `src/lib.rs:22`; reason: temporary accepted risk until migration lands; owner: missing; ticket: missing; until: 2999-12-31; raw: `// rustsec-auditor: ignore RSA-UNSAFE-BLOCK until=2999-12-31 -- temporary accepted risk until migration lands`

## Expired Suppressions

- RSA-UNSAFE-BLOCK at `src/lib.rs:27`; reason: temporary risk acceptance expired; owner: missing; ticket: missing; until: 2000-01-01; raw: `// rustsec-auditor: ignore RSA-UNSAFE-BLOCK until=2000-01-01 -- temporary risk acceptance expired`

## Invalid Suppressions

- RSA-UNSAFE-BLOCK at `src/lib.rs:7`; reason: missing required reason; owner: missing; ticket: missing; raw: `// rustsec-auditor: ignore RSA-UNSAFE-BLOCK`; invalid: Suppression reason is required after '--'.

## Recommended Actions

- Expired suppression: re-evaluate the accepted risk or remove the suppression.
- Invalid suppression: add a reason after `--` or fix the suppression format.
- Missing owner: add `owner=` metadata so future reviewers know who accepted the risk.
- Missing ticket: add `ticket=` metadata for traceability.
