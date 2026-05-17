# Rust Project Security Audit

## Summary

- Result: NEEDS_FIX_BEFORE_RELEASE
- Critical: 0
- High: 1
- Medium: 19
- Low: 1
- Info: 0
- Manual Review: 0
- Scope: <repo>/test/fixtures/vulnerable-rust-project

## Critical Risk Findings

No critical risk findings.

## High Risk Findings

### RSA-BUILD-COMMAND-8C9A005B: Build script spawns an external command

- Severity: High
- Confidence: High
- Category: command_execution
- Rule: RSA-BUILD-COMMAND
- Location: `build.rs:4`

#### Evidence

- Line 4: let _ = Command::new("cc").arg("native.c").status();

#### Why it matters

External commands in build.rs execute with build-host privileges and inherit the build environment by default.

#### Risk scenario

An attacker controls the invoked binary or arguments and executes unintended code during CI or release packaging.

#### Suggested fix

Use absolute tool paths or allowlisted commands, validate arguments, and avoid passing untrusted environment values to the process.

#### Suggested tests

- Test the build script with a clean PATH and unexpected environment values to ensure command resolution is controlled.

## Medium Risk Findings

### RSA-BUILD-SCRIPT-B9C844AC: Build script runs code during cargo build

- Severity: Medium
- Confidence: High
- Category: supply_chain
- Rule: RSA-BUILD-SCRIPT
- Location: `build.rs:1`

#### Evidence

- Line 1: use std::process::Command;

#### Why it matters

build.rs executes on the build host before compilation and can access the filesystem, environment, network, and native toolchain.

#### Risk scenario

A compromised build script reads secrets from CI or invokes a malicious local tool during release builds.

#### Suggested fix

Keep build scripts minimal, review filesystem/environment/process access, and run builds with least-privilege CI permissions.

#### Suggested tests

- Run release builds in a clean CI environment with restricted secrets and assert generated artifacts are deterministic.

### RSA-DEP-LOCK-GIT-F76DA24B: Cargo.lock resolves a git-sourced package

- Severity: Medium
- Confidence: High
- Category: supply_chain
- Rule: RSA-DEP-LOCK-GIT
- Location: `Cargo.lock:7`

#### Evidence

- Line 7: source = "git+https://github.com/example/unsafe-crate?rev=abc123#abc123abc123abc123abc123abc123abc123abcd"

#### Why it matters

A git source in Cargo.lock confirms the final dependency graph includes code outside the registry checksum path.

#### Risk scenario

The release includes a transitive git dependency whose repository trust and revision were not part of the dependency review.

#### Suggested fix

Review each git source in the lockfile, pin immutable revisions, and prefer crates.io releases when available.

#### Suggested tests

- Fail CI if new git sources appear in Cargo.lock without explicit security review.

### RSA-DEP-GIT-BCE85494: Git dependency requires supply-chain review

- Severity: Medium
- Confidence: High
- Category: supply_chain
- Rule: RSA-DEP-GIT
- Location: `Cargo.toml:13`

#### Evidence

- Line 13: gitdep = { git = "https://github.com/example/unsafe-crate", rev = "abc123" }

#### Why it matters

Git dependencies bypass the normal registry review and versioning path, so trust depends on the referenced repository and revision.

#### Risk scenario

A branch or mutable reference changes after review and introduces malicious build-time or runtime code.

#### Suggested fix

Pin git dependencies to immutable revisions, prefer registry releases when practical, and review repository ownership before release.

#### Suggested tests

- Verify CI resolves the expected revision and fails on unexpected dependency source changes.

### RSA-DEP-PROC-MACRO-1F6CA2E1: Proc-macro crate executes code during compilation

- Severity: Medium
- Confidence: High
- Category: supply_chain
- Rule: RSA-DEP-PROC-MACRO
- Location: `Cargo.toml:17`

#### Evidence

- Line 17: proc-macro = true

#### Why it matters

Proc macros run as compiler plugins during builds and can read files, environment variables, or generate security-sensitive code.

#### Risk scenario

A malicious or compromised proc macro exfiltrates build secrets or injects unexpected code during compilation.

#### Suggested fix

Review proc-macro crates as build-time code, pin versions or revisions, and avoid exposing sensitive environment variables during builds.

#### Suggested tests

- Build in a restricted CI environment and verify generated code or macro expansion for security-sensitive paths.

### RSA-UNSAFE-FN-5D5D0CE5: Unsafe function requires a caller safety contract

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-FN
- Location: `src/lib.rs:1`

#### Evidence

- Line 1: pub unsafe fn read_byte(ptr: *const u8) -> u8 {

#### Why it matters

An unsafe function shifts memory-safety obligations to callers, so the required preconditions must be explicit and testable.

#### Risk scenario

A caller can pass an invalid pointer, alias mutable state, or violate lifetime requirements and trigger undefined behavior.

#### Suggested fix

Add a precise Safety contract, validate what can be checked at runtime, and keep the unsafe body as small as possible.

#### Suggested tests

- Cover rejected invalid inputs and valid boundary cases for the documented Safety contract.

### RSA-UNSAFE-BLOCK-91AA22BF: Unsafe block needs local invariant review

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-BLOCK
- Location: `src/lib.rs:2`

#### Evidence

- Line 2: unsafe { *ptr }

#### Why it matters

Unsafe blocks can dereference raw pointers, call unsafe functions, or rely on invariants outside Rust's borrow checker.

#### Risk scenario

A future change weakens the invariant around the unsafe operation and introduces undefined behavior without a compiler error.

#### Suggested fix

Keep the block minimal, state the local invariant next to the operation, and wrap it in a safe API when possible.

#### Suggested tests

- Add boundary tests that would fail if the unsafe preconditions are violated.

### RSA-UNSAFE-IMPL-SEND-E2F38AC1: Unsafe Send implementation requires thread-safety review

- Severity: Medium
- Confidence: High
- Category: concurrency
- Rule: RSA-UNSAFE-IMPL-SEND
- Location: `src/lib.rs:7`

#### Evidence

- Line 7: unsafe impl Send for Shared {}

#### Why it matters

An unsafe Send implementation asserts cross-thread transfer invariants that the compiler cannot verify.

#### Risk scenario

If the type contains unsynchronized raw pointers or ownership-sensitive state, moving it across threads can cause data races or memory corruption.

#### Suggested fix

Document the Send invariant, restrict the implementation to types that uphold it, and add cross-thread ownership tests.

#### Suggested tests

- Move the type across threads with representative state and drop-order cases.

### RSA-UNSAFE-IMPL-SYNC-F29D8FBE: Unsafe Sync implementation requires shared-access review

- Severity: Medium
- Confidence: High
- Category: concurrency
- Rule: RSA-UNSAFE-IMPL-SYNC
- Location: `src/lib.rs:8`

#### Evidence

- Line 8: unsafe impl Sync for Shared {}

#### Why it matters

An unsafe Sync implementation asserts shared-reference thread-safety invariants that the compiler cannot verify.

#### Risk scenario

If interior mutability or raw pointers are not synchronized correctly, shared references can allow data races or memory corruption.

#### Suggested fix

Document the Sync invariant, protect shared mutable state with synchronization, and test concurrent access paths.

#### Suggested tests

- Exercise shared references across threads with concurrent reads, writes, and drop paths.

### RSA-FFI-EXTERN-C-8F06F22A: C ABI boundary requires FFI safety review

- Severity: Medium
- Confidence: High
- Category: ffi
- Rule: RSA-FFI-EXTERN-C
- Location: `src/lib.rs:10`

#### Evidence

- Line 10: pub extern "C" fn exported(ptr: *const u8) -> usize {

#### Why it matters

An extern C boundary crosses Rust's type and panic-safety guarantees and often handles raw pointers or foreign ownership.

#### Risk scenario

A foreign caller passes invalid pointers or Rust unwinds through the C ABI, causing undefined behavior or process aborts.

#### Suggested fix

Use FFI-safe types, validate nullable pointers before dereference, define ownership rules, and prevent unwinding across the boundary.

#### Suggested tests

- Test null, invalid-length, and panic-path behavior at the ABI boundary.

### RSA-UNSAFE-BLOCK-4064E557: Unsafe block needs local invariant review

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-BLOCK
- Location: `src/lib.rs:11`

#### Evidence

- Line 11: unsafe { std::slice::from_raw_parts(ptr, 4).len() }

#### Why it matters

Unsafe blocks can dereference raw pointers, call unsafe functions, or rely on invariants outside Rust's borrow checker.

#### Risk scenario

A future change weakens the invariant around the unsafe operation and introduces undefined behavior without a compiler error.

#### Suggested fix

Keep the block minimal, state the local invariant next to the operation, and wrap it in a safe API when possible.

#### Suggested tests

- Add boundary tests that would fail if the unsafe preconditions are violated.

### RSA-UNSAFE-FROM-RAW-PARTS-FB4B9917: from_raw_parts requires pointer and length review

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-FROM-RAW-PARTS
- Location: `src/lib.rs:11`

#### Evidence

- Line 11: unsafe { std::slice::from_raw_parts(ptr, 4).len() }

#### Why it matters

from_raw_parts relies on pointer validity, alignment, lifetime, and length invariants that Rust cannot verify.

#### Risk scenario

An invalid length or stale pointer creates out-of-bounds reads or references to freed memory.

#### Suggested fix

Validate pointer nullability, alignment, lifetime ownership, and length before constructing slices from raw parts.

#### Suggested tests

- Test null, zero-length, maximum-length, and invalid-length boundary cases.

### RSA-UNSAFE-BLOCK-68848946: Unsafe block needs local invariant review

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-BLOCK
- Location: `src/lib.rs:15`

#### Evidence

- Line 15: unsafe { std::mem::transmute(value) }

#### Why it matters

Unsafe blocks can dereference raw pointers, call unsafe functions, or rely on invariants outside Rust's borrow checker.

#### Risk scenario

A future change weakens the invariant around the unsafe operation and introduces undefined behavior without a compiler error.

#### Suggested fix

Keep the block minimal, state the local invariant next to the operation, and wrap it in a safe API when possible.

#### Suggested tests

- Add boundary tests that would fail if the unsafe preconditions are violated.

### RSA-UNSAFE-TRANSMUTE-AC3C61F3: transmute requires layout and validity review

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-TRANSMUTE
- Location: `src/lib.rs:15`

#### Evidence

- Line 15: unsafe { std::mem::transmute(value) }

#### Why it matters

transmute depends on layout, size, alignment, and value validity assumptions that Rust cannot check.

#### Risk scenario

A value is reinterpreted as a type with stricter validity rules, creating invalid values or undefined behavior.

#### Suggested fix

Prefer explicit conversion APIs, bytemuck-style checked casts, or a small wrapper that verifies layout and validity assumptions.

#### Suggested tests

- Test representative bit patterns and layout assumptions for the conversion boundary.

### RSA-UNSAFE-MAYBEUNINIT-5CB12A51: MaybeUninit requires initialization invariant review

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-MAYBEUNINIT
- Location: `src/lib.rs:19`

#### Evidence

- Line 19: let value = std::mem::MaybeUninit::<u8>::uninit();

#### Why it matters

MaybeUninit bypasses Rust's normal initialization checks and must never expose uninitialized bytes as initialized values.

#### Risk scenario

An error path or partial write leaves memory uninitialized but later treats it as a valid value.

#### Suggested fix

Track initialization state explicitly, prefer safe collection builders, and isolate assume_init behind checked control flow.

#### Suggested tests

- Cover partial initialization, early return, and panic paths.

### RSA-UNSAFE-BLOCK-4414E415: Unsafe block needs local invariant review

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-BLOCK
- Location: `src/lib.rs:20`

#### Evidence

- Line 20: unsafe { value.assume_init() }

#### Why it matters

Unsafe blocks can dereference raw pointers, call unsafe functions, or rely on invariants outside Rust's borrow checker.

#### Risk scenario

A future change weakens the invariant around the unsafe operation and introduces undefined behavior without a compiler error.

#### Suggested fix

Keep the block minimal, state the local invariant next to the operation, and wrap it in a safe API when possible.

#### Suggested tests

- Add boundary tests that would fail if the unsafe preconditions are violated.

### RSA-UNSAFE-BLOCK-9BE0C979: Unsafe block needs local invariant review

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-BLOCK
- Location: `src/lib.rs:24`

#### Evidence

- Line 24: unsafe { values.set_len(values.capacity()) }

#### Why it matters

Unsafe blocks can dereference raw pointers, call unsafe functions, or rely on invariants outside Rust's borrow checker.

#### Risk scenario

A future change weakens the invariant around the unsafe operation and introduces undefined behavior without a compiler error.

#### Suggested fix

Keep the block minimal, state the local invariant next to the operation, and wrap it in a safe API when possible.

#### Suggested tests

- Add boundary tests that would fail if the unsafe preconditions are violated.

### RSA-UNSAFE-SET-LEN-5DA5691E: set_len requires initialized capacity review

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-SET-LEN
- Location: `src/lib.rs:24`

#### Evidence

- Line 24: unsafe { values.set_len(values.capacity()) }

#### Why it matters

set_len can expose uninitialized memory or set a length larger than allocated capacity.

#### Risk scenario

A vector length is increased before every element is initialized, allowing reads of uninitialized memory.

#### Suggested fix

Only call set_len after all elements are initialized and the requested length is within capacity.

#### Suggested tests

- Cover short writes, error returns, and maximum-capacity paths.

### RSA-UNSAFE-FN-DA9DB871: Unsafe function requires a caller safety contract

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-FN
- Location: `src/lib.rs:27`

#### Evidence

- Line 27: pub unsafe fn take(ptr: *mut u8) -> Box<u8> {

#### Why it matters

An unsafe function shifts memory-safety obligations to callers, so the required preconditions must be explicit and testable.

#### Risk scenario

A caller can pass an invalid pointer, alias mutable state, or violate lifetime requirements and trigger undefined behavior.

#### Suggested fix

Add a precise Safety contract, validate what can be checked at runtime, and keep the unsafe body as small as possible.

#### Suggested tests

- Cover rejected invalid inputs and valid boundary cases for the documented Safety contract.

### RSA-UNSAFE-BOX-FROM-RAW-B86263A9: Box::from_raw requires ownership review

- Severity: Medium
- Confidence: High
- Category: unsafe
- Rule: RSA-UNSAFE-BOX-FROM-RAW
- Location: `src/lib.rs:28`

#### Evidence

- Line 28: Box::from_raw(ptr)

#### Why it matters

Box::from_raw assumes the pointer was allocated by Box and that ownership is transferred exactly once.

#### Risk scenario

A pointer is converted into a Box twice or was allocated by a foreign allocator, causing double free or allocator mismatch.

#### Suggested fix

Prove single ownership transfer, pair the allocation and deallocation strategy, and avoid repeated from_raw conversions.

#### Suggested tests

- Test ownership transfer and drop paths around the raw pointer boundary.

## Low Risk Findings

### RSA-DEP-PATH-64555982: Path dependency needs local trust boundary review

- Severity: Low
- Confidence: High
- Category: dependency
- Rule: RSA-DEP-PATH
- Location: `Cargo.toml:14`

#### Evidence

- Line 14: local_dep = { path = "crates/local_dep" }

#### Why it matters

Path dependencies are resolved from the local filesystem and can change without a registry version or checksum boundary.

#### Risk scenario

A local crate is replaced or modified in CI and the audited package builds against code that was not reviewed.

#### Suggested fix

Keep path dependencies inside the reviewed workspace, avoid absolute paths, and ensure CI checks the complete dependency tree.

#### Suggested tests

- Run dependency resolution in CI from a clean checkout and fail if path dependencies point outside the workspace.

## Informational Findings

No info risk findings.

## Needs Manual Review

No manual review items.

## Release Gate Recommendation

Fix high or critical security findings before release or merge.

