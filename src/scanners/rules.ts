import type { Category, Confidence, Severity } from "../reports/schemas.js";

/** MCP tool placement is independent from a finding's vulnerability category. */
export type ToolScope = "project" | "unsafe" | "dependency";

export interface RuleMetadata {
  ruleId: string;
  title: string;
  category: Category;
  severity: Severity;
  confidence: Confidence;
  description: string;
  whyItMatters: string;
  riskScenario: string;
  remediation: string;
  suggestedTests?: readonly string[];
}

export const ruleMetadata = {
  "RSA-UNSAFE-BLOCK": {
    ruleId: "RSA-UNSAFE-BLOCK",
    title: "Unsafe block needs local invariant review",
    category: "unsafe",
    severity: "medium",
    confidence: "high",
    description: "Detects an explicit unsafe block in Rust source.",
    whyItMatters:
      "Unsafe blocks can dereference raw pointers, call unsafe functions, or rely on invariants outside Rust's borrow checker.",
    riskScenario:
      "A future change weakens the invariant around the unsafe operation and introduces undefined behavior without a compiler error.",
    remediation:
      "Keep the block minimal, state the local invariant next to the operation, and wrap it in a safe API when possible.",
    suggestedTests: ["Add boundary tests that would fail if the unsafe preconditions are violated."]
  },
  "RSA-UNSAFE-FN": {
    ruleId: "RSA-UNSAFE-FN",
    title: "Unsafe function requires a caller safety contract",
    category: "unsafe",
    severity: "medium",
    confidence: "high",
    description: "Detects an unsafe function declaration.",
    whyItMatters:
      "An unsafe function shifts memory-safety obligations to callers, so the required preconditions must be explicit and testable.",
    riskScenario:
      "A caller can pass an invalid pointer, alias mutable state, or violate lifetime requirements and trigger undefined behavior.",
    remediation:
      "Add a precise Safety contract, validate what can be checked at runtime, and keep the unsafe body as small as possible.",
    suggestedTests: ["Cover rejected invalid inputs and valid boundary cases for the documented Safety contract."]
  },
  "RSA-UNSAFE-IMPL-SEND": {
    ruleId: "RSA-UNSAFE-IMPL-SEND",
    title: "Unsafe Send implementation requires thread-safety review",
    category: "concurrency",
    severity: "medium",
    confidence: "high",
    description: "Detects an unsafe impl Send declaration.",
    whyItMatters:
      "An unsafe Send implementation asserts cross-thread transfer invariants that the compiler cannot verify.",
    riskScenario:
      "If the type contains unsynchronized raw pointers or ownership-sensitive state, moving it across threads can cause data races or memory corruption.",
    remediation:
      "Document the Send invariant, restrict the implementation to types that uphold it, and add cross-thread ownership tests.",
    suggestedTests: ["Move the type across threads with representative state and drop-order cases."]
  },
  "RSA-UNSAFE-IMPL-SYNC": {
    ruleId: "RSA-UNSAFE-IMPL-SYNC",
    title: "Unsafe Sync implementation requires shared-access review",
    category: "concurrency",
    severity: "medium",
    confidence: "high",
    description: "Detects an unsafe impl Sync declaration.",
    whyItMatters:
      "An unsafe Sync implementation asserts shared-reference thread-safety invariants that the compiler cannot verify.",
    riskScenario:
      "If interior mutability or raw pointers are not synchronized correctly, shared references can allow data races or memory corruption.",
    remediation:
      "Document the Sync invariant, protect shared mutable state with synchronization, and test concurrent access paths.",
    suggestedTests: ["Exercise shared references across threads with concurrent reads, writes, and drop paths."]
  },
  "RSA-FFI-EXTERN-C": {
    ruleId: "RSA-FFI-EXTERN-C",
    title: "C ABI boundary requires FFI safety review",
    category: "ffi",
    severity: "medium",
    confidence: "high",
    description: "Detects an extern C ABI boundary.",
    whyItMatters:
      "An extern C boundary crosses Rust's type and panic-safety guarantees and often handles raw pointers or foreign ownership.",
    riskScenario:
      "A foreign caller passes invalid pointers or Rust unwinds through the C ABI, causing undefined behavior or process aborts.",
    remediation:
      "Use FFI-safe types, validate nullable pointers before dereference, define ownership rules, and prevent unwinding across the boundary.",
    suggestedTests: ["Test null, invalid-length, and panic-path behavior at the ABI boundary."]
  },
  "RSA-UNSAFE-TRANSMUTE": {
    ruleId: "RSA-UNSAFE-TRANSMUTE",
    title: "transmute requires layout and validity review",
    category: "unsafe",
    severity: "medium",
    confidence: "high",
    description: "Detects std::mem::transmute or mem::transmute.",
    whyItMatters:
      "transmute depends on layout, size, alignment, and value validity assumptions that Rust cannot check.",
    riskScenario:
      "A value is reinterpreted as a type with stricter validity rules, creating invalid values or undefined behavior.",
    remediation:
      "Prefer explicit conversion APIs, bytemuck-style checked casts, or a small wrapper that verifies layout and validity assumptions.",
    suggestedTests: ["Test representative bit patterns and layout assumptions for the conversion boundary."]
  },
  "RSA-UNSAFE-MAYBEUNINIT": {
    ruleId: "RSA-UNSAFE-MAYBEUNINIT",
    title: "MaybeUninit requires initialization invariant review",
    category: "unsafe",
    severity: "medium",
    confidence: "high",
    description: "Detects MaybeUninit usage.",
    whyItMatters:
      "MaybeUninit bypasses Rust's normal initialization checks and must never expose uninitialized bytes as initialized values.",
    riskScenario:
      "An error path or partial write leaves memory uninitialized but later treats it as a valid value.",
    remediation:
      "Track initialization state explicitly, prefer safe collection builders, and isolate assume_init behind checked control flow.",
    suggestedTests: ["Cover partial initialization, early return, and panic paths."]
  },
  "RSA-UNSAFE-FROM-RAW-PARTS": {
    ruleId: "RSA-UNSAFE-FROM-RAW-PARTS",
    title: "from_raw_parts requires pointer and length review",
    category: "unsafe",
    severity: "medium",
    confidence: "high",
    description: "Detects slice or string construction from raw parts.",
    whyItMatters:
      "from_raw_parts relies on pointer validity, alignment, lifetime, and length invariants that Rust cannot verify.",
    riskScenario:
      "An invalid length or stale pointer creates out-of-bounds reads or references to freed memory.",
    remediation:
      "Validate pointer nullability, alignment, lifetime ownership, and length before constructing slices from raw parts.",
    suggestedTests: ["Test null, zero-length, maximum-length, and invalid-length boundary cases."]
  },
  "RSA-UNSAFE-SET-LEN": {
    ruleId: "RSA-UNSAFE-SET-LEN",
    title: "set_len requires initialized capacity review",
    category: "unsafe",
    severity: "medium",
    confidence: "high",
    description: "Detects Vec::set_len or set_len calls.",
    whyItMatters:
      "set_len can expose uninitialized memory or set a length larger than allocated capacity.",
    riskScenario:
      "A vector length is increased before every element is initialized, allowing reads of uninitialized memory.",
    remediation:
      "Only call set_len after all elements are initialized and the requested length is within capacity.",
    suggestedTests: ["Cover short writes, error returns, and maximum-capacity paths."]
  },
  "RSA-UNSAFE-BOX-FROM-RAW": {
    ruleId: "RSA-UNSAFE-BOX-FROM-RAW",
    title: "Box::from_raw requires ownership review",
    category: "unsafe",
    severity: "medium",
    confidence: "high",
    description: "Detects Box::from_raw usage.",
    whyItMatters:
      "Box::from_raw assumes the pointer was allocated by Box and that ownership is transferred exactly once.",
    riskScenario:
      "A pointer is converted into a Box twice or was allocated by a foreign allocator, causing double free or allocator mismatch.",
    remediation:
      "Prove single ownership transfer, pair the allocation and deallocation strategy, and avoid repeated from_raw conversions.",
    suggestedTests: ["Test ownership transfer and drop paths around the raw pointer boundary."]
  },
  "RSA-UNSAFE-GET-UNCHECKED": {
    ruleId: "RSA-UNSAFE-GET-UNCHECKED",
    title: "get_unchecked skips bounds checking",
    category: "unsafe",
    severity: "medium",
    confidence: "high",
    description: "Detects get_unchecked or get_unchecked_mut indexing.",
    whyItMatters:
      "get_unchecked removes the bounds check that normally turns an indexing mistake into a panic instead of memory corruption.",
    riskScenario:
      "An attacker-influenced or off-by-one index reads or writes outside the allocation and corrupts adjacent memory.",
    remediation:
      "Prove the index is in bounds at every call site, or use checked indexing and `get` until profiling shows the bounds check matters.",
    suggestedTests: ["Cover empty, single-element, and maximum-index inputs for the indexed collection."]
  },
  "RSA-UNSAFE-UNCHECKED-CALL": {
    ruleId: "RSA-UNSAFE-UNCHECKED-CALL",
    title: "Unchecked constructor or accessor skips a validity check",
    category: "unsafe",
    severity: "medium",
    confidence: "high",
    description: "Detects *_unchecked calls such as from_utf8_unchecked, unwrap_unchecked, or new_unchecked.",
    whyItMatters:
      "An *_unchecked API moves a validity precondition from the library to the caller; violating it is immediate undefined behavior.",
    riskScenario:
      "Untrusted bytes reach from_utf8_unchecked, or an empty value reaches unwrap_unchecked, and later code observes an invalid value.",
    remediation:
      "Validate the precondition before the call, or use the checked variant and handle the error path explicitly.",
    suggestedTests: ["Feed invalid or boundary inputs through the checked variant to confirm the precondition really holds."]
  },
  "RSA-UNSAFE-STATIC-MUT": {
    ruleId: "RSA-UNSAFE-STATIC-MUT",
    title: "static mut allows unsynchronized shared mutation",
    category: "concurrency",
    severity: "high",
    confidence: "high",
    description: "Detects a static mut declaration.",
    whyItMatters:
      "Every reference to a static mut can alias mutable global state without synchronization, which is why references to it are denied by default in the 2024 edition.",
    riskScenario:
      "Two threads, or a reentrant call, mutate the same global concurrently and produce a data race with undefined behavior.",
    remediation:
      "Replace static mut with an atomic, a Mutex/RwLock, OnceLock, or thread-local state, and keep any remaining raw access behind addr_of_mut!.",
    suggestedTests: ["Exercise concurrent access to the global from multiple threads under a race detector."]
  },
  "RSA-UNSAFE-RAW-PTR-ACCESS": {
    ruleId: "RSA-UNSAFE-RAW-PTR-ACCESS",
    title: "Raw pointer read/write/copy requires validity review",
    category: "unsafe",
    severity: "medium",
    confidence: "high",
    description: "Detects copy_nonoverlapping, ptr::copy, ptr::read/write, write_bytes, or volatile access.",
    whyItMatters:
      "These primitives assume the pointers are non-null, aligned, in-bounds, correctly initialized, and non-overlapping when required.",
    riskScenario:
      "A wrong length, an unaligned pointer, or overlapping ranges corrupt memory or expose adjacent heap contents.",
    remediation:
      "Validate alignment, bounds, and overlap before the call, prefer safe slice APIs such as copy_from_slice, and keep the unsafe region minimal.",
    suggestedTests: ["Cover zero-length, maximum-length, unaligned, and overlapping-range cases."]
  },
  "RSA-FFI-CSTR-FROM-PTR": {
    ruleId: "RSA-FFI-CSTR-FROM-PTR",
    title: "C string conversion trusts a foreign pointer",
    category: "ffi",
    severity: "medium",
    confidence: "high",
    description: "Detects CStr::from_ptr or CString::from_raw.",
    whyItMatters:
      "These conversions assume a non-null pointer, a valid NUL terminator, a lifetime that outlives the borrow, and for from_raw a matching allocator and single ownership transfer.",
    riskScenario:
      "A foreign caller passes a null, unterminated, or already-freed pointer and the conversion reads out of bounds or double frees.",
    remediation:
      "Reject null pointers explicitly, document who owns the buffer and how long it lives, and bound the lifetime of the resulting borrow.",
    suggestedTests: ["Test null, empty, unterminated, and already-freed pointer inputs at the boundary."]
  },
  "RSA-EXEC-COMMAND": {
    ruleId: "RSA-EXEC-COMMAND",
    title: "Runtime code spawns an external process",
    category: "command_execution",
    severity: "medium",
    confidence: "high",
    description: "Detects std::process::Command usage outside build scripts.",
    whyItMatters:
      "A spawned process runs with the application's privileges, resolves its program through PATH by default, and inherits the current environment.",
    riskScenario:
      "Untrusted input reaches the program name or arguments, or a shell is invoked with an interpolated string, and the attacker executes arbitrary commands.",
    remediation:
      "Use absolute or allowlisted program paths, pass arguments as separate values instead of a shell string, and never interpolate untrusted input into `sh -c`.",
    suggestedTests: ["Test argument values containing shell metacharacters, spaces, and path traversal sequences."]
  },
  "RSA-DEP-GIT": {
    ruleId: "RSA-DEP-GIT",
    title: "Git dependency requires supply-chain review",
    category: "supply_chain",
    severity: "medium",
    confidence: "high",
    description: "Detects git-sourced dependencies in Cargo.toml.",
    whyItMatters:
      "Git dependencies bypass the normal registry review and versioning path, so trust depends on the referenced repository and revision.",
    riskScenario:
      "A branch or mutable reference changes after review and introduces malicious build-time or runtime code.",
    remediation:
      "Pin git dependencies to immutable revisions, prefer registry releases when practical, and review repository ownership before release.",
    suggestedTests: ["Verify CI resolves the expected revision and fails on unexpected dependency source changes."]
  },
  "RSA-DEP-PATH": {
    ruleId: "RSA-DEP-PATH",
    title: "Path dependency needs local trust boundary review",
    category: "dependency",
    severity: "low",
    confidence: "high",
    description: "Detects path dependencies in Cargo.toml.",
    whyItMatters:
      "Path dependencies are resolved from the local filesystem and can change without a registry version or checksum boundary.",
    riskScenario:
      "A local crate is replaced or modified in CI and the audited package builds against code that was not reviewed.",
    remediation:
      "Keep path dependencies inside the reviewed workspace, avoid absolute paths, and ensure CI checks the complete dependency tree.",
    suggestedTests: ["Run dependency resolution in CI from a clean checkout and fail if path dependencies point outside the workspace."]
  },
  "RSA-DEP-PROC-MACRO": {
    ruleId: "RSA-DEP-PROC-MACRO",
    title: "Proc-macro crate executes code during compilation",
    category: "supply_chain",
    severity: "medium",
    confidence: "high",
    description: "Detects proc-macro crates in Cargo.toml.",
    whyItMatters:
      "Proc macros run as compiler plugins during builds and can read files, environment variables, or generate security-sensitive code.",
    riskScenario:
      "A malicious or compromised proc macro exfiltrates build secrets or injects unexpected code during compilation.",
    remediation:
      "Review proc-macro crates as build-time code, pin versions or revisions, and avoid exposing sensitive environment variables during builds.",
    suggestedTests: ["Build in a restricted CI environment and verify generated code or macro expansion for security-sensitive paths."]
  },
  "RSA-DEP-BUILD-DEPENDENCIES": {
    ruleId: "RSA-DEP-BUILD-DEPENDENCIES",
    title: "Build dependencies expand the build-time trust boundary",
    category: "supply_chain",
    severity: "medium",
    confidence: "high",
    description: "Detects Cargo build-dependencies sections.",
    whyItMatters:
      "Build dependencies are compiled for and used by build scripts or code generators that execute on the build host.",
    riskScenario:
      "A compromised build dependency executes during CI and reads environment secrets or tampers with generated artifacts.",
    remediation:
      "Review build dependencies as build-time code, pin versions, and run release builds with restricted environment access.",
    suggestedTests: ["Fail CI when new build dependencies appear without explicit review."]
  },
  "RSA-DEP-LOCK-GIT": {
    ruleId: "RSA-DEP-LOCK-GIT",
    title: "Cargo.lock resolves a git-sourced package",
    category: "supply_chain",
    severity: "medium",
    confidence: "high",
    description: "Detects git sources in Cargo.lock.",
    whyItMatters:
      "A git source in Cargo.lock confirms the final dependency graph includes code outside the registry checksum path.",
    riskScenario:
      "The release includes a transitive git dependency whose repository trust and revision were not part of the dependency review.",
    remediation:
      "Review each git source in the lockfile, pin immutable revisions, and prefer crates.io releases when available.",
    suggestedTests: ["Fail CI if new git sources appear in Cargo.lock without explicit security review."]
  },
  "RSA-BUILD-SCRIPT": {
    ruleId: "RSA-BUILD-SCRIPT",
    title: "Build script runs code during cargo build",
    category: "supply_chain",
    severity: "medium",
    confidence: "high",
    description: "Detects build.rs files.",
    whyItMatters:
      "build.rs executes on the build host before compilation and can access the filesystem, environment, network, and native toolchain.",
    riskScenario:
      "A compromised build script reads secrets from CI or invokes a malicious local tool during release builds.",
    remediation:
      "Keep build scripts minimal, review filesystem/environment/process access, and run builds with least-privilege CI permissions.",
    suggestedTests: ["Run release builds in a clean CI environment with restricted secrets and assert generated artifacts are deterministic."]
  },
  "RSA-BUILD-COMMAND": {
    ruleId: "RSA-BUILD-COMMAND",
    title: "Build script spawns an external command",
    category: "command_execution",
    severity: "high",
    confidence: "high",
    description: "Detects external process execution from build.rs.",
    whyItMatters:
      "External commands in build.rs execute with build-host privileges and inherit the build environment by default.",
    riskScenario:
      "An attacker controls the invoked binary or arguments and executes unintended code during CI or release packaging.",
    remediation:
      "Use absolute tool paths or allowlisted commands, validate arguments, and avoid passing untrusted environment values to the process.",
    suggestedTests: ["Test the build script with a clean PATH and unexpected environment values to ensure command resolution is controlled."]
  },
  "RSA-DEP-VERSION-UNBOUNDED": {
    ruleId: "RSA-DEP-VERSION-UNBOUNDED",
    title: "Dependency requirement has no upper bound",
    category: "supply_chain",
    severity: "medium",
    confidence: "high",
    description: "Detects wildcard or open-ended dependency version requirements in Cargo.toml.",
    whyItMatters:
      "A wildcard or `>=`-only requirement accepts any future release, so the code that ships can change without any local edit or review.",
    riskScenario:
      "A compromised or breaking upstream release is pulled into a fresh build or CI run that regenerates the lockfile, and unreviewed code reaches production.",
    remediation:
      "Use a caret requirement pinned to a reviewed major/minor version, commit Cargo.lock for binaries, and upgrade deliberately.",
    suggestedTests: ["Build from a clean checkout in CI and fail when Cargo.lock changes unexpectedly."]
  },
  "RSA-CARGO-SOURCE-REPLACEMENT": {
    ruleId: "RSA-CARGO-SOURCE-REPLACEMENT",
    title: "Cargo config replaces a registry source",
    category: "supply_chain",
    severity: "high",
    confidence: "high",
    description: "Detects source replacement (`replace-with`) in .cargo/config.toml.",
    whyItMatters:
      "Source replacement silently redirects where every crate is fetched from, including crates.io, for anyone who builds in this directory.",
    riskScenario:
      "A mirror or vendored source serves modified crates, and the build produces binaries containing code that was never reviewed on crates.io.",
    remediation:
      "Confirm the replacement source is intended and trusted, document who controls it, and prefer vendoring with checked-in checksums.",
    suggestedTests: ["Verify in CI that the resolved source of each dependency matches the expected registry."]
  },
  "RSA-CARGO-RUNNER": {
    ruleId: "RSA-CARGO-RUNNER",
    title: "Cargo config sets a custom target runner",
    category: "command_execution",
    severity: "high",
    confidence: "high",
    description: "Detects a `runner` entry in .cargo/config.toml.",
    whyItMatters:
      "A target runner is the command Cargo executes for `cargo run` and `cargo test`, so it runs arbitrary code on the developer or CI machine.",
    riskScenario:
      "A repository ships a config whose runner executes an attacker-controlled binary the first time a contributor runs the test suite.",
    remediation:
      "Review the runner command and its arguments, keep it inside the repository, and treat changes to .cargo/config.toml as security-relevant.",
    suggestedTests: ["Run the test suite in an isolated container the first time an unfamiliar .cargo/config.toml is introduced."]
  }
} as const satisfies Record<string, RuleMetadata>;

export type RuleId = keyof typeof ruleMetadata;

/**
 * One explicit registry entry per rule. Do not infer this from rule-id prefixes
 * or finding categories: both are report metadata, not an API boundary.
 */
export const toolScopesByRule = {
  "RSA-UNSAFE-BLOCK": ["project", "unsafe"],
  "RSA-UNSAFE-FN": ["project", "unsafe"],
  "RSA-UNSAFE-IMPL-SEND": ["project", "unsafe"],
  "RSA-UNSAFE-IMPL-SYNC": ["project", "unsafe"],
  "RSA-FFI-EXTERN-C": ["project", "unsafe"],
  "RSA-UNSAFE-TRANSMUTE": ["project", "unsafe"],
  "RSA-UNSAFE-MAYBEUNINIT": ["project", "unsafe"],
  "RSA-UNSAFE-FROM-RAW-PARTS": ["project", "unsafe"],
  "RSA-UNSAFE-SET-LEN": ["project", "unsafe"],
  "RSA-UNSAFE-BOX-FROM-RAW": ["project", "unsafe"],
  "RSA-UNSAFE-GET-UNCHECKED": ["project", "unsafe"],
  "RSA-UNSAFE-UNCHECKED-CALL": ["project", "unsafe"],
  "RSA-UNSAFE-STATIC-MUT": ["project", "unsafe"],
  "RSA-UNSAFE-RAW-PTR-ACCESS": ["project", "unsafe"],
  "RSA-FFI-CSTR-FROM-PTR": ["project", "unsafe"],
  "RSA-EXEC-COMMAND": ["project"],
  "RSA-DEP-GIT": ["project", "dependency"],
  "RSA-DEP-PATH": ["project", "dependency"],
  "RSA-DEP-PROC-MACRO": ["project", "dependency"],
  "RSA-DEP-BUILD-DEPENDENCIES": ["project", "dependency"],
  "RSA-DEP-LOCK-GIT": ["project", "dependency"],
  "RSA-BUILD-SCRIPT": ["project", "dependency"],
  "RSA-BUILD-COMMAND": ["project", "dependency"],
  "RSA-DEP-VERSION-UNBOUNDED": ["project", "dependency"],
  "RSA-CARGO-SOURCE-REPLACEMENT": ["project", "dependency"],
  "RSA-CARGO-RUNNER": ["project", "dependency"]
} as const satisfies Record<RuleId, readonly ToolScope[]>;

export interface ScopedRuleMetadata extends RuleMetadata {
  toolScopes: readonly ToolScope[];
}

export const allRules: readonly ScopedRuleMetadata[] = Object.values(ruleMetadata).map((rule) => ({
  ...rule,
  toolScopes: toolScopesByRule[rule.ruleId as RuleId]
}));

export function getRuleMetadata(ruleId: RuleId): ScopedRuleMetadata {
  return { ...ruleMetadata[ruleId], toolScopes: toolScopesByRule[ruleId] };
}

export function ruleHasToolScope(ruleId: string, toolScope: ToolScope): boolean {
  const scopes: readonly ToolScope[] | undefined = toolScopesByRule[ruleId as RuleId];
  return scopes?.includes(toolScope) ?? false;
}
