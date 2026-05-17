import type { Category, Confidence, Severity } from "../reports/schemas.js";

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
  }
} as const satisfies Record<string, RuleMetadata>;

export type RuleId = keyof typeof ruleMetadata;

export const allRules = Object.values(ruleMetadata);

export function getRuleMetadata(ruleId: RuleId): RuleMetadata {
  return ruleMetadata[ruleId];
}
