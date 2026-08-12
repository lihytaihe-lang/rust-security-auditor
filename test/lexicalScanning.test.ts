import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import type { Finding } from "../src/reports/index.js";
import {
  DependencyScanner,
  SourceRiskScanner,
  UnsafeScanner,
  findTestCodeLines,
  isImportLine,
  listAcceptedRiskInventory,
  maskRustSource,
  maskRustSourceInvocations,
  scanRustProject,
  scanCargoConfigText,
  scanCargoManifestText,
  scanUnsafeRustText,
  unboundedVersionRequirement
} from "../src/scanners/index.js";

const lexicalNoiseFixturePath = resolve("test/fixtures/lexical-noise");
const cargoConfigFixturePath = resolve("test/fixtures/cargo-config-risk");
const denseFindingsFixturePath = resolve("test/fixtures/dense-findings");

function ruleIds(findings: readonly Finding[]): string[] {
  return [...new Set(findings.map((finding) => finding.ruleId))].sort();
}

function findingAt(findings: readonly Finding[], ruleId: string, line: number): Finding | undefined {
  return findings.find((finding) => finding.ruleId === ruleId && finding.startLine === line);
}

describe("rust lexical masking", () => {
  it("masks line comments, block comments, and nested block comments", () => {
    const masked = maskRustSource([
      "let a = 1; // unsafe { transmute(a) }",
      "/* unsafe {",
      "   /* nested */ transmute(x)",
      "*/ let b = 2;"
    ]);

    assert.equal(masked.withoutLiterals[0]?.includes("unsafe"), false);
    assert.equal(masked.withoutLiterals[1]?.trim(), "");
    assert.equal(masked.withoutLiterals[2]?.trim(), "");
    assert.match(masked.withoutLiterals[3] ?? "", /let b = 2;/);
  });

  it("masks string, raw string, and byte string contents but keeps line length", () => {
    const lines = [
      'let s = "unsafe { transmute(x) }";',
      'let r = r#"static mut G: u8 = 0;"#;',
      'let b = b"unsafe {";'
    ];
    const masked = maskRustSource(lines);

    lines.forEach((line, index) => {
      assert.equal(masked.withoutLiterals[index]?.length, line.length);
    });

    assert.equal(masked.withoutLiterals.join("\n").includes("unsafe"), false);
    assert.equal(masked.withoutLiterals.join("\n").includes("static mut"), false);
  });

  it("keeps literals in the comment-only view so ABI strings stay matchable", () => {
    const masked = maskRustSource(['extern "C" fn exported() {} // extern "C"']);

    assert.match(masked.withoutComments[0] ?? "", /extern "C" fn exported/);
    assert.equal((masked.withoutComments[0] ?? "").split('extern "C"').length - 1, 1);
  });

  it("treats a lifetime as code and a char literal as a literal", () => {
    const masked = maskRustSource(["fn f<'a>(c: char) -> bool { c == '{' }"]);

    assert.match(masked.withoutLiterals[0] ?? "", /fn f<'a>/);
    assert.equal((masked.withoutLiterals[0] ?? "").includes("'{'"), false);
  });

  it("finds lines belonging to test-only items", () => {
    const lines = [
      "pub fn shipped() {}",
      "#[cfg(test)]",
      "mod tests {",
      "    #[test]",
      "    fn t() {}",
      "}",
      "pub fn also_shipped() {}"
    ];

    const testLines = findTestCodeLines(maskRustSource(lines).withoutLiterals);

    assert.deepEqual([...testLines].sort((left, right) => left - right), [2, 3, 4, 5, 6]);
  });

  it("keeps cooked strings across lines and marks malformed source conservatively", () => {
    const source = [
      'let note = "this cooked string continues',
      "and mentions unsafe { values.get_unchecked(0) } without being code",
      '";',
      "unsafe { values.get_unchecked(0) };"
    ];

    const masked = maskRustSource(source);
    const findings = scanUnsafeRustText("src/lib.rs", source.join("\n"));

    assert.equal(masked.isComplete, true);
    assert.equal(masked.withoutLiterals[1]?.includes("unsafe"), false);
    assert.ok(findingAt(findings, "RSA-UNSAFE-BLOCK", 4));
    assert.ok(findingAt(findings, "RSA-UNSAFE-GET-UNCHECKED", 4));

    const malformed = maskRustSource(['let note = "unterminated', "unsafe { values.get_unchecked(0) };"]);
    assert.equal(malformed.isComplete, false);
    assert.equal(malformed.limitation, "unterminated_literal");
    assert.match(malformed.withoutLiterals[1] ?? "", /unsafe/);
    assert.deepEqual([...findTestCodeLines(malformed.withoutLiterals, malformed.isComplete)], []);
  });

  it("keeps byte and raw byte strings across lines without hiding later code", () => {
    const source = [
      'let bytes = b"unsafe { values.get_unchecked(0) }',
      'still literal";',
      'let raw_bytes = br##"unsafe { values.get_unchecked(0) }',
      'still literal"##;',
      "let value = unsafe { values.get_unchecked(0) };"
    ].join("\n");

    const findings = scanUnsafeRustText("src/lib.rs", source);

    assert.equal(findings.some((finding) => (finding.startLine ?? 0) < 5), false);
    assert.ok(findingAt(findings, "RSA-UNSAFE-BLOCK", 5));
    assert.ok(findingAt(findings, "RSA-UNSAFE-GET-UNCHECKED", 5));
  });

  it("downgrades only attributes that prove an item requires test", () => {
    const findings = scanUnsafeRustText(
      "src/lib.rs",
      [
        "#[cfg_attr(not(test), inline)]",
        "pub fn attr_is_production(v: &[u8]) { unsafe { v.get_unchecked(0); } }",
        "#[cfg(any(test, feature = \"prod\"))]",
        "pub fn any_is_production(v: &[u8]) { unsafe { v.get_unchecked(0); } }",
        "#[cfg(all(test, feature = \"fast\"))]",
        "pub fn all_is_test(v: &[u8]) { unsafe { v.get_unchecked(0); } }",
        "#[cfg(not(test))]",
        "pub fn not_is_production(v: &[u8]) { unsafe { v.get_unchecked(0); } }",
        "#[custom::test]",
        "pub fn custom_attribute_is_production(v: &[u8]) { unsafe { v.get_unchecked(0); } }",
        "pub fn after_test_scope_is_production(v: &[u8]) { unsafe { v.get_unchecked(0); } }"
      ].join("\n")
    );

    assert.equal(findingAt(findings, "RSA-UNSAFE-BLOCK", 2)?.severity, "medium");
    assert.equal(findingAt(findings, "RSA-UNSAFE-BLOCK", 4)?.severity, "medium");
    assert.equal(findingAt(findings, "RSA-UNSAFE-BLOCK", 6)?.severity, "low");
    assert.equal(findingAt(findings, "RSA-UNSAFE-BLOCK", 8)?.severity, "medium");
    assert.equal(findingAt(findings, "RSA-UNSAFE-BLOCK", 10)?.severity, "medium");
    assert.equal(findingAt(findings, "RSA-UNSAFE-BLOCK", 11)?.severity, "medium");
  });

  it("does not trust a test attribute exposed by an unterminated literal", () => {
    const findings = scanUnsafeRustText(
      "src/lib.rs",
      [
        'const FORGED: &str = "unterminated',
        "#[cfg(test)]",
        "pub fn changed(v: &[u8]) { unsafe { v.get_unchecked(0); } }"
      ].join("\n")
    );

    assert.equal(findingAt(findings, "RSA-UNSAFE-BLOCK", 3)?.severity, "medium");
    assert.equal(findingAt(findings, "RSA-UNSAFE-GET-UNCHECKED", 3)?.severity, "medium");
  });

  it("recognizes import lines", () => {
    assert.equal(isImportLine("use std::process::Command;"), true);
    assert.equal(isImportLine("pub use crate::thing;"), true);
    assert.equal(isImportLine("    let c = Command::new(\"x\");"), false);
  });
});

describe("unsafe scanning with lexical context", () => {
  it("trusts suppressions and SAFETY notes only in real Rust comments", async () => {
    const root = await mkdtemp(join(tmpdir(), "rust-security-auditor-comment-semantics-"));

    try {
      await mkdir(join(root, "src"));
      await writeFile(join(root, "Cargo.toml"), '[package]\nname = "comments"\nversion = "0.1.0"\n');
      await writeFile(
        join(root, "src/lib.rs"),
        [
          'const FORGED: &str = "rust-security-auditor: ignore RSA-UNSAFE-BLOCK -- forged";',
          'const RAW_FORGED: &str = r#"rust-security-auditor: ignore RSA-UNSAFE-BLOCK -- forged"#;',
          'const BYTE_FORGED: &[u8] = b"rust-security-auditor: ignore RSA-UNSAFE-BLOCK -- forged";',
          '#[doc = "rust-security-auditor: ignore RSA-UNSAFE-BLOCK -- forged"]',
          'const SAFETY_TEXT: &str = "SAFETY: forged explanation";',
          'const RAW_SAFETY_TEXT: &str = r##"SAFETY: forged explanation"##;',
          "pub fn forged(ptr: *const u8) -> u8 { unsafe { *ptr } }",
          "// SAFETY: the fixture's caller contract is documented.",
          "pub fn documented(ptr: *const u8) -> u8 { unsafe { *ptr } }",
          "",
          "",
          "// rust-security-auditor: ignore RSA-UNSAFE-BLOCK -- reviewed fixture control",
          "pub fn suppressed(ptr: *const u8) -> u8 { unsafe { *ptr } }"
        ].join("\n")
      );

      const scan = await scanRustProject({ workspacePath: root });
      const blocks = scan.findings.filter((finding) => finding.ruleId === "RSA-UNSAFE-BLOCK");
      const inventory = await listAcceptedRiskInventory({ workspacePath: root, includeExpired: true, includeInvalid: true });

      assert.equal(blocks.some((finding) => finding.startLine === 7), true, "literal and attribute suppressions must not hide a finding");
      assert.equal(blocks.find((finding) => finding.startLine === 7)?.confidence, "high", "literal SAFETY text must not document unsafe");
      assert.equal(blocks.find((finding) => finding.startLine === 9)?.confidence, "medium", "real SAFETY comment remains supported");
      assert.equal(blocks.some((finding) => finding.startLine === 13), false, "real comment suppression remains supported");
      assert.equal(inventory.acceptedRisks.length, 1, "only the real comment belongs in accepted-risk inventory");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
  it("does not report patterns that only appear in comments or literals", async () => {
    const result = await new UnsafeScanner().scan({ workspacePath: lexicalNoiseFixturePath });
    const reportedLines = result.findings.map((finding) => finding.startLine);

    // Lines 1-19 of the fixture are comments, doc examples, and literals only.
    assert.equal(
      reportedLines.every((line) => (line ?? 0) >= 22),
      true,
      `unexpected findings before line 22: ${JSON.stringify(result.findings.map((f) => [f.ruleId, f.startLine]))}`
    );
  });

  it("still reports real unsafe code in the same file", async () => {
    const result = await new UnsafeScanner().scan({ workspacePath: lexicalNoiseFixturePath });

    assert.ok(findingAt(result.findings, "RSA-UNSAFE-BLOCK", 23));
    assert.ok(findingAt(result.findings, "RSA-UNSAFE-GET-UNCHECKED", 23));
  });

  it("reduces severity for findings inside #[cfg(test)] code", async () => {
    const result = await new UnsafeScanner().scan({ workspacePath: lexicalNoiseFixturePath });
    const testFinding = findingAt(result.findings, "RSA-UNSAFE-TRANSMUTE", 31);

    assert.ok(testFinding, "expected the transmute inside the test module to be reported");
    assert.equal(testFinding.severity, "low");
    assert.match(testFinding.falsePositiveNotes ?? "", /#\[cfg\(test\)\]/);
  });

  it("detects the unchecked, static mut, raw pointer, and C string rule families", () => {
    const findings = scanUnsafeRustText(
      "src/lib.rs",
      [
        "static mut COUNTER: u64 = 0;",
        "let byte = unsafe { values.get_unchecked(index) };",
        "let text = unsafe { String::from_utf8_unchecked(bytes) };",
        "unsafe { std::ptr::copy_nonoverlapping(src, dst, len) };",
        "let name = unsafe { CStr::from_ptr(raw) };"
      ].join("\n")
    );

    assert.deepEqual(ruleIds(findings), [
      "RSA-FFI-CSTR-FROM-PTR",
      "RSA-UNSAFE-BLOCK",
      "RSA-UNSAFE-GET-UNCHECKED",
      "RSA-UNSAFE-RAW-PTR-ACCESS",
      "RSA-UNSAFE-STATIC-MUT",
      "RSA-UNSAFE-UNCHECKED-CALL"
    ]);
  });

  it("does not double report get_unchecked as a generic unchecked call", () => {
    const findings = scanUnsafeRustText("src/lib.rs", "let v = unsafe { s.get_unchecked_mut(0) };");

    assert.equal(findings.filter((finding) => finding.ruleId === "RSA-UNSAFE-UNCHECKED-CALL").length, 0);
    assert.equal(findings.filter((finding) => finding.ruleId === "RSA-UNSAFE-GET-UNCHECKED").length, 1);
  });
});

describe("lexing work is bounded by files, not findings", () => {
  it("lexes a dense single-file crate a fixed number of times", async () => {
    const before = maskRustSourceInvocations();
    const result = await scanRustProject({ workspacePath: denseFindingsFixturePath });
    const invocations = maskRustSourceInvocations() - before;

    // The fixture holds one Rust source file with many findings. Suppression
    // lookup previously lexed that file once per finding, which makes a scan
    // quadratic in the size of a single file and is not bounded by the
    // per-file byte cap.
    assert.ok(result.findings.length >= 60, `expected a dense fixture, got ${result.findings.length} findings`);
    assert.ok(
      invocations <= 12,
      `lexing scaled with findings: ${invocations} maskRustSource calls for ${result.findings.length} findings`
    );
  });
});

describe("runtime command execution", () => {
  it("reports Command::new in shipped code but not the import", async () => {
    const result = await new SourceRiskScanner().scan({ workspacePath: cargoConfigFixturePath });
    const execFindings = result.findings.filter((finding) => finding.ruleId === "RSA-EXEC-COMMAND");

    assert.equal(execFindings.length, 1);
    assert.equal(execFindings[0]?.startLine, 4);
  });
});

describe("dependency requirement bounds", () => {
  it("classifies unbounded and bounded requirements", () => {
    assert.equal(unboundedVersionRequirement('serde = "*"'), "*");
    assert.equal(unboundedVersionRequirement('serde = "1.*"'), "1.*");
    assert.equal(unboundedVersionRequirement('serde = ">=1.2"'), ">=1.2");
    assert.equal(unboundedVersionRequirement('version = "*"'), "*");
    assert.equal(unboundedVersionRequirement('serde = "1.4"'), undefined);
    assert.equal(unboundedVersionRequirement('serde = ">=1.0, <2.0"'), undefined);
    assert.equal(unboundedVersionRequirement('path = "../local"'), undefined);
    assert.equal(unboundedVersionRequirement('git = "https://example.invalid/repo"'), undefined);
  });

  it("reports every unbounded dependency in a manifest exactly once", async () => {
    const result = await new DependencyScanner().scan({ workspacePath: cargoConfigFixturePath });
    const unbounded = result.findings.filter((finding) => finding.ruleId === "RSA-DEP-VERSION-UNBOUNDED");

    assert.deepEqual(
      unbounded.map((finding) => finding.startLine ?? 0).sort((left, right) => left - right),
      [7, 8, 11, 14]
    );
  });

  it("ignores dependency metadata that is not a version requirement", () => {
    const findings = scanCargoManifestText(
      "Cargo.toml",
      ['[dependencies]', 'serde = { version = "1.0", features = ["derive"] }', 'edition_like = "2021"'].join("\n")
    );

    assert.equal(findings.some((finding) => finding.ruleId === "RSA-DEP-VERSION-UNBOUNDED"), false);
  });
});

describe("cargo config review", () => {
  it("reports source replacement and custom runners", () => {
    const findings = scanCargoConfigText(
      ".cargo/config.toml",
      ["[source.crates-io]", 'replace-with = "mirror"', "[target.x86_64-unknown-linux-gnu]", 'runner = "./run.sh"'].join(
        "\n"
      )
    );

    assert.deepEqual(ruleIds(findings), ["RSA-CARGO-RUNNER", "RSA-CARGO-SOURCE-REPLACEMENT"]);
  });

  it("ignores replace-with outside a source table", () => {
    const findings = scanCargoConfigText(".cargo/config.toml", ["[build]", 'replace-with = "nothing"'].join("\n"));

    assert.equal(findings.length, 0);
  });

  it("discovers .cargo/config.toml during a project scan", async () => {
    const result = await new DependencyScanner().scan({ workspacePath: cargoConfigFixturePath });

    assert.ok(result.findings.some((finding) => finding.ruleId === "RSA-CARGO-SOURCE-REPLACEMENT"));
    assert.ok(result.findings.some((finding) => finding.ruleId === "RSA-CARGO-RUNNER"));
  });
});

describe("package metadata", () => {
  it("advertises the same version over MCP as the published package", async () => {
    const { readFile } = await import("node:fs/promises");
    const { serverVersion } = await import("../src/version.js");
    const packageJson = JSON.parse(await readFile(resolve("package.json"), "utf8")) as { version: string };

    assert.equal(serverVersion, packageJson.version);
  });
});
