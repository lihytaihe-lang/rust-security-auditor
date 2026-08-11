import assert from "node:assert/strict";
import { resolve } from "node:path";
import { describe, it } from "node:test";
import type { Finding } from "../src/reports/index.js";
import {
  DependencyScanner,
  SourceRiskScanner,
  UnsafeScanner,
  findTestCodeLines,
  isImportLine,
  maskRustSource,
  scanCargoConfigText,
  scanCargoManifestText,
  scanUnsafeRustText,
  unboundedVersionRequirement
} from "../src/scanners/index.js";

const lexicalNoiseFixturePath = resolve("test/fixtures/lexical-noise");
const cargoConfigFixturePath = resolve("test/fixtures/cargo-config-risk");

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

  it("recognizes import lines", () => {
    assert.equal(isImportLine("use std::process::Command;"), true);
    assert.equal(isImportLine("pub use crate::thing;"), true);
    assert.equal(isImportLine("    let c = Command::new(\"x\");"), false);
  });
});

describe("unsafe scanning with lexical context", () => {
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
