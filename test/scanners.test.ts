import assert from "node:assert/strict";
import { mkdir, mkdtemp, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { renderJsonReport, renderMarkdownReport, type Finding } from "../src/reports/index.js";
import { dedupeFindings, sortFindings } from "../src/scanners/resultUtils.js";
import {
  allRules,
  collectWorkspaceFiles,
  DependencyScanner,
  ProjectScanner,
  SafeSourceReader,
  UnsafeScanner,
  scanRustProject,
  ruleHasToolScope,
  toRustAuditReportInput
} from "../src/scanners/index.js";

const vulnerableFixturePath = resolve("test/fixtures/vulnerable-rust-project");
const safeFixturePath = resolve("test/fixtures/safe-rust-project");
const unsafeDocumentedFixturePath = resolve("test/fixtures/unsafe-documented");
const dependencyRiskFixturePath = resolve("test/fixtures/dependency-risk");
const suppressedFixturePath = resolve("test/fixtures/suppressed-rust-project");

describe("rule metadata", () => {
  it("defines complete metadata for every scanner rule", () => {
    assert.ok(allRules.length >= 10);

    for (const rule of allRules) {
      assert.ok(rule.ruleId.length > 0);
      assert.ok(rule.title.length > 0);
      assert.ok(rule.category.length > 0);
      assert.ok(rule.severity.length > 0);
      assert.ok(rule.confidence.length > 0);
      assert.ok(rule.description.length > 0);
      assert.ok(rule.whyItMatters.length > 0);
      assert.ok(rule.remediation.length > 0);
      assert.ok(rule.toolScopes.length > 0);
    }

    assert.equal(ruleHasToolScope("RSA-CARGO-SOURCE-REPLACEMENT", "dependency"), true);
    assert.equal(ruleHasToolScope("RSA-CARGO-RUNNER", "dependency"), true);
    assert.equal(ruleHasToolScope("RSA-CARGO-RUNNER", "unsafe"), false);
  });
});

describe("project scanner", () => {
  it("identifies Cargo manifests, lockfiles, workspace metadata, build scripts, and Rust sources", async () => {
    const result = await new ProjectScanner().scan({ workspacePath: vulnerableFixturePath });

    assert.equal(result.project.isRustProject, true);
    assert.deepEqual(
      result.project.cargoTomlFiles.map((file) => file.file),
      ["Cargo.toml", "crates/local_dep/Cargo.toml"]
    );
    assert.deepEqual(
      result.project.cargoLockFiles.map((file) => file.file),
      ["Cargo.lock"]
    );
    assert.deepEqual(
      result.project.buildScripts.map((file) => file.file),
      ["build.rs"]
    );
    assert.deepEqual(result.project.workspaceManifests[0]?.members, ["crates/local_dep"]);
    assert.ok(result.project.rustSourceFiles.some((file) => file.file === "src/lib.rs"));
  });
});

describe("bounded source reader", () => {
  it("caches content and enforces root, file-count, and concurrency boundaries", async () => {
    const root = await mkdtemp(join(tmpdir(), "rust-security-auditor-reader-"));
    const outside = await mkdtemp(join(tmpdir(), "rust-security-auditor-reader-outside-"));

    try {
      await mkdir(join(root, "src"));
      await writeFile(join(root, "src/a.rs"), "pub fn a() {}\n");
      await writeFile(join(root, "src/b.rs"), "pub fn b() {}\n");
      await writeFile(join(outside, "outside.rs"), "pub fn outside() {}\n");
      const reader = new SafeSourceReader(root, { maxFiles: 2, maxConcurrency: 1 });

      const [first, cached, second, escaped] = await Promise.all([
        reader.readTextLines(join(root, "src/a.rs"), "src/a.rs", "rust", "unsafe_scan"),
        reader.readTextLines(join(root, "src/a.rs"), "src/a.rs", "rust", "suppression"),
        reader.readTextLines(join(root, "src/b.rs"), "src/b.rs", "rust", "source_risk_scan"),
        reader.readTextLines(join(outside, "outside.rs"), "../outside.rs", "rust", "unsafe_scan")
      ]);

      assert.equal(first?.[0], "pub fn a() {}");
      assert.deepEqual(cached, first);
      assert.equal(second?.[0], "pub fn b() {}");
      assert.equal(escaped, undefined);
      assert.deepEqual(reader.readStats(), { openedFiles: 2, maxObservedConcurrency: 1 });
      assert.ok(reader.coverage().entries.some((entry) => entry.reason === "outside_workspace"));
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("rejects an in-root path when an ancestor is replaced by a symbolic link", async () => {
    const root = await mkdtemp(join(tmpdir(), "rust-security-auditor-reader-ancestor-"));
    const outside = await mkdtemp(join(tmpdir(), "rust-security-auditor-reader-ancestor-outside-"));

    try {
      await mkdir(join(root, "src"));
      await writeFile(join(root, "src/lib.rs"), "pub fn inside() {}\n");
      await writeFile(join(outside, "lib.rs"), "outside-controlled-proof\n");
      const reader = new SafeSourceReader(root);

      await rename(join(root, "src"), join(root, "src-before-link"));
      await symlink(outside, join(root, "src"));

      const lines = await reader.readTextLines(join(root, "src/lib.rs"), "src/lib.rs", "rust", "unsafe_scan");

      assert.equal(lines, undefined);
      assert.ok(
        reader.coverage().entries.some(
          (entry) => entry.file === "src/lib.rs" && entry.status === "incomplete" && entry.reason === "symbolic_link"
        )
      );
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("does not recurse into an in-root directory symbolic link during discovery", async () => {
    const root = await mkdtemp(join(tmpdir(), "rust-security-auditor-discovery-link-"));
    const outside = await mkdtemp(join(tmpdir(), "rust-security-auditor-discovery-link-outside-"));

    try {
      await writeFile(join(outside, "escaped.rs"), "pub fn escaped() {}\n");
      await symlink(outside, join(root, "src"));
      const reader = new SafeSourceReader(root);

      const result = await collectWorkspaceFiles(root, {}, reader);

      assert.equal(result.files.includes(join(root, "src", "escaped.rs")), false);
      assert.ok(result.warnings.some((warning) => warning.includes("symbolic link")));
      assert.ok(
        reader.coverage().entries.some(
          (entry) => entry.file === "src" && entry.status === "incomplete" && entry.reason === "symbolic_link"
        )
      );
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("keeps prior relevant incomplete coverage after a later auxiliary read succeeds", async () => {
    const root = await mkdtemp(join(tmpdir(), "rust-security-auditor-reader-coverage-"));

    try {
      await mkdir(join(root, "src"));
      await writeFile(join(root, "src/lib.rs"), "pub fn changed() {}\n");
      const reader = new SafeSourceReader(root);
      reader.recordIncomplete(
        "src/lib.rs",
        "rust",
        "diff_selection",
        "missing_current_input",
        "Current changed Rust input was not discovered for scanning.",
        true
      );

      const lines = await reader.readTextLines(join(root, "src/lib.rs"), "src/lib.rs", "rust", "rust_context");
      const coverage = reader.coverage().entries.find((entry) => entry.file === "src/lib.rs");

      assert.equal(lines?.[0], "pub fn changed() {}");
      assert.deepEqual(coverage, {
        status: "incomplete",
        file: "src/lib.rs",
        inputType: "rust",
        stage: "diff_selection",
        reason: "missing_current_input",
        message: "Current changed Rust input was not discovered for scanning.",
        relevantToDiff: true
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects a requested project root that is replaced by a symbolic link", async () => {
    const container = await mkdtemp(join(tmpdir(), "rust-security-auditor-reader-root-link-"));
    const root = join(container, "project");
    const outside = await mkdtemp(join(tmpdir(), "rust-security-auditor-reader-root-link-outside-"));

    try {
      await mkdir(join(root, "src"), { recursive: true });
      await writeFile(join(root, "src/lib.rs"), "pub fn inside() {}\n");
      await mkdir(join(outside, "src"));
      await writeFile(join(outside, "src/lib.rs"), "outside-controlled-proof\n");
      const reader = new SafeSourceReader(root);

      await rename(root, join(container, "project-before-link"));
      await symlink(outside, root);

      const lines = await reader.readTextLines(join(root, "src/lib.rs"), "src/lib.rs", "rust", "unsafe_scan");

      assert.equal(lines, undefined);
      assert.ok(reader.coverage().entries.some((entry) => entry.reason === "symbolic_link"));
    } finally {
      await rm(container, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("enforces byte limits using the opened file metadata", async () => {
    const root = await mkdtemp(join(tmpdir(), "rust-security-auditor-reader-opened-size-"));

    try {
      await writeFile(join(root, "oversized.rs"), "x".repeat(32));
      const reader = new SafeSourceReader(root, { maxFileBytes: 8, maxTotalBytes: 8 });

      const lines = await reader.readTextLines(join(root, "oversized.rs"), "oversized.rs", "rust", "unsafe_scan");

      assert.equal(lines, undefined);
      assert.deepEqual(reader.readStats(), { openedFiles: 0, maxObservedConcurrency: 1 });
      assert.ok(reader.coverage().entries.some((entry) => entry.reason === "file_too_large"));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("unsafe scanner", () => {
  it("emits distinct findings for unsafe functions, unsafe impls, unsafe blocks, memory primitives, and extern C", async () => {
    const project = (await new ProjectScanner().scan({ workspacePath: vulnerableFixturePath })).project;
    const result = await new UnsafeScanner().scan({ workspacePath: vulnerableFixturePath, project });
    const ruleIds = new Set(result.findings.map((finding) => finding.ruleId));

    assert.ok(ruleIds.has("RSA-UNSAFE-FN"));
    assert.ok(ruleIds.has("RSA-UNSAFE-IMPL-SEND"));
    assert.ok(ruleIds.has("RSA-UNSAFE-IMPL-SYNC"));
    assert.ok(ruleIds.has("RSA-FFI-EXTERN-C"));
    assert.ok(ruleIds.has("RSA-UNSAFE-BLOCK"));
    assert.ok(ruleIds.has("RSA-UNSAFE-TRANSMUTE"));
    assert.ok(ruleIds.has("RSA-UNSAFE-MAYBEUNINIT"));
    assert.ok(ruleIds.has("RSA-UNSAFE-FROM-RAW-PARTS"));
    assert.ok(ruleIds.has("RSA-UNSAFE-SET-LEN"));
    assert.ok(ruleIds.has("RSA-UNSAFE-BOX-FROM-RAW"));
    assertRequiredFindingFields(result.findings);
  });

  it("keeps documented unsafe findings but lowers unsafe-block confidence", async () => {
    const result = await scanRustProject({ workspacePath: unsafeDocumentedFixturePath });
    const unsafeBlock = result.findings.find((finding) => finding.ruleId === "RSA-UNSAFE-BLOCK");

    assert.ok(unsafeBlock);
    assert.equal(unsafeBlock.confidence, "medium");
    assert.match(unsafeBlock.evidence.join("\n"), /SAFETY:/);
    assert.match(unsafeBlock.falsePositiveNotes ?? "", /Nearby Safety comment/);
  });
});

describe("dependency scanner", () => {
  it("emits findings for Cargo and build.rs supply-chain risk clues", async () => {
    const project = (await new ProjectScanner().scan({ workspacePath: dependencyRiskFixturePath })).project;
    const result = await new DependencyScanner().scan({ workspacePath: dependencyRiskFixturePath, project });
    const ruleIds = new Set(result.findings.map((finding) => finding.ruleId));

    assert.ok(ruleIds.has("RSA-DEP-GIT"));
    assert.ok(ruleIds.has("RSA-DEP-LOCK-GIT"));
    assert.ok(ruleIds.has("RSA-DEP-PATH"));
    assert.ok(ruleIds.has("RSA-DEP-PROC-MACRO"));
    assert.ok(ruleIds.has("RSA-DEP-BUILD-DEPENDENCIES"));
    assert.ok(ruleIds.has("RSA-BUILD-SCRIPT"));
    assert.ok(ruleIds.has("RSA-BUILD-COMMAND"));
    assert.equal(result.findings[0]?.ruleId, "RSA-BUILD-COMMAND");
    assert.equal(result.findings[0]?.severity, "high");
    assertRequiredFindingFields(result.findings);
  });
});

describe("rust project scan", () => {
  it("returns Finding[] that render through existing JSON and Markdown reporters", async () => {
    const result = await scanRustProject({ workspacePath: vulnerableFixturePath });
    const reportInput = toRustAuditReportInput(result, {
      generatedAt: "2026-05-16T00:00:00.000Z"
    });

    assertRequiredFindingFields(result.findings);
    assert.ok(result.findings.length >= 10);

    const json = JSON.parse(renderJsonReport(reportInput)) as { findings: Finding[]; summary: { total: number } };
    const markdown = renderMarkdownReport(reportInput);

    assert.equal(json.summary.total, result.findings.length);
    assert.match(markdown, /## High Risk Findings/);
    assert.match(markdown, /Git dependency requires supply-chain review/);
    assert.match(markdown, /Unsafe function requires a caller safety contract/);
    assert.match(markdown, /- Rule: RSA-UNSAFE-FN/);
  });

  it("tracks valid, invalid, and expired accepted-risk suppressions", async () => {
    const result = await scanRustProject({ workspacePath: suppressedFixturePath });
    const suppressedFindings = result.suppressedFindings ?? [];
    const activeSuppressions = suppressedFindings.filter((suppression) => suppression.isValid && !suppression.isExpired);
    const invalidSuppressions = suppressedFindings.filter((suppression) => !suppression.isValid);
    const expiredSuppressions = suppressedFindings.filter((suppression) => suppression.isExpired);

    assert.equal(result.findings.filter((finding) => finding.ruleId === "RSA-UNSAFE-BLOCK").length, 2);
    assert.equal(result.suppressedCount, 4);
    assert.equal(result.expiredSuppressionCount, 1);
    assert.equal(result.invalidSuppressionCount, 1);
    assert.equal(suppressedFindings.length, 6);
    assert.equal(activeSuppressions.length, 4);
    assert.equal(invalidSuppressions[0]?.invalidSuppression?.includes("reason is required"), true);
    assert.equal(expiredSuppressions[0]?.until, "2000-01-01");
    assert.equal(expiredSuppressions[0]?.isExpired, true);
    assert.ok(activeSuppressions.some((suppression) => suppression.reason.includes("legacy FFI wrapper")));
    assert.ok(activeSuppressions.some((suppression) => suppression.owner === "@security"));
    assert.ok(activeSuppressions.some((suppression) => suppression.ticket === "SEC-123"));
    assert.ok(activeSuppressions.some((suppression) => suppression.until === "2999-12-31"));
    assert.ok(suppressedFindings.every((suppression) => suppression.rawComment.includes("rustsec-auditor: ignore")));
    assert.match(result.warnings.join("\n"), /invalid accepted-risk suppression/);
    assert.match(result.warnings.join("\n"), /expired accepted-risk suppression/);
  });

  it("keeps the safe fixture much quieter than the vulnerable fixture", async () => {
    const safe = await scanRustProject({ workspacePath: safeFixturePath });
    const vulnerable = await scanRustProject({ workspacePath: vulnerableFixturePath });

    assert.equal(safe.findings.length, 0);
    assert.ok(vulnerable.findings.length >= 10);
    assert.ok(safe.findings.length < vulnerable.findings.length / 3);
  });

  it("deduplicates by file, line, and ruleId and sorts by severity, confidence, file, and line", () => {
    const duplicate: Finding = {
      id: "duplicate",
      ruleId: "RSA-DEP-PATH",
      title: "Path dependency needs local trust boundary review",
      severity: "low",
      confidence: "high",
      category: "dependency",
      file: "b/Cargo.toml",
      startLine: 5,
      evidence: ["Line 5: dep = { path = \"../dep\" }"],
      whyItMatters: "Path dependencies are local trust boundaries.",
      riskScenario: "A local dependency changes without review.",
      suggestedFix: "Keep local dependencies inside the reviewed workspace."
    };
    const high: Finding = {
      ...duplicate,
      id: "high",
      ruleId: "RSA-BUILD-COMMAND",
      title: "Build script spawns an external command",
      severity: "high",
      category: "command_execution",
      file: "a/build.rs",
      startLine: 10
    };
    const medium: Finding = {
      ...duplicate,
      id: "medium",
      ruleId: "RSA-DEP-GIT",
      title: "Git dependency requires supply-chain review",
      severity: "medium",
      category: "supply_chain",
      file: "a/Cargo.toml",
      startLine: 3
    };

    const sorted = sortFindings(dedupeFindings([duplicate, high, { ...duplicate, id: "duplicate-2" }, medium]));

    assert.deepEqual(
      sorted.map((finding) => finding.id),
      ["high", "medium", "duplicate"]
    );
  });
});

function assertRequiredFindingFields(findings: readonly Finding[]): void {
  for (const finding of findings) {
    assert.ok(finding.ruleId.length > 0);
    assert.ok(finding.file.length > 0);
    if (finding.startLine === undefined) {
      assert.fail(`Finding ${finding.id} is missing startLine`);
    }
    assert.ok(finding.startLine > 0);
    assert.ok(finding.category.length > 0);
    assert.ok(finding.severity.length > 0);
    assert.ok(finding.confidence.length > 0);
    assert.ok(finding.evidence.length > 0);
  }
}
