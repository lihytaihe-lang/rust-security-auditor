import assert from "node:assert/strict";
import { resolve } from "node:path";
import { describe, it } from "node:test";
import { renderJsonReport, renderMarkdownReport, type Finding } from "../src/reports/index.js";
import { dedupeFindings, sortFindings } from "../src/scanners/resultUtils.js";
import {
  allRules,
  DependencyScanner,
  ProjectScanner,
  UnsafeScanner,
  scanRustProject,
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
    }
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

  it("suppresses ignored rule findings near inline directives", async () => {
    const result = await scanRustProject({ workspacePath: suppressedFixturePath });

    assert.equal(result.findings.some((finding) => finding.ruleId === "RSA-UNSAFE-BLOCK"), false);
    assert.equal(result.suppressedCount, 1);
    assert.equal(result.suppressedFindings?.[0]?.ruleId, "RSA-UNSAFE-BLOCK");
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
