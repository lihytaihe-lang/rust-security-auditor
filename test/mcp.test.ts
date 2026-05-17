import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  createRustSecurityAuditorMcpServer,
  type DiffAwareFinding,
  mcpToolNames,
  type McpAuditToolOutput,
  rustAuditDependencies,
  rustAuditProject,
  rustAuditUnsafe,
  rustListAcceptedRisks,
  rustReviewCurrentDiff
} from "../src/mcp/index.js";
import { actionabilityForDiffFinding, inferReviewDecision } from "../src/mcp/reviewDecision.js";
import type { Finding } from "../src/reports/index.js";
import { runShellCommandOrThrow } from "../src/utils/shell.js";

const vulnerableFixturePath = resolve("test/fixtures/vulnerable-rust-project");
const dependencyRiskFixturePath = resolve("test/fixtures/dependency-risk");
const unsafeDocumentedFixturePath = resolve("test/fixtures/unsafe-documented");
const suppressedFixturePath = resolve("test/fixtures/suppressed-rust-project");

describe("MCP audit tools", () => {
  it("lists MCP tools through an MCP client transport", async () => {
    await withMcpClient(async (client) => {
      const result = await client.listTools();
      const toolNames = result.tools.map((tool) => tool.name).sort();

      assert.deepEqual(toolNames, [...mcpToolNames].sort());
      assert.match(
        result.tools.find((tool) => tool.name === "rust_audit_project")?.description ?? "",
        /release|full-project/i
      );
      assert.match(
        result.tools.find((tool) => tool.name === "rust_audit_unsafe")?.description ?? "",
        /unsafe \/ FFI|unsafe/i
      );
      assert.match(
        result.tools.find((tool) => tool.name === "rust_audit_dependencies")?.description ?? "",
        /Cargo|supply-chain/i
      );
      assert.match(
        result.tools.find((tool) => tool.name === "rust_review_current_diff")?.description ?? "",
        /commit|PR/i
      );
      assert.match(
        result.tools.find((tool) => tool.name === "rust_list_accepted_risks")?.description ?? "",
        /release|suppression|expired/i
      );
    });
  });

  it("calls an MCP tool through an MCP client transport", async () => {
    await withMcpClient(async (client) => {
      const result = await client.callTool({
        name: "rust_audit_dependencies",
        arguments: {
          projectPath: dependencyRiskFixturePath
        }
      });

      assert.equal("content" in result, true);
      assert.equal(result.isError, false);

      const output = result.structuredContent as unknown as McpAuditToolOutput;
      assert.equal(output.tool, "rust_audit_dependencies");
      assert.equal(output.error, undefined);
      assert.ok(output.findings.length > 0);
      assert.ok(output.findings.every((finding) => finding.ruleId.startsWith("RSA-DEP-") || finding.ruleId.startsWith("RSA-BUILD-")));
    });
  });

  it("calls rust_list_accepted_risks through an MCP client transport", async () => {
    await withMcpClient(async (client) => {
      const result = await client.callTool({
        name: "rust_list_accepted_risks",
        arguments: {
          projectPath: suppressedFixturePath,
          includeExpired: true,
          includeInvalid: true,
          outputFormat: "json"
        }
      });

      assert.equal("content" in result, true);
      assert.equal(result.isError, false);

      const output = result.structuredContent as Awaited<ReturnType<typeof rustListAcceptedRisks>>;
      assert.equal(output.tool, "rust_list_accepted_risks");
      assert.equal(output.error, undefined);
      assert.equal(output.acceptedRisks.length, 6);
    });
  });

  it("rust_audit_project scans a vulnerable Rust fixture and returns structured output", async () => {
    const output = await rustAuditProject({
      projectPath: vulnerableFixturePath,
      outputFormat: "markdown"
    });

    assert.equal(output.tool, "rust_audit_project");
    assert.equal(output.projectPath, vulnerableFixturePath);
    assert.equal(output.error, undefined);
    assert.ok(output.summary.findingCount >= 10);
    assert.equal(output.summary.findingCount, output.findings.length);
    assert.equal(output.summary.riskLevel, "high_risk");
    assert.ok(output.summary.severityCounts.high >= 1);
    assert.match(output.reportMarkdown ?? "", /# Rust Project Security Audit/);
  });

  it("rust_audit_unsafe only returns unsafe, FFI, and unsafe impl related findings", async () => {
    const output = await rustAuditUnsafe({
      projectPath: vulnerableFixturePath
    });

    assert.equal(output.error, undefined);
    assert.ok(output.findings.length > 0);
    assert.ok(
      output.findings.every(
        (finding) => finding.ruleId.startsWith("RSA-UNSAFE-") || finding.ruleId.startsWith("RSA-FFI-")
      )
    );
    assert.ok(output.findings.some((finding) => finding.ruleId === "RSA-UNSAFE-IMPL-SEND"));
    assert.ok(output.findings.some((finding) => finding.ruleId === "RSA-FFI-EXTERN-C"));
    assert.equal(output.findings.some((finding) => finding.ruleId.startsWith("RSA-DEP-")), false);
  });

  it("rust_audit_unsafe can omit documented unsafe block findings", async () => {
    const output = await rustAuditUnsafe({
      projectPath: unsafeDocumentedFixturePath,
      includeDocumentedUnsafe: false
    });

    assert.equal(output.error, undefined);
    assert.equal(output.findings.some((finding) => finding.ruleId === "RSA-UNSAFE-BLOCK"), false);
  });

  it("rust_audit_dependencies only returns dependency, build, and supply-chain findings", async () => {
    const output = await rustAuditDependencies({
      projectPath: dependencyRiskFixturePath
    });

    assert.equal(output.error, undefined);
    assert.ok(output.findings.length > 0);
    assert.ok(
      output.findings.every(
        (finding) => finding.ruleId.startsWith("RSA-DEP-") || finding.ruleId.startsWith("RSA-BUILD-")
      )
    );
    assert.ok(output.findings.some((finding) => finding.ruleId === "RSA-BUILD-COMMAND"));
    assert.equal(output.findings.some((finding) => finding.ruleId.startsWith("RSA-UNSAFE-")), false);
  });

  it("rust_list_accepted_risks inventories valid, expired, and invalid suppressions", async () => {
    const output = await rustListAcceptedRisks({
      projectPath: suppressedFixturePath,
      includeExpired: true,
      includeInvalid: true,
      outputFormat: "markdown"
    });

    assert.equal(output.tool, "rust_list_accepted_risks");
    assert.equal(output.projectPath, suppressedFixturePath);
    assert.equal(output.error, undefined);
    assert.equal(output.summary.acceptedRiskCount, 4);
    assert.equal(output.summary.expiredCount, 1);
    assert.equal(output.summary.invalidCount, 1);
    assert.deepEqual(output.summary.byRuleId, { "RSA-UNSAFE-BLOCK": 6 });
    assert.deepEqual(output.summary.byOwner, { "(missing)": 5, "@security": 1 });
    assert.equal(output.acceptedRisks.length, 6);
    assert.ok(output.acceptedRisks.some((risk) => risk.isValid && !risk.isExpired && risk.reason.includes("legacy FFI wrapper")));
    assert.ok(output.acceptedRisks.some((risk) => risk.isExpired && risk.until === "2000-01-01"));
    assert.ok(output.acceptedRisks.some((risk) => !risk.isValid && risk.invalidSuppression?.includes("reason is required")));
    assert.ok(output.acceptedRisks.every((risk) => risk.rawComment.includes("rustsec-auditor: ignore")));
    assert.match(output.reportMarkdown ?? "", /## Active Accepted Risks/);
    assert.match(output.reportMarkdown ?? "", /## Expired Suppressions/);
    assert.match(output.reportMarkdown ?? "", /## Invalid Suppressions/);
  });

  it("rust_list_accepted_risks can hide expired and invalid suppressions", async () => {
    const activeOnly = await rustListAcceptedRisks({
      projectPath: suppressedFixturePath,
      includeExpired: false,
      includeInvalid: false,
      outputFormat: "json"
    });
    const withoutInvalid = await rustListAcceptedRisks({
      projectPath: suppressedFixturePath,
      includeExpired: true,
      includeInvalid: false,
      outputFormat: "json"
    });

    assert.equal(activeOnly.acceptedRisks.length, 4);
    assert.equal(activeOnly.acceptedRisks.some((risk) => risk.isExpired), false);
    assert.equal(activeOnly.acceptedRisks.some((risk) => !risk.isValid), false);
    assert.equal(activeOnly.summary.acceptedRiskCount, 4);
    assert.equal(activeOnly.summary.expiredCount, 0);
    assert.equal(activeOnly.summary.invalidCount, 0);

    assert.equal(withoutInvalid.acceptedRisks.length, 5);
    assert.equal(withoutInvalid.acceptedRisks.some((risk) => risk.isExpired), true);
    assert.equal(withoutInvalid.acceptedRisks.some((risk) => !risk.isValid), false);
    assert.equal(withoutInvalid.summary.expiredCount, 1);
    assert.equal(withoutInvalid.summary.invalidCount, 0);
  });

  it("rust_review_current_diff classifies introduced, nearby, and pre-existing findings", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown"
      });

      assert.equal(output.error, undefined);
      assert.deepEqual(output.diffAffectedFiles, ["src/lib.rs"]);
      assert.ok(output.diff?.files[0]?.hunks.some((hunk) => hunk.addedLines.length > 0));
      assert.equal(output.diffReview?.mode, "working_tree");
      assert.equal(output.diffReview?.includePreExisting, false);
      assert.ok((output.diffReview?.relationCounts.introduced_by_diff ?? 0) >= 2);
      assert.ok((output.diffReview?.relationCounts.near_changed_lines ?? 0) >= 2);
      assert.ok((output.diffReview?.relationCounts.pre_existing_in_changed_file ?? 0) >= 2);
      assert.ok((output.diffReview?.hiddenPreExistingCount ?? 0) >= 2);
      assert.ok(output.enrichedFindings?.some((item) => item.diffContext.relation === "introduced_by_diff"));
      assert.ok(output.enrichedFindings?.some((item) => item.diffContext.relation === "near_changed_lines"));
      assert.ok(output.enrichedFindings?.every((item) => item.actionability?.recommendedAction !== undefined));
      assert.equal(
        output.enrichedFindings?.some((item) => item.diffContext.relation === "pre_existing_in_changed_file"),
        false
      );
      assert.equal(output.findings.some((finding) => finding.evidence.join("\n").includes("legacy_far")), false);
      assert.equal(output.reviewDecision?.status, "needs_attention");
      assert.equal(output.reviewDecision?.safeToCommit, false);
      assert.match(output.reportMarkdown ?? "", /## Decision/);
      assert.match(output.reportMarkdown ?? "", /## Needs Manual Review/);
      assert.match(output.reportMarkdown ?? "", /## Accepted \/ Suppressed Risks/);
      assert.match(output.reportMarkdown ?? "", /Hidden pre-existing findings/);
      assert.match(output.reportMarkdown ?? "", /NEEDS ATTENTION/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff blocks introduced high findings", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(
        join(repoPath, "build.rs"),
        [
          "use std::process::Command;",
          "",
          "fn main() {",
          "    let _ = Command::new(\"sh\").arg(\"-c\").arg(\"echo generated\").status();",
          "}"
        ].join("\n") + "\n",
        "utf8"
      );
      await runShellCommandOrThrow("git", ["add", "build.rs"], { cwd: repoPath });

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        staged: true,
        outputFormat: "markdown"
      });

      assert.equal(output.error, undefined);
      assert.equal(output.reviewDecision?.status, "block");
      assert.equal(output.reviewDecision?.safeToCommit, false);
      assert.ok(output.reviewDecision?.blockingFindingIds.some((id) => id.startsWith("RSA-BUILD-COMMAND")));
      const blocker = output.enrichedFindings?.find((item) => item.actionability?.recommendedAction === "fix_before_commit");
      assert.ok(blocker);
      assert.equal(blocker.actionability?.suppressionSuggestion, undefined);
      assert.match(output.reportMarkdown ?? "", /## Decision/);
      assert.match(output.reportMarkdown ?? "", /## Blocking Issues/);
      assert.match(output.reportMarkdown ?? "", /## Suggested Codex Fix Prompts/);
      assert.match(output.reportMarkdown ?? "", /Please fix RSA-BUILD-COMMAND/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff marks introduced medium findings as needs_attention", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath
      });

      assert.equal(output.error, undefined);
      assert.equal(output.reviewDecision?.status, "needs_attention");
      assert.equal(output.reviewDecision?.blockingFindingIds.length, 0);
      assert.ok((output.reviewDecision?.needsManualReviewFindingIds.length ?? 0) > 0);
      assert.ok(output.enrichedFindings?.some((item) => item.actionability?.recommendedAction === "manual_review"));
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("low confidence high findings suggest suppression only if accepted without a hard block", () => {
    const finding = testFinding({
      id: "RSA-BUILD-COMMAND-LOWCONF",
      ruleId: "RSA-BUILD-COMMAND",
      severity: "high",
      confidence: "low",
      category: "command_execution"
    });
    const diffFinding: DiffAwareFinding = {
      finding,
      diffContext: {
        relation: "introduced_by_diff",
        nearestChangedLine: 10,
        distance: 0
      }
    };

    const decision = inferReviewDecision([diffFinding]);
    const actionability = actionabilityForDiffFinding(diffFinding);

    assert.equal(decision.status, "needs_attention");
    assert.deepEqual(decision.blockingFindingIds, []);
    assert.deepEqual(decision.needsManualReviewFindingIds, [finding.id]);
    assert.equal(decision.safeToCommit, false);
    assert.equal(actionability.recommendedAction, "suppress_if_accepted");
    assert.match(actionability.suppressionSuggestion ?? "", /rustsec-auditor: ignore RSA-BUILD-COMMAND/);
  });

  it("rust_review_current_diff reports active, invalid, and expired suppressions", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), suppressedDiffReviewLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown"
      });

      assert.equal(output.error, undefined);
      assert.equal(output.suppressionSummary?.suppressedCount, 1);
      assert.equal(output.suppressionSummary?.expiredSuppressionCount, 1);
      assert.equal(output.suppressionSummary?.invalidSuppressionCount, 1);
      assert.equal(output.summary.suppressedCount, 1);
      assert.equal(output.suppressedFindings?.length, 3);
      assert.equal(output.findings.filter((finding) => finding.ruleId === "RSA-UNSAFE-BLOCK").length, 2);
      assert.equal(output.reviewDecision?.status, "needs_attention");
      assert.equal(output.reviewDecision?.safeToCommit, false);
      assert.ok(output.enrichedFindings?.some((item) => item.suppression?.isExpired === true));
      assert.ok(output.enrichedFindings?.some((item) => item.suppression?.isValid === false));
      assert.match(output.reportMarkdown ?? "", /## Accepted \/ Suppressed Risks/);
      assert.match(output.reportMarkdown ?? "", /Expired suppression: finding is shown again/);
      assert.match(output.warnings?.join("\n") ?? "", /invalid rustsec-auditor suppression/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff passes only low non-blocking introduced findings and reports metrics", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(
        join(repoPath, "Cargo.toml"),
        [
          "[package]",
          "name = \"diff_review_fixture\"",
          "version = \"0.1.0\"",
          "edition = \"2021\"",
          "",
          "[dependencies]",
          "local_dep = { path = \"crates/local_dep\" }"
        ].join("\n") + "\n",
        "utf8"
      );

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath
      });

      assert.equal(output.error, undefined);
      assert.equal(output.reviewDecision?.status, "pass");
      assert.equal(output.reviewDecision?.safeToCommit, true);
      assert.equal(output.findings.length, 1);
      assert.equal(output.findings[0]?.severity, "low");
      assert.equal(output.summary.introducedFindingCount, 1);
      assert.equal(output.summary.nearChangedFindingCount, 0);
      assert.equal(output.summary.preExistingFindingCount, 0);
      assert.equal(output.summary.blockingCount, 0);
      assert.equal(output.summary.manualReviewCount, 0);
      assert.equal(output.summary.nonBlockingCount, 1);
      assert.equal(output.enrichedFindings?.[0]?.actionability?.recommendedAction, "monitor");
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff can include pre-existing findings in changed files", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        includePreExisting: true
      });

      assert.equal(output.error, undefined);
      assert.equal(output.diffReview?.includePreExisting, true);
      assert.equal(output.diffReview?.hiddenPreExistingCount, 0);
      assert.ok(output.enrichedFindings?.some((item) => item.diffContext.relation === "pre_existing_in_changed_file"));
      assert.ok(output.findings.some((finding) => finding.evidence.join("\n").includes("legacy_far")));
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff supports staged diffs", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");
      await runShellCommandOrThrow("git", ["add", "src/lib.rs"], { cwd: repoPath });

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        staged: true
      });

      assert.equal(output.error, undefined);
      assert.equal(output.diffReview?.mode, "staged");
      assert.ok(output.enrichedFindings?.some((item) => item.diffContext.relation === "introduced_by_diff"));
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff supports baseRef/headRef diffs", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");
      await runShellCommandOrThrow("git", ["add", "src/lib.rs"], { cwd: repoPath });
      await runShellCommandOrThrow("git", ["commit", "-m", "introduce unsafe diff"], { cwd: repoPath });

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        baseRef: "HEAD~1",
        headRef: "HEAD"
      });

      assert.equal(output.error, undefined);
      assert.equal(output.diffReview?.mode, "range");
      assert.deepEqual(output.diffAffectedFiles, ["src/lib.rs"]);
      assert.ok(output.enrichedFindings?.some((item) => item.diffContext.relation === "introduced_by_diff"));
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("returns a clear error for invalid projectPath", async () => {
    const output = await rustAuditProject({
      projectPath: resolve("test/fixtures/does-not-exist")
    });

    assert.equal(output.tool, "rust_audit_project");
    assert.equal(output.summary.findingCount, 0);
    assert.equal(output.findings.length, 0);
    assert.equal(output.error?.code, "PROJECT_PATH_NOT_FOUND");
    assert.match(output.error?.message ?? "", /projectPath does not exist/);
  });

  it("returns a clear error when projectPath is not a Rust project", async () => {
    const tempRoot = await mkdtemp(join(tmpdir(), "rust-security-auditor-not-rust-"));

    try {
      const output = await rustAuditProject({
        projectPath: tempRoot
      });

      assert.equal(output.tool, "rust_audit_project");
      assert.equal(output.summary.findingCount, 0);
      assert.equal(output.findings.length, 0);
      assert.equal(output.error?.code, "PROJECT_PATH_NOT_RUST_PROJECT");
      assert.match(output.error?.message ?? "", /not a Rust project/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("returns a clear error when current diff review runs outside a git repo", async () => {
    const tempRoot = await mkdtemp(join(tmpdir(), "rust-security-auditor-no-git-"));
    const projectPath = join(tempRoot, "repo");

    try {
      await cp(vulnerableFixturePath, projectPath, { recursive: true });

      const output = await rustReviewCurrentDiff({
        projectPath
      });

      assert.equal(output.error?.code, "PROJECT_PATH_NOT_GIT_REPO");
      assert.equal(output.findings.length, 0);
      assert.match(output.error?.message ?? "", /Git work tree/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });
});

async function createDiffReviewRepo(): Promise<{ tempRoot: string; repoPath: string }> {
  const tempRoot = await mkdtemp(join(tmpdir(), "rust-security-auditor-diff-"));
  const repoPath = join(tempRoot, "repo");

  await mkdir(join(repoPath, "src"), { recursive: true });
  await writeFile(
    join(repoPath, "Cargo.toml"),
    `[package]
name = "diff_review_fixture"
version = "0.1.0"
edition = "2021"
`,
    "utf8"
  );
  await writeFile(join(repoPath, "src/lib.rs"), initialDiffReviewLibSource(), "utf8");
  await runShellCommandOrThrow("git", ["init"], { cwd: repoPath });
  await runShellCommandOrThrow("git", ["config", "user.email", "tester@example.com"], { cwd: repoPath });
  await runShellCommandOrThrow("git", ["config", "user.name", "Rust Security Auditor Test"], { cwd: repoPath });
  await runShellCommandOrThrow("git", ["add", "."], { cwd: repoPath });
  await runShellCommandOrThrow("git", ["commit", "-m", "initial fixture"], { cwd: repoPath });

  return { tempRoot, repoPath };
}

function initialDiffReviewLibSource(): string {
  return `${[
    "pub fn stable() -> u8 {",
    "    1",
    "}",
    "",
    "pub unsafe fn legacy_near(ptr: *const u8) -> u8 {",
    "    unsafe { *ptr }",
    "}",
    "",
    "pub fn padding_01() -> u8 { 1 }",
    "pub fn padding_02() -> u8 { 2 }",
    "pub fn padding_03() -> u8 { 3 }",
    "pub fn padding_04() -> u8 { 4 }",
    "pub fn padding_05() -> u8 { 5 }",
    "pub fn padding_06() -> u8 { 6 }",
    "pub fn padding_07() -> u8 { 7 }",
    "pub fn padding_08() -> u8 { 8 }",
    "pub fn padding_09() -> u8 { 9 }",
    "pub fn padding_10() -> u8 { 10 }",
    "",
    "pub unsafe fn legacy_far(ptr: *const u8) -> u8 {",
    "    unsafe { *ptr }",
    "}",
    "",
    "pub fn tail_01() -> u8 { 1 }",
    "pub fn tail_02() -> u8 { 2 }",
    "pub fn tail_03() -> u8 { 3 }",
    "pub fn tail_04() -> u8 { 4 }",
    "pub fn tail_05() -> u8 { 5 }",
    "pub fn tail_06() -> u8 { 6 }",
    "pub fn tail_07() -> u8 { 7 }",
    "pub fn tail_08() -> u8 { 8 }",
    "pub fn tail_09() -> u8 { 9 }",
    "pub fn tail_10() -> u8 { 10 }",
    "pub fn tail_11() -> u8 { 11 }",
    "pub fn tail_12() -> u8 { 12 }"
  ].join("\n")}\n`;
}

function changedLineAwareLibSource(): string {
  const lines = initialDiffReviewLibSource().trimEnd().split("\n");
  lines.splice(7, 0, "// touched near legacy unsafe");
  lines.push(
    "",
    "pub unsafe fn introduced(ptr: *const u8) -> u8 {",
    "    unsafe { *ptr }",
    "}"
  );
  return `${lines.join("\n")}\n`;
}

function suppressedDiffReviewLibSource(): string {
  const lines = initialDiffReviewLibSource().trimEnd().split("\n");
  lines.push(
    "",
    "pub fn active_suppressed(ptr: *const u8) -> u8 {",
    "    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK ticket=SEC-456 -- accepted legacy pointer shim",
    "    unsafe { *ptr }",
    "}",
    "",
    "pub fn invalid_suppression(ptr: *const u8) -> u8 {",
    "    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK",
    "    unsafe { *ptr }",
    "}",
    "",
    "pub fn expired_suppression(ptr: *const u8) -> u8 {",
    "    // rustsec-auditor: ignore RSA-UNSAFE-BLOCK until=2000-01-01 -- temporary accepted risk expired",
    "    unsafe { *ptr }",
    "}"
  );
  return `${lines.join("\n")}\n`;
}

function testFinding(input: {
  id: string;
  ruleId: string;
  severity: Finding["severity"];
  confidence: Finding["confidence"];
  category: Finding["category"];
}): Finding {
  return {
    id: input.id,
    ruleId: input.ruleId,
    title: "Synthetic test finding",
    severity: input.severity,
    confidence: input.confidence,
    category: input.category,
    file: "src/lib.rs",
    startLine: 10,
    evidence: ["Line 10: synthetic evidence"],
    whyItMatters: "Synthetic test finding for decision logic.",
    riskScenario: "The decision logic could overstate a low-confidence finding.",
    suggestedFix: "Confirm the finding before changing code."
  };
}

async function withMcpClient(callback: (client: Client) => Promise<void>): Promise<void> {
  const server = createRustSecurityAuditorMcpServer();
  const client = new Client({
    name: "rust-security-auditor-smoke-test",
    version: "0.0.0"
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  await server.connect(serverTransport);
  await client.connect(clientTransport);

  try {
    await callback(client);
  } finally {
    await client.close();
    await server.close();
  }
}
