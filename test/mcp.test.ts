import assert from "node:assert/strict";
import { cp, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
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
const cargoConfigFixturePath = resolve("test/fixtures/cargo-config-risk");

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

  it("asks only for a project path", async () => {
    // An agent calls these tools by reading the schema. Every switch has a
    // documented default, so requiring one makes the obvious call fail with a
    // validation error instead of running. `rust_list_accepted_risks` required
    // includeExpired, includeInvalid, and outputFormat even though its handler
    // already treated all three as optional.
    await withMcpClient(async (client) => {
      const result = await client.listTools();

      for (const tool of result.tools) {
        assert.deepEqual(
          tool.inputSchema.required ?? [],
          ["projectPath"],
          `${tool.name} asks the caller for more than a project path`
        );
      }
    });
  });

  it("never rejects a project-path-only call as invalid arguments", async () => {
    // A tool may still refuse the work for a domain reason — reviewing the
    // current diff outside a git repository, for one. What it must not do is
    // refuse to run at all because a switch with a default was left unset.
    // A schema rejection comes back as an error result, not a thrown error, so
    // both paths have to be read for this to guard anything.
    await withMcpClient(async (client) => {
      for (const name of mcpToolNames) {
        const message = await client.callTool({ name, arguments: { projectPath: suppressedFixturePath } }).then(
          (result) => JSON.stringify(result.content),
          (error: unknown) => String(error)
        );

        assert.doesNotMatch(message, /invalid arguments|input validation/i, `${name} rejected a project-path-only call`);
      }
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
    assert.match(output.reportMarkdown ?? "", /# Rust Security Audit/);
  });

  it("rust_audit_project defaults to compact non-diff Markdown", async () => {
    const output = await rustAuditProject({
      projectPath: vulnerableFixturePath,
      outputFormat: "markdown"
    });
    const markdown = output.reportMarkdown ?? "";

    assert.equal(output.error, undefined);
    assert.match(markdown, /# Rust Security Audit/);
    assert.match(markdown, /## Decision \/ Risk Level/);
    assert.match(markdown, /- riskLevel: high_risk/);
    assert.match(markdown, /- findingCount: 21/);
    assert.match(markdown, /## Top Findings/);
    assert.match(markdown, /## Grouped Findings/);
    assert.match(markdown, /## Recommended Next Actions/);
    assert.match(markdown, /## Hidden Details/);
    assert.doesNotMatch(markdown, /#### Evidence/);
    assert.doesNotMatch(markdown, /#### Why it matters/);
    assert.equal(countMarkdownTopFindingBullets(markdown), 5);
    assert.ok(output.findings.length > countMarkdownTopFindingBullets(markdown));
  });

  it("rust_audit_project full report keeps complete finding details", async () => {
    const output = await rustAuditProject({
      projectPath: vulnerableFixturePath,
      outputFormat: "markdown",
      reportMode: "full"
    });
    const markdown = output.reportMarkdown ?? "";

    assert.equal(output.error, undefined);
    assert.match(markdown, /# Rust Project Security Audit/);
    assert.match(markdown, /### RSA-BUILD-COMMAND-/);
    assert.match(markdown, /#### Evidence/);
    assert.match(markdown, /#### Why it matters/);
    assert.match(markdown, /#### Risk scenario/);
    assert.match(markdown, /#### Suggested fix/);
    assert.match(markdown, /#### Suggested tests/);
    assert.doesNotMatch(markdown, /## Critical Risk Findings\s+No critical risk findings/);
  });

  it("rust_audit_project full report includes suppression information when present", async () => {
    const output = await rustAuditProject({
      projectPath: suppressedFixturePath,
      includeSuppressed: true,
      outputFormat: "markdown",
      reportMode: "full"
    });
    const markdown = output.reportMarkdown ?? "";

    assert.equal(output.error, undefined);
    assert.match(markdown, /## Accepted \/ Suppressed Risks/);
    assert.match(markdown, /accepted risk: RSA-UNSAFE-BLOCK/);
    assert.match(markdown, /expired suppression: RSA-UNSAFE-BLOCK/);
    assert.match(markdown, /invalid suppression: RSA-UNSAFE-BLOCK/);
  });

  it("rust_audit_project keeps relative paths in compact Markdown by default", async () => {
    const output = await rustAuditProject({
      projectPath: vulnerableFixturePath,
      outputFormat: "markdown",
      pathMode: "relative"
    });
    const markdown = output.reportMarkdown ?? "";

    assert.equal(output.error, undefined);
    assert.match(markdown, /- Scope: \./);
    assert.match(markdown, /build\.rs/);
    assert.doesNotMatch(markdown, new RegExp(escapeRegExp(vulnerableFixturePath)));
    assert.doesNotMatch(markdown, new RegExp(escapeRegExp(output.projectPath)));
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

  it("rust_audit_unsafe compact report groups by unsafe site or function", async () => {
    const output = await rustAuditUnsafe({
      projectPath: vulnerableFixturePath,
      outputFormat: "markdown"
    });
    const markdown = output.reportMarkdown ?? "";

    assert.equal(output.error, undefined);
    assert.match(markdown, /# Rust Unsafe Audit/);
    assert.match(markdown, /## Unsafe Sites to Review/);
    assert.match(markdown, /### Unsafe block at src\/lib\.rs:11/);
    assert.match(markdown, /Rules: RSA-UNSAFE-BLOCK: 1, RSA-UNSAFE-FROM-RAW-PARTS: 1/);
    assert.match(markdown, /## Required Manual Review/);
    assert.match(markdown, /pointer validity/i);
    assert.match(markdown, /## Suggested Codex Review Prompts/);
    assert.doesNotMatch(markdown, /#### Evidence/);
    assert.ok(countMarkdownHeadings(markdown, "###") < output.findings.length);
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
        (finding) =>
          finding.ruleId.startsWith("RSA-DEP-") ||
          finding.ruleId.startsWith("RSA-BUILD-") ||
          finding.ruleId.startsWith("RSA-CARGO-")
      )
    );
    assert.ok(output.findings.some((finding) => finding.ruleId === "RSA-BUILD-COMMAND"));
    assert.equal(output.findings.some((finding) => finding.ruleId.startsWith("RSA-UNSAFE-")), false);
  });

  it("uses explicit tool scopes for Cargo config findings", async () => {
    const output = await rustAuditDependencies({ projectPath: cargoConfigFixturePath });

    assert.equal(output.error, undefined);
    assert.ok(output.findings.some((finding) => finding.ruleId === "RSA-CARGO-SOURCE-REPLACEMENT"));
    assert.ok(output.findings.some((finding) => finding.ruleId === "RSA-CARGO-RUNNER"));
  });

  it("rust_audit_dependencies compact report uses a supply-chain checklist", async () => {
    const output = await rustAuditDependencies({
      projectPath: dependencyRiskFixturePath,
      outputFormat: "markdown"
    });
    const markdown = output.reportMarkdown ?? "";

    assert.equal(output.error, undefined);
    assert.match(markdown, /# Rust Dependency & Supply Chain Audit/);
    assert.match(markdown, /## High Priority Review Items/);
    assert.match(markdown, /RSA-BUILD-COMMAND/);
    assert.match(markdown, /## Supply-Chain Checklist/);
    assert.match(markdown, /git dependencies: 1/);
    assert.match(markdown, /build dependencies: 1/);
    assert.match(markdown, /run `cargo audit` separately/i);
    assert.doesNotMatch(markdown, /#### Evidence/);
  });

  it("rust_audit_dependencies compact report groups workspace-local path dependencies", async () => {
    const { tempRoot, projectPath } = await createWorkspacePathDependencyProject();

    try {
      const output = await rustAuditDependencies({
        projectPath,
        outputFormat: "markdown",
        reportMode: "compact"
      });
      const markdown = output.reportMarkdown ?? "";

      assert.equal(output.error, undefined);
      assert.equal(output.findings.filter((finding) => finding.ruleId === "RSA-DEP-PATH").length, 2);
      assert.match(markdown, /Workspace-local path dependencies: 2 items/);
      assert.match(markdown, /low-priority trust-boundary signal/);
      assert.match(markdown, /Confidence: pattern-detection confidence, not exploitability confidence/);
      assert.doesNotMatch(markdown, /Path dependency needs local trust boundary review/);
      assert.doesNotMatch(markdown, /^- Low RSA-DEP-PATH/m);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_audit_project compact report groups workspace-local path dependencies as low priority", async () => {
    const { tempRoot, projectPath } = await createWorkspacePathDependencyProject();

    try {
      const output = await rustAuditProject({
        projectPath,
        outputFormat: "markdown",
        reportMode: "compact"
      });
      const markdown = output.reportMarkdown ?? "";

      assert.equal(output.error, undefined);
      assert.equal(output.findings.filter((finding) => finding.ruleId === "RSA-DEP-PATH").length, 2);
      assert.match(markdown, /## Grouped Findings/);
      assert.match(markdown, /Workspace-local path dependencies: 2 items/);
      assert.match(markdown, /Workspace-local path dependencies: 2 low-priority trust-boundary signals/);
      assert.doesNotMatch(markdown, /^- RSA-DEP-PATH: 2$/m);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("non-diff reportMode full expands details while compact stays concise", async () => {
    const compact = await rustAuditDependencies({
      projectPath: dependencyRiskFixturePath,
      outputFormat: "markdown",
      reportMode: "compact"
    });
    const full = await rustAuditDependencies({
      projectPath: dependencyRiskFixturePath,
      outputFormat: "markdown",
      reportMode: "full"
    });

    assert.equal(compact.error, undefined);
    assert.equal(full.error, undefined);
    assert.doesNotMatch(compact.reportMarkdown ?? "", /#### Evidence/);
    assert.match(full.reportMarkdown ?? "", /#### Evidence/);
    assert.match(full.reportMarkdown ?? "", /#### Suggested fix/);
    assert.ok((compact.reportMarkdown ?? "").length < (full.reportMarkdown ?? "").length);
  });

  it("rust_audit_dependencies full report preserves workspace path dependency details", async () => {
    const { tempRoot, projectPath } = await createWorkspacePathDependencyProject();

    try {
      const output = await rustAuditDependencies({
        projectPath,
        outputFormat: "markdown",
        reportMode: "full"
      });
      const markdown = output.reportMarkdown ?? "";

      assert.equal(output.error, undefined);
      assert.equal(output.findings.filter((finding) => finding.ruleId === "RSA-DEP-PATH").length, 2);
      assert.equal(countOccurrences(markdown, "### RSA-DEP-PATH-"), 2);
      assert.match(markdown, /core_dep = \{ path = "crates\/core" \}/);
      assert.match(markdown, /ui_dep = \{ path = "crates\/ui" \}/);
      assert.match(markdown, /Confidence: High pattern-detection confidence \(not exploitability confidence\)/);
      assert.doesNotMatch(markdown, /Workspace-local path dependencies: 2 items/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
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

  it("rust_list_accepted_risks rejects a local directory that is not a Rust Cargo project", async () => {
    const root = await mkdtemp(join(tmpdir(), "rust-security-auditor-accepted-risk-not-rust-"));

    try {
      await writeFile(join(root, "notes.rs"), "// rustsec-auditor: ignore RSA-UNSAFE-BLOCK -- no cargo\n");

      const output = await rustListAcceptedRisks({
        projectPath: root,
        includeExpired: true,
        includeInvalid: true,
        outputFormat: "json"
      });

      assert.equal(output.error?.code, "PROJECT_PATH_NOT_RUST_PROJECT");
      assert.equal(output.acceptedRisks.length, 0);
      assert.match(output.error?.message ?? "", /not a Rust project/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rust_list_accepted_risks reports incomplete coverage instead of presenting a linked source as empty", async () => {
    const root = await mkdtemp(join(tmpdir(), "rust-security-auditor-accepted-risk-link-"));
    const outside = await mkdtemp(join(tmpdir(), "rust-security-auditor-accepted-risk-link-outside-"));

    try {
      await mkdir(join(root, "src"));
      await writeFile(join(root, "Cargo.toml"), '[package]\nname = "linked_inventory"\nversion = "0.1.0"\n');
      const outsideFile = join(outside, "lib.rs");
      await writeFile(outsideFile, "// rustsec-auditor: ignore RSA-UNSAFE-BLOCK -- external control\n");
      await symlink(outsideFile, join(root, "src/lib.rs"));

      const output = await rustListAcceptedRisks({
        projectPath: root,
        includeExpired: true,
        includeInvalid: true,
        outputFormat: "markdown"
      });

      assert.equal(output.error, undefined);
      assert.equal(output.acceptedRisks.length, 0);
      assert.equal(output.scanCoverage?.complete, false);
      assert.ok(output.warnings?.some((warning) => warning.includes("symbolic_link")));
      assert.ok(output.scanCoverage?.entries.some((entry) => entry.file === "src/lib.rs" && entry.reason === "symbolic_link"));
      assert.match(output.reportMarkdown ?? "", /## Scan Coverage/);
      assert.match(output.reportMarkdown ?? "", /symbolic_link/);
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff classifies introduced, context, and pre-existing findings", async () => {
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
      assert.ok((output.diffReview?.relationCounts.unrelated_nearby ?? 0) >= 2);
      assert.ok((output.diffReview?.relationCounts.pre_existing_in_changed_file ?? 0) >= 2);
      assert.ok((output.diffReview?.hiddenPreExistingCount ?? 0) >= 2);
      assert.ok(output.enrichedFindings?.some((item) => item.diffContext.relation === "introduced_by_diff"));
      assert.equal(output.enrichedFindings?.some((item) => item.diffContext.relation === "unrelated_nearby"), false);
      assert.ok(output.enrichedFindings?.every((item) => item.actionability?.recommendedAction !== undefined));
      assert.equal(
        output.enrichedFindings?.some((item) => item.diffContext.relation === "pre_existing_in_changed_file"),
        false
      );
      assert.equal(output.findings.some((finding) => finding.evidence.join("\n").includes("legacy_far")), false);
      assert.equal(output.reviewDecision?.status, "needs_attention");
      assert.equal(output.reviewDecision?.safeToCommit, false);
      assert.match(output.reportMarkdown ?? "", /## Decision/);
      assert.match(output.reportMarkdown ?? "", /## Introduced by this diff/);
      assert.match(output.reportMarkdown ?? "", /## Legacy nearby findings hidden by default/);
      assert.match(output.reportMarkdown ?? "", /Hidden pre-existing findings/);
      assert.match(output.reportMarkdown ?? "", /NEEDS ATTENTION/);
      assert.doesNotMatch(output.reportMarkdown ?? "", new RegExp(escapeRegExp(repoPath)));
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff keeps relative paths in Markdown by default", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown",
        pathMode: "relative"
      });

      assert.equal(output.error, undefined);
      // projectPath is the resolved OS-native path, so the separator is not `/` everywhere.
      assert.equal(basename(output.projectPath), "repo");
      assert.match(output.reportMarkdown ?? "", /- Scope: \./);
      assert.match(output.reportMarkdown ?? "", /src\/lib\.rs/);
      assert.doesNotMatch(output.reportMarkdown ?? "", new RegExp(escapeRegExp(repoPath)));
      assert.doesNotMatch(output.reportMarkdown ?? "", new RegExp(escapeRegExp(output.projectPath)));
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("rust_review_current_diff applies nearChangedLineWindow", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        nearChangedLineWindow: 1
      });

      assert.equal(output.error, undefined);
      assert.equal(output.diffReview?.changedLineWindow, 1);
      assert.equal(output.diffReview?.relationCounts.nearby_legacy_context, 0);
      assert.equal(output.diffReview?.relationCounts.unrelated_nearby, 0);
      assert.equal(output.enrichedFindings?.some((item) => item.diffContext.relation === "nearby_legacy_context"), false);
      assert.equal(output.enrichedFindings?.some((item) => item.diffContext.relation === "unrelated_nearby"), false);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("nearby legacy in a different function stays hidden from compact review", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "build.rs"), nearbyLegacyCommandBuildScript(), "utf8");
      await runShellCommandOrThrow("git", ["add", "build.rs"], { cwd: repoPath });
      await runShellCommandOrThrow("git", ["commit", "-m", "add legacy build script"], { cwd: repoPath });
      await writeFile(join(repoPath, "build.rs"), changedNearbyDifferentFunctionBuildScript(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown"
      });

      const commandFinding = output.enrichedFindings?.find((item) => item.finding.ruleId === "RSA-BUILD-COMMAND");
      assert.equal(output.error, undefined);
      assert.equal(commandFinding, undefined);
      assert.equal(output.diffReview?.relationCounts.nearby_legacy_context, 1);
      assert.equal(output.diffReview?.hiddenNearChangedCount, 1);
      assert.equal(output.reviewDecision?.status, "pass");
      assert.equal(output.reviewDecision?.safeToCommit, true);
      assert.deepEqual(output.reviewDecision?.blockingFindingIds, []);
      assert.match(output.reportMarkdown ?? "", /## Legacy nearby findings hidden by default/);
      assert.doesNotMatch(output.reportMarkdown ?? "", /RSA-BUILD-COMMAND: Build script executes a shell command/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("full current diff report includes legacy nearby context without affecting safeToCommit", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "build.rs"), nearbyLegacyCommandBuildScript(), "utf8");
      await runShellCommandOrThrow("git", ["add", "build.rs"], { cwd: repoPath });
      await runShellCommandOrThrow("git", ["commit", "-m", "add legacy build script"], { cwd: repoPath });
      await writeFile(join(repoPath, "build.rs"), changedNearbyDifferentFunctionBuildScript(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown",
        reportMode: "full"
      });

      const commandFinding = output.enrichedFindings?.find((item) => item.finding.ruleId === "RSA-BUILD-COMMAND");
      assert.equal(output.error, undefined);
      assert.equal(commandFinding?.diffContext.relation, "nearby_legacy_context");
      assert.equal(commandFinding?.diffContext.contextAssessment, "nearby_legacy");
      assert.equal(commandFinding?.actionability?.recommendedAction, "monitor");
      assert.match(commandFinding?.actionability?.suggestedFixPrompt ?? "", /Legacy context near the current diff/);
      assert.doesNotMatch(commandFinding?.actionability?.suggestedFixPrompt ?? "", /First explain|then apply/);
      assert.equal(output.reviewDecision?.status, "pass");
      assert.equal(output.reviewDecision?.safeToCommit, true);
      assert.match(output.reportMarkdown ?? "", /## Legacy nearby findings hidden by default/);
      assert.match(output.reportMarkdown ?? "", /RSA-BUILD-COMMAND/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("old unsafe in the same function is marked same_function_context", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await commitLibSource(repoPath, sameFunctionContextBaseSource(), "add same function context baseline");
      await writeFile(join(repoPath, "src/lib.rs"), sameFunctionContextChangedSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown"
      });

      const sameFunctionFinding = output.enrichedFindings?.find(
        (item) => item.finding.ruleId === "RSA-UNSAFE-BLOCK" && item.diffContext.relation === "same_function_context"
      );

      assert.equal(output.error, undefined);
      assert.ok(sameFunctionFinding);
      assert.equal(sameFunctionFinding.diffContext.contextAssessment, "same_function");
      assert.equal(sameFunctionFinding.actionability?.recommendedAction, "manual_review");
      assert.equal(output.reviewDecision?.status, "needs_attention");
      assert.match(output.reportMarkdown ?? "", /## Relevant context in same function/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("old primitive in the same unsafe site is marked same_unsafe_site_context", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await commitLibSource(repoPath, sameUnsafeSiteContextBaseSource(), "add same unsafe site baseline");
      await writeFile(join(repoPath, "src/lib.rs"), sameUnsafeSiteContextChangedSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown"
      });

      const sameSitePrimitive = output.enrichedFindings?.find(
        (item) => item.finding.ruleId === "RSA-UNSAFE-TRANSMUTE" && item.diffContext.relation === "same_unsafe_site_context"
      );

      assert.equal(output.error, undefined);
      assert.ok(sameSitePrimitive);
      assert.equal(sameSitePrimitive.diffContext.contextAssessment, "same_unsafe_site");
      assert.equal(sameSitePrimitive.actionability?.recommendedAction, "manual_review");
      assert.equal(output.reviewDecision?.status, "needs_attention");
      assert.deepEqual(output.reviewDecision?.blockingFindingIds, []);
      assert.match(output.reportMarkdown ?? "", /## Relevant context in same unsafe site/);
      assert.match(sameSitePrimitive.actionability?.suggestedFixPrompt ?? "", /same unsafe site/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("added unsafe block only produces introduced_by_diff manual review in compact mode", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), groupedUnsafeSiteLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown"
      });

      assert.equal(output.error, undefined);
      assert.ok((output.enrichedFindings?.length ?? 0) > 0);
      assert.equal(output.enrichedFindings?.every((item) => item.diffContext.relation === "introduced_by_diff"), true);
      assert.equal(output.diffReview?.relationCounts.same_unsafe_site_context, 0);
      assert.equal(output.diffReview?.relationCounts.same_function_context, 0);
      assert.equal(output.reviewDecision?.status, "needs_attention");
      assert.equal(output.reviewDecision?.blockingFindingIds.length, 0);
      assert.ok((output.reviewDecision?.needsManualReviewFindingIds.length ?? 0) > 0);
      assert.match(output.reportMarkdown ?? "", /## Introduced by this diff/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("groups generic and specific findings at the same unsafe site", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), groupedUnsafeSiteLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown"
      });

      const group = output.reviewGroups?.find(
        (item) => item.ruleIds.includes("RSA-UNSAFE-BLOCK") && item.ruleIds.includes("RSA-UNSAFE-TRANSMUTE")
      );

      assert.equal(output.error, undefined);
      assert.ok(group);
      assert.ok(group.unsafeSite);
      assert.match(output.reportMarkdown ?? "", /Unsafe site at src\/lib\.rs/);
      assert.match(output.reportMarkdown ?? "", /Generic unsafe block/);
      assert.match(output.reportMarkdown ?? "", /Specific primitive: transmute/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("suggestedFixPrompt includes rule, location, function, and relation context", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown"
      });
      const introduced = output.enrichedFindings?.find(
        (item) => item.finding.ruleId === "RSA-UNSAFE-FN" && item.diffContext.relation === "introduced_by_diff"
      );
      const prompt = introduced?.actionability?.suggestedFixPrompt ?? "";

      assert.match(prompt, /RSA-UNSAFE-FN/);
      assert.match(prompt, /src\/lib\.rs:\d+/);
      assert.match(prompt, /inside function introduced/);
      assert.match(prompt, /introduced by the current diff/);
      assert.match(prompt, /First explain/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("full current diff report includes complete details", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), changedLineAwareLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        outputFormat: "markdown",
        reportMode: "full"
      });

      assert.equal(output.error, undefined);
      assert.match(output.reportMarkdown ?? "", /## Changed Files/);
      assert.match(output.reportMarkdown ?? "", /## Legacy nearby findings hidden by default/);
      assert.match(output.reportMarkdown ?? "", /## Accepted \/ Suppressed Risks/);
      assert.match(output.reportMarkdown ?? "", /#### Evidence/);
      assert.match(output.reportMarkdown ?? "", /#### Recommendation/);
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
      assert.match(output.reportMarkdown ?? "", /## Introduced by this diff/);
      assert.match(output.reportMarkdown ?? "", /## Suggested Codex Fix Prompts/);
      assert.match(output.reportMarkdown ?? "", /Please review RSA-BUILD-COMMAND/);
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
    assert.match(actionability.suppressionSuggestion ?? "", /rust-security-auditor: ignore RSA-BUILD-COMMAND/);
  });

  it("same unsafe-site high findings need attention but do not hard block", () => {
    const finding = testFinding({
      id: "RSA-BUILD-COMMAND-SAME-SITE",
      ruleId: "RSA-BUILD-COMMAND",
      severity: "high",
      confidence: "high",
      category: "command_execution"
    });
    const diffFinding: DiffAwareFinding = {
      finding,
      diffContext: {
        relation: "same_unsafe_site_context",
        nearestChangedLine: 11,
        distance: 1,
        contextAssessment: "same_unsafe_site"
      }
    };

    const decision = inferReviewDecision([diffFinding]);
    const actionability = actionabilityForDiffFinding(diffFinding);

    assert.equal(decision.status, "needs_attention");
    assert.deepEqual(decision.blockingFindingIds, []);
    assert.deepEqual(decision.needsManualReviewFindingIds, [finding.id]);
    assert.equal(decision.safeToCommit, false);
    assert.equal(actionability.recommendedAction, "manual_review");
  });

  it("nearby legacy context only affects safeToCommit when includePreExisting is enabled", () => {
    const finding = testFinding({
      id: "RSA-BUILD-COMMAND-LEGACY",
      ruleId: "RSA-BUILD-COMMAND",
      severity: "high",
      confidence: "high",
      category: "command_execution"
    });
    const diffFinding: DiffAwareFinding = {
      finding,
      diffContext: {
        relation: "nearby_legacy_context",
        nearestChangedLine: 12,
        distance: 2,
        contextAssessment: "nearby_legacy"
      }
    };

    const defaultDecision = inferReviewDecision([diffFinding]);
    const includePreExistingDecision = inferReviewDecision([diffFinding], { includePreExisting: true });

    assert.equal(defaultDecision.status, "pass");
    assert.equal(defaultDecision.safeToCommit, true);
    assert.deepEqual(defaultDecision.blockingFindingIds, []);
    assert.equal(includePreExistingDecision.status, "needs_attention");
    assert.equal(includePreExistingDecision.safeToCommit, false);
    assert.deepEqual(includePreExistingDecision.blockingFindingIds, []);
  });

  it("still reviews a changed test target even though broad audits skip it", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await mkdir(join(repoPath, "tests"), { recursive: true });
      await writeFile(join(repoPath, "tests/integration.rs"), "pub fn existing() {}\n", "utf8");
      await runShellCommandOrThrow("git", ["add", "."], { cwd: repoPath });
      await runShellCommandOrThrow("git", ["commit", "-m", "add integration test"], { cwd: repoPath });

      await writeFile(
        join(repoPath, "tests/integration.rs"),
        "pub fn existing() {}\n\npub fn added(p: *const u8) -> u8 {\n    unsafe { *p }\n}\n",
        "utf8"
      );

      const [diffOutput, auditOutput] = await Promise.all([
        rustReviewCurrentDiff({ projectPath: repoPath, outputFormat: "json" }),
        rustAuditProject({ projectPath: repoPath, outputFormat: "json" })
      ]);

      // A broad audit skips test targets because they do not ship. A diff
      // review must not: the author changed that file on purpose.
      assert.equal(diffOutput.error, undefined);
      assert.ok(
        diffOutput.findings.some((finding) => finding.file === "tests/integration.rs"),
        `diff review dropped the changed test target: ${JSON.stringify(diffOutput.findings.map((f) => f.file))}`
      );
      assert.equal(
        auditOutput.findings.some((finding) => finding.file === "tests/integration.rs"),
        false
      );
      assert.ok(auditOutput.warnings?.some((warning) => warning.includes("Excluded")));
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("does not alias a backslash file name onto a harmless sibling", { skip: process.platform === "win32" }, async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      // Two distinct files: `src/alias.rs` and a file whose *name* contains a
      // literal backslash. Rewriting `\` to `/` made a change to the second
      // look like a change to the first, so the review reported the harmless
      // sibling's findings — none — and returned pass/safeToCommit.
      await writeFile(join(repoPath, "src/alias.rs"), "pub fn harmless() {}\n", "utf8");
      await writeFile(join(repoPath, "src\\alias.rs"), "pub fn other() {}\n", "utf8");
      await runShellCommandOrThrow("git", ["add", "."], { cwd: repoPath });
      await runShellCommandOrThrow("git", ["commit", "-m", "add alias pair"], { cwd: repoPath });

      await writeFile(join(repoPath, "src\\alias.rs"), "pub fn other() {}\n\npub static mut EVIL: u64 = 0;\n", "utf8");

      const output = await rustReviewCurrentDiff({ projectPath: repoPath, outputFormat: "json" });

      assert.equal(output.error, undefined);
      assert.equal(output.reviewDecision?.status, "block");
      assert.equal(output.reviewDecision?.safeToCommit, false);
      assert.deepEqual(output.diffAffectedFiles, ["src\\alias.rs"]);
      assert.deepEqual(
        output.findings.map((finding) => [finding.ruleId, finding.file]),
        [["RSA-UNSAFE-STATIC-MUT", "src\\alias.rs"]]
      );
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("keeps a hard block when a required diff input was not fully scanned", () => {
    const finding = testFinding({
      id: "RSA-UNSAFE-STATIC-MUT-1",
      ruleId: "RSA-UNSAFE-STATIC-MUT",
      severity: "high",
      confidence: "high",
      category: "concurrency"
    });
    const blockingFinding: DiffAwareFinding = {
      finding,
      diffContext: {
        relation: "introduced_by_diff",
        nearestChangedLine: 10,
        distance: 0
      }
    };

    const decision = inferReviewDecision([blockingFinding], {
      incompleteCoverage: [
        {
          status: "incomplete",
          file: "src/generated.rs",
          inputType: "rust",
          stage: "rust_context",
          reason: "file_too_large",
          message: "File exceeds the scan limit.",
          relevantToDiff: true
        }
      ]
    });

    // Incomplete coverage may only make a verdict stricter. Ranking it above
    // the blocking check downgraded `block` to `needs_attention` exactly when
    // the scan was least trustworthy.
    assert.equal(decision.status, "block");
    assert.equal(decision.safeToCommit, false);
    assert.deepEqual(decision.blockingFindingIds, ["RSA-UNSAFE-STATIC-MUT-1"]);
    assert.match(decision.reason, /not fully scanned/);
    assert.match(decision.reason, /src\/generated\.rs/);
  });

  it("rust_review_current_diff reports active, invalid, and expired suppressions", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(join(repoPath, "src/lib.rs"), suppressedDiffReviewLibSource(), "utf8");

      const output = await rustReviewCurrentDiff({
        projectPath: repoPath,
        reportMode: "full",
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
      assert.match(output.warnings?.join("\n") ?? "", /invalid accepted-risk suppression/);
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
      assert.doesNotMatch(output.reportMarkdown ?? "", /## Blocking Issues/);
      assert.doesNotMatch(output.reportMarkdown ?? "", /## Needs Manual Review/);
      assert.doesNotMatch(output.reportMarkdown ?? "", /## Non-blocking Notes/);
      assert.doesNotMatch(output.reportMarkdown ?? "", /None\./);
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

  it("fails closed when a changed Rust input is a symbolic link", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      const outsideFile = join(tempRoot, "outside.rs");
      await writeFile(outsideFile, "pub fn outside(ptr: *const u8) -> u8 { unsafe { *ptr } }\n");
      await symlink(outsideFile, join(repoPath, "src/linked.rs"));
      await runShellCommandOrThrow("git", ["add", "src/linked.rs"], { cwd: repoPath });

      const output = await rustReviewCurrentDiff({ projectPath: repoPath, staged: true, outputFormat: "markdown" });

      assert.equal(output.error, undefined);
      assert.equal(output.reviewDecision?.status, "needs_attention");
      assert.equal(output.reviewDecision?.safeToCommit, false);
      assert.ok(
        output.scanCoverage?.entries.some(
          (entry) => entry.file === "src/linked.rs" && entry.relevantToDiff === true && entry.reason === "symbolic_link"
        )
      );
      assert.match(output.reportMarkdown ?? "", /Scan Coverage/);
      assert.match(output.reportMarkdown ?? "", /symbolic_link/);
    } finally {
      await rm(tempRoot, { recursive: true, force: true });
    }
  });

  it("fails closed when malformed literals could forge a test-only current-diff downgrade", async () => {
    const { tempRoot, repoPath } = await createDiffReviewRepo();

    try {
      await writeFile(
        join(repoPath, "src/lib.rs"),
        [
          'const FORGED: &str = "unterminated',
          "#[cfg(test)]",
          "pub fn changed(v: &[u8]) { unsafe { v.get_unchecked(0); } }"
        ].join("\n"),
        "utf8"
      );

      const output = await rustReviewCurrentDiff({ projectPath: repoPath, outputFormat: "markdown" });

      assert.equal(output.error, undefined);
      assert.equal(output.reviewDecision?.status, "needs_attention");
      assert.equal(output.reviewDecision?.safeToCommit, false);
      assert.ok(output.findings.some((finding) => finding.ruleId === "RSA-UNSAFE-BLOCK" && finding.severity === "medium"));
      assert.ok(
        output.scanCoverage?.entries.some(
          (entry) => entry.file === "src/lib.rs" && entry.relevantToDiff === true && entry.reason === "lexical_incomplete"
        )
      );
      assert.match(output.reportMarkdown ?? "", /lexical_incomplete/);
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

async function createWorkspacePathDependencyProject(): Promise<{ tempRoot: string; projectPath: string }> {
  const tempRoot = await mkdtemp(join(tmpdir(), "rust-security-auditor-workspace-path-"));
  const projectPath = join(tempRoot, "workspace");

  await mkdir(join(projectPath, "src"), { recursive: true });
  await mkdir(join(projectPath, "crates/core/src"), { recursive: true });
  await mkdir(join(projectPath, "crates/ui/src"), { recursive: true });
  await writeFile(
    join(projectPath, "Cargo.toml"),
    `${[
      "[workspace]",
      "members = [\"crates/core\", \"crates/ui\"]",
      "",
      "[package]",
      "name = \"workspace_path_fixture\"",
      "version = \"0.1.0\"",
      "edition = \"2021\"",
      "",
      "[dependencies]",
      "core_dep = { path = \"crates/core\" }",
      "ui_dep = { path = \"crates/ui\" }"
    ].join("\n")}\n`,
    "utf8"
  );
  await writeFile(join(projectPath, "src/lib.rs"), "pub fn root() {}\n", "utf8");
  await writeFile(
    join(projectPath, "crates/core/Cargo.toml"),
    `${[
      "[package]",
      "name = \"core_dep\"",
      "version = \"0.1.0\"",
      "edition = \"2021\""
    ].join("\n")}\n`,
    "utf8"
  );
  await writeFile(join(projectPath, "crates/core/src/lib.rs"), "pub fn core() {}\n", "utf8");
  await writeFile(
    join(projectPath, "crates/ui/Cargo.toml"),
    `${[
      "[package]",
      "name = \"ui_dep\"",
      "version = \"0.1.0\"",
      "edition = \"2021\""
    ].join("\n")}\n`,
    "utf8"
  );
  await writeFile(join(projectPath, "crates/ui/src/lib.rs"), "pub fn ui() {}\n", "utf8");

  return { tempRoot, projectPath };
}

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

async function commitLibSource(repoPath: string, source: string, message: string): Promise<void> {
  await writeFile(join(repoPath, "src/lib.rs"), source, "utf8");
  await runShellCommandOrThrow("git", ["add", "src/lib.rs"], { cwd: repoPath });
  await runShellCommandOrThrow("git", ["commit", "-m", message], { cwd: repoPath });
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

function groupedUnsafeSiteLibSource(): string {
  const lines = initialDiffReviewLibSource().trimEnd().split("\n");
  lines.push(
    "",
    "pub fn grouped_transmute(value: u32) -> u64 {",
    "    unsafe { std::mem::transmute(value) }",
    "}"
  );
  return `${lines.join("\n")}\n`;
}

function sameFunctionContextBaseSource(): string {
  return `${[
    "pub fn same_function_context(ptr: *const u8) -> u8 {",
    "    let value = 1;",
    "    let read = unsafe { *ptr };",
    "    read + value",
    "}"
  ].join("\n")}\n`;
}

function sameFunctionContextChangedSource(): string {
  return `${[
    "pub fn same_function_context(ptr: *const u8) -> u8 {",
    "    let value = 2;",
    "    let read = unsafe { *ptr };",
    "    read + value",
    "}"
  ].join("\n")}\n`;
}

function sameUnsafeSiteContextBaseSource(): string {
  return `${[
    "pub fn same_unsafe_site_context(value: u32) -> u64 {",
    "    unsafe {",
    "        let widened = std::mem::transmute(value);",
    "        widened",
    "    }",
    "}"
  ].join("\n")}\n`;
}

function sameUnsafeSiteContextChangedSource(): string {
  return `${[
    "pub fn same_unsafe_site_context(value: u32) -> u64 {",
    "    unsafe {",
    "        let _guard = value;",
    "        let widened = std::mem::transmute(value);",
    "        widened",
    "    }",
    "}"
  ].join("\n")}\n`;
}

function nearbyLegacyCommandBuildScript(): string {
  return `${[
    "use std::process::Command;",
    "fn legacy() {",
    "    let _ = Command::new(\"sh\").arg(\"-c\").arg(\"echo legacy\").status();",
    "}",
    "fn touched() {",
    "    let value = 1;",
    "}"
  ].join("\n")}\n`;
}

function changedNearbyDifferentFunctionBuildScript(): string {
  return `${[
    "use std::process::Command;",
    "fn legacy() {",
    "    let _ = Command::new(\"sh\").arg(\"-c\").arg(\"echo legacy\").status();",
    "}",
    "fn touched() {",
    "    let value = 2;",
    "}"
  ].join("\n")}\n`;
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

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function countMarkdownTopFindingBullets(markdown: string): number {
  return markdown.match(/^- (?:Critical|High|Medium|Low|Info) RSA-/gm)?.length ?? 0;
}

function countMarkdownHeadings(markdown: string, prefix: string): number {
  return markdown.match(new RegExp(`^${escapeRegExp(prefix)} `, "gm"))?.length ?? 0;
}

function countOccurrences(value: string, needle: string): number {
  return value.split(needle).length - 1;
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
