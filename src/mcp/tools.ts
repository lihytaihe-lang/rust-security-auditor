import { realpath, stat } from "node:fs/promises";
import { isAbsolute, posix, resolve } from "node:path";
import { parseUnifiedDiff, type GitDiffFile, type ParsedGitDiff } from "../git/index.js";
import { renderMarkdownReport, toJsonReport, type AuditReportInput, type Category, categories, type Finding, type Severity, severities } from "../reports/index.js";
import { DependencyScanner, ProjectScanner, UnsafeScanner, discoverRustProject, listAcceptedRiskInventory, scanRustProject, type RustProject, type RustProjectScanResult } from "../scanners/index.js";
import { countActiveSuppressions, countExpiredSuppressions, countInvalidSuppressions, dedupeFindings, sortFindings } from "../scanners/resultUtils.js";
import type { SuppressedFinding } from "../scanners/types.js";
import { runShellCommand } from "../utils/shell.js";
import {
  conclusionFromReviewDecision,
  inferReviewDecision,
  shouldDisplayDiffFinding,
  summarizeDiffReviewMetrics,
  withDiffReviewActionability
} from "./reviewDecision.js";
import { contextForLine, extractRustContextForDiffFiles, type RustFileContext } from "./rustContext.js";
import {
  type DiffAwareFinding,
  type DiffReportMode,
  type DiffReviewDetails,
  type DiffReviewSummaryMetrics,
  type DiffReviewMode,
  type FindingDiffContext,
  type PathMode,
  type AcceptedRisk,
  type AcceptedRiskInventorySummary,
  type AcceptedRiskInventoryToolOutput,
  type McpAuditError,
  type McpAuditSummary,
  type McpAuditToolOutput,
  type McpToolOutput,
  type McpToolName,
  type OutputFormat,
  type RustAuditDependenciesInput,
  type RustAuditProjectInput,
  type RustAuditToolInput,
  type RustAuditUnsafeInput,
  type ReviewFindingGroup,
  type RustListAcceptedRisksInput,
  type RustReviewCurrentDiffInput,
  type SuppressionSummary,
  type UnsafeSiteContext,
  mcpToolNames
} from "./types.js";

const dependencyRulePrefixes = ["RSA-DEP-", "RSA-BUILD-"] as const;
const unsafeRulePrefixes = ["RSA-UNSAFE-", "RSA-FFI-"] as const;
const defaultNearChangedLineWindow = 3;

export function isMcpToolName(value: string): value is McpToolName {
  return (mcpToolNames as readonly string[]).includes(value);
}

export async function callRustAuditTool(
  tool: McpToolName,
  input: RustAuditToolInput
): Promise<McpToolOutput> {
  switch (tool) {
    case "rust_audit_project":
      return await rustAuditProject(input as RustAuditProjectInput);
    case "rust_audit_unsafe":
      return await rustAuditUnsafe(input as RustAuditUnsafeInput);
    case "rust_audit_dependencies":
      return await rustAuditDependencies(input as RustAuditDependenciesInput);
    case "rust_review_current_diff":
      return await rustReviewCurrentDiff(input as RustReviewCurrentDiffInput);
    case "rust_list_accepted_risks":
      return await rustListAcceptedRisks(input as RustListAcceptedRisksInput);
  }
}

export async function rustAuditProject(input: RustAuditProjectInput): Promise<McpAuditToolOutput> {
  return await runTool("rust_audit_project", input.projectPath, async () => {
    const projectPath = await resolveRustProjectPath(input.projectPath);
    const scan = await scanRustProject({
      workspacePath: projectPath,
      includeSuppressed: input.includeSuppressed === true
    });

    return buildToolOutput({
      tool: "rust_audit_project",
      projectPath,
      findings: scan.findings,
      suppressedCount: scan.suppressedCount ?? 0,
      suppressedFindings: scan.suppressedFindings ?? [],
      outputFormat: input.outputFormat,
      pathMode: normalizePathMode(input.pathMode),
      title: "Rust Project Security Audit",
      warnings: scan.warnings
    });
  });
}

export async function rustAuditUnsafe(input: RustAuditUnsafeInput): Promise<McpAuditToolOutput> {
  return await runTool("rust_audit_unsafe", input.projectPath, async () => {
    const projectPath = await resolveRustProjectPath(input.projectPath);
    const projectResult = await new ProjectScanner().scan({ workspacePath: projectPath });
    const unsafeResult = await new UnsafeScanner().scan({
      workspacePath: projectPath,
      project: projectResult.project
    });
    const includeDocumentedUnsafe = input.includeDocumentedUnsafe !== false;
    const findings = unsafeResult.findings
      .filter(isUnsafeOrFfiFinding)
      .filter((finding) => includeDocumentedUnsafe || !isDocumentedUnsafeFinding(finding));

    return buildToolOutput({
      tool: "rust_audit_unsafe",
      projectPath,
      findings,
      suppressedCount: unsafeResult.suppressedCount ?? 0,
      suppressedFindings: unsafeResult.suppressedFindings ?? [],
      outputFormat: input.outputFormat,
      pathMode: normalizePathMode(input.pathMode),
      title: "Rust Unsafe And FFI Audit",
      warnings: [...projectResult.warnings, ...unsafeResult.warnings]
    });
  });
}

export async function rustAuditDependencies(input: RustAuditDependenciesInput): Promise<McpAuditToolOutput> {
  return await runTool("rust_audit_dependencies", input.projectPath, async () => {
    const projectPath = await resolveRustProjectPath(input.projectPath);
    const projectResult = await new ProjectScanner().scan({ workspacePath: projectPath });
    const dependencyResult = await new DependencyScanner().scan({
      workspacePath: projectPath,
      project: projectResult.project
    });
    const findings = dependencyResult.findings.filter(isDependencyOrBuildFinding);

    return buildToolOutput({
      tool: "rust_audit_dependencies",
      projectPath,
      findings,
      suppressedCount: dependencyResult.suppressedCount ?? 0,
      suppressedFindings: dependencyResult.suppressedFindings ?? [],
      outputFormat: input.outputFormat,
      pathMode: normalizePathMode(input.pathMode),
      title: "Rust Dependency And Supply-Chain Audit",
      warnings: [...projectResult.warnings, ...dependencyResult.warnings]
    });
  });
}

export async function rustReviewCurrentDiff(input: RustReviewCurrentDiffInput): Promise<McpAuditToolOutput> {
  return await runTool("rust_review_current_diff", input.projectPath, async () => {
    const projectPath = await resolveRustProjectPath(input.projectPath);
    const pathMode = normalizePathMode(input.pathMode);
    const reportMode = normalizeReportMode(input.reportMode);
    const nearChangedLineWindow = normalizeNearChangedLineWindow(input.nearChangedLineWindow);
    const gitDiff = await readGitDiff(projectPath, input);
    const diffAffectedFiles = affectedFilePaths(gitDiff.diff);
    const affectedFiles = new Set(diffAffectedFiles);
    const scan =
      affectedFiles.size === 0
        ? emptyRustProjectScan(projectPath)
        : await scanRustProjectFiles(projectPath, affectedFiles);
    const suppressedFindings = scan.suppressedFindings ?? [];
    const suppressionSummary = summarizeSuppressions(suppressedFindings);
    const rustContexts = await extractRustContextForDiffFiles(projectPath, gitDiff.diff.files);
    const allEnrichedFindings = attachSuppressionMetadata(
      enrichFindingsWithDiff(scan.findings, gitDiff.diff.files, nearChangedLineWindow, rustContexts),
      suppressedFindings
    );
    const includePreExisting = input.includePreExisting === true;
    const enrichedFindings = withDiffReviewActionability(
      allEnrichedFindings.filter((item) => shouldDisplayDiffFinding(item, includePreExisting, reportMode)),
      { includePreExisting, reportMode }
    );
    const hiddenNearChangedCount = countHiddenNearChangedFindings(allEnrichedFindings, enrichedFindings);
    const reviewGroups = buildReviewGroups(enrichedFindings);
    const unsafeSiteGroupCount = reviewGroups.filter((group) => group.unsafeSite !== undefined).length;
    const findings = enrichedFindings.map((item) => item.finding);
    const relationCounts = countRelations(allEnrichedFindings);
    const reviewDecision = inferReviewDecision(enrichedFindings, { includePreExisting, reportMode });
    const summaryMetrics = summarizeDiffReviewMetrics({
      allFindings: allEnrichedFindings,
      visibleFindings: enrichedFindings,
      reviewDecision,
      hiddenNearChangedCount,
      unsafeSiteGroupCount
    });
    const conclusion = conclusionFromReviewDecision(reviewDecision);
    const diffReview: DiffReviewDetails = {
      mode: gitDiff.mode,
      changedLineWindow: nearChangedLineWindow,
      reportMode,
      pathMode,
      includePreExisting,
      includedRelations: includedDiffRelations(includePreExisting, reportMode),
      relationCounts,
      hiddenPreExistingCount: countHiddenPreExistingFindings(allEnrichedFindings, enrichedFindings),
      hiddenNearChangedCount,
      unsafeSiteGroupCount,
      conclusion
    };
    const warnings = [
      ...scan.warnings,
      ...gitDiff.warnings,
      "rust_review_current_diff is changed-line aware, but it is still heuristic scanner output rather than full data-flow or taint analysis.",
      "near_changed_lines is split into same_unsafe_site_context, same_function_context, nearby_legacy_context, and unrelated_nearby relations."
    ];

    if (diffAffectedFiles.length === 0) {
      warnings.push("No changed Rust project files were detected in the selected git diff.");
    }

    return buildDiffReviewToolOutput({
      tool: "rust_review_current_diff",
      projectPath,
      findings,
      enrichedFindings,
      suppressedFindings,
      suppressedCount: suppressionSummary.suppressedCount,
      suppressionSummary,
      outputFormat: input.outputFormat,
      pathMode,
      reportMode,
      title: "Rust Current Diff Security Review",
      warnings,
      diffAffectedFiles,
      diff: gitDiff.diff,
      diffReview,
      reviewDecision,
      summaryMetrics,
      reviewGroups
    });
  });
}

export async function rustListAcceptedRisks(
  input: RustListAcceptedRisksInput
): Promise<AcceptedRiskInventoryToolOutput> {
  try {
    const projectPath = await resolveRustProjectPath(input.projectPath);
    const inventory = await listAcceptedRiskInventory({
      workspacePath: projectPath,
      includeExpired: input.includeExpired === true,
      includeInvalid: input.includeInvalid === true
    });
    const pathMode = normalizePathMode(input.pathMode);
    const output: AcceptedRiskInventoryToolOutput = {
      tool: "rust_list_accepted_risks",
      projectPath,
      summary: inventory.summary,
      acceptedRisks: inventory.acceptedRisks
    };

    if (input.outputFormat === "markdown") {
      output.reportMarkdown = renderAcceptedRiskInventoryMarkdown({
        projectPath,
        pathMode,
        summary: inventory.summary,
        acceptedRisks: inventory.acceptedRisks
      });
    }

    return output;
  } catch (error) {
    return errorAcceptedRiskInventoryOutput(input.projectPath, toMcpAuditError(error));
  }
}

class McpToolInputError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "McpToolInputError";
    this.code = code;
  }
}

async function runTool(
  tool: McpToolName,
  projectPath: string,
  action: () => Promise<McpAuditToolOutput>
): Promise<McpAuditToolOutput> {
  try {
    return await action();
  } catch (error) {
    return errorToolOutput(tool, projectPath, toMcpAuditError(error));
  }
}

function normalizePathMode(value: PathMode | undefined): PathMode {
  if (value === undefined || value === "relative") return "relative";
  if (value === "absolute") return "absolute";
  throw new McpToolInputError("INVALID_PATH_MODE", "pathMode must be either relative or absolute.");
}

function normalizeReportMode(value: DiffReportMode | undefined): DiffReportMode {
  if (value === undefined || value === "compact") return "compact";
  if (value === "full") return "full";
  throw new McpToolInputError("INVALID_REPORT_MODE", "reportMode must be either compact or full.");
}

function normalizeNearChangedLineWindow(value: number | undefined): number {
  if (value === undefined) return defaultNearChangedLineWindow;

  if (!Number.isInteger(value) || value < 0 || value > 50) {
    throw new McpToolInputError(
      "INVALID_NEAR_CHANGED_LINE_WINDOW",
      "nearChangedLineWindow must be an integer between 0 and 50."
    );
  }

  return value;
}

async function resolveLocalProjectPath(projectPath: string): Promise<string> {
  const trimmed = projectPath.trim();

  if (trimmed.length === 0) {
    throw new McpToolInputError("INVALID_PROJECT_PATH", "projectPath must be a non-empty local directory path.");
  }

  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(trimmed)) {
    throw new McpToolInputError("INVALID_PROJECT_PATH", "projectPath must be a local filesystem path, not a URL.");
  }

  const resolved = resolve(trimmed);
  let pathStat;

  try {
    pathStat = await stat(resolved);
  } catch {
    throw new McpToolInputError("PROJECT_PATH_NOT_FOUND", `projectPath does not exist: ${resolved}`);
  }

  if (!pathStat.isDirectory()) {
    throw new McpToolInputError("PROJECT_PATH_NOT_DIRECTORY", `projectPath must be a directory: ${resolved}`);
  }

  return await realpath(resolved);
}

async function resolveRustProjectPath(projectPath: string): Promise<string> {
  const resolved = await resolveLocalProjectPath(projectPath);
  const project = await discoverRustProject(resolved);

  if (!project.isRustProject) {
    throw new McpToolInputError(
      "PROJECT_PATH_NOT_RUST_PROJECT",
      `projectPath is not a Rust project: ${resolved}. Expected a local Cargo project or workspace containing at least one Cargo.toml.`
    );
  }

  return resolved;
}

function buildToolOutput(input: {
  tool: McpToolName;
  projectPath: string;
  findings: readonly Finding[];
  suppressedCount: number;
  suppressedFindings?: readonly SuppressedFinding[] | undefined;
  outputFormat?: OutputFormat | undefined;
  pathMode: PathMode;
  title: string;
  warnings: readonly string[];
  diffAffectedFiles?: readonly string[] | undefined;
}): McpAuditToolOutput {
  const reportInput: AuditReportInput = {
    title: input.title,
    scope: input.projectPath,
    findings: input.findings,
    summaryNotes: input.warnings
  };
  const jsonReport = toJsonReport(reportInput);
  const findings = jsonReport.findings;
  const output: McpAuditToolOutput = {
    tool: input.tool,
    projectPath: input.projectPath,
    summary: summarizeForMcp(findings, input.suppressedCount),
    findings
  };

  if (input.outputFormat === "markdown") {
    output.reportMarkdown = renderMarkdownReport(toMarkdownReportInput(reportInput, input.projectPath, input.pathMode));
  }

  if (input.warnings.length > 0) {
    output.warnings = [...input.warnings];
  }

  if (input.diffAffectedFiles !== undefined) {
    output.diffAffectedFiles = [...input.diffAffectedFiles];
  }

  if (input.suppressedFindings !== undefined && input.suppressedFindings.length > 0) {
    output.suppressedFindings = [...input.suppressedFindings];
  }

  return output;
}

function buildDiffReviewToolOutput(input: {
  tool: McpToolName;
  projectPath: string;
  findings: readonly Finding[];
  enrichedFindings: readonly DiffAwareFinding[];
  reviewGroups: readonly ReviewFindingGroup[];
  suppressedFindings: readonly SuppressedFinding[];
  suppressedCount: number;
  suppressionSummary: SuppressionSummary;
  outputFormat?: OutputFormat | undefined;
  pathMode: PathMode;
  reportMode: DiffReportMode;
  title: string;
  warnings: readonly string[];
  diffAffectedFiles: readonly string[];
  diff: ParsedGitDiff;
  diffReview: DiffReviewDetails;
  reviewDecision: NonNullable<McpAuditToolOutput["reviewDecision"]>;
  summaryMetrics: DiffReviewSummaryMetrics;
}): McpAuditToolOutput {
  const reportInput: AuditReportInput = {
    title: input.title,
    scope: input.projectPath,
    findings: input.findings,
    summaryNotes: input.warnings
  };
  const jsonReport = toJsonReport(reportInput);
  const findings = jsonReport.findings;
  const output: McpAuditToolOutput = {
    tool: input.tool,
    projectPath: input.projectPath,
    summary: {
      ...summarizeForMcp(findings, input.suppressedCount),
      ...input.summaryMetrics
    },
    suppressionSummary: input.suppressionSummary,
    findings,
    diffAffectedFiles: [...input.diffAffectedFiles],
    diff: {
      files: input.diff.files
    },
    diffReview: input.diffReview,
    reviewDecision: input.reviewDecision,
    reviewGroups: [...input.reviewGroups],
    enrichedFindings: input.enrichedFindings.map((item) => ({
      finding: item.finding,
      diffContext: item.diffContext,
      actionability: item.actionability,
      suppression: item.suppression
    }))
  };

  if (input.outputFormat === "markdown") {
    output.reportMarkdown = renderDiffReviewMarkdown({
      title: input.title,
      projectPath: input.projectPath,
      pathMode: input.pathMode,
      reportMode: input.reportMode,
      findings: input.enrichedFindings,
      reviewGroups: input.reviewGroups,
      suppressedFindings: input.suppressedFindings,
      suppressionSummary: input.suppressionSummary,
      warnings: input.warnings,
      diffAffectedFiles: input.diffAffectedFiles,
      diffReview: input.diffReview,
      reviewDecision: input.reviewDecision
    });
  }

  if (input.warnings.length > 0) {
    output.warnings = [...input.warnings];
  }

  if (input.suppressedFindings.length > 0) {
    output.suppressedFindings = [...input.suppressedFindings];
  }

  return output;
}

function errorToolOutput(tool: McpToolName, projectPath: string, error: McpAuditError): McpAuditToolOutput {
  return {
    tool,
    projectPath,
    summary: emptySummary("warning"),
    findings: [],
    error
  };
}

function errorAcceptedRiskInventoryOutput(
  projectPath: string,
  error: McpAuditError
): AcceptedRiskInventoryToolOutput {
  return {
    tool: "rust_list_accepted_risks",
    projectPath,
    summary: emptyAcceptedRiskInventorySummary(),
    acceptedRisks: [],
    error
  };
}

function summarizeForMcp(findings: readonly Finding[], suppressedCount: number): McpAuditSummary {
  const severityCounts = Object.fromEntries(severities.map((severity) => [severity, 0])) as Record<Severity, number>;
  const categoryCounts = Object.fromEntries(categories.map((category) => [category, 0])) as Record<Category, number>;

  for (const finding of findings) {
    severityCounts[finding.severity] += 1;
    categoryCounts[finding.category] += 1;
  }

  return {
    findingCount: findings.length,
    suppressedCount,
    severityCounts,
    categoryCounts,
    riskLevel: inferRiskLevel(findings)
  };
}

function emptySummary(riskLevel: McpAuditSummary["riskLevel"]): McpAuditSummary {
  return {
    findingCount: 0,
    suppressedCount: 0,
    severityCounts: Object.fromEntries(severities.map((severity) => [severity, 0])) as Record<Severity, number>,
    categoryCounts: Object.fromEntries(categories.map((category) => [category, 0])) as Record<Category, number>,
    riskLevel
  };
}

function emptyAcceptedRiskInventorySummary(): AcceptedRiskInventorySummary {
  return {
    acceptedRiskCount: 0,
    expiredCount: 0,
    invalidCount: 0,
    byRuleId: {},
    byOwner: {}
  };
}

function inferRiskLevel(findings: readonly Finding[]): McpAuditSummary["riskLevel"] {
  if (findings.some((finding) => finding.severity === "critical" || finding.severity === "high")) {
    return "high_risk";
  }

  if (findings.some((finding) => finding.severity === "medium" || finding.category === "manual_review")) {
    return "needs_attention";
  }

  if (findings.length > 0) {
    return "warning";
  }

  return "pass";
}

function toMarkdownReportInput(
  input: AuditReportInput,
  projectPath: string,
  pathMode: PathMode
): AuditReportInput {
  return {
    ...input,
    scope: formatProjectScope(projectPath, pathMode),
    findings: input.findings.map((finding) => ({
      ...finding,
      file: formatDisplayPath(finding.file, projectPath, pathMode)
    }))
  };
}

function formatProjectScope(projectPath: string, pathMode: PathMode): string {
  return pathMode === "absolute" ? projectPath : ".";
}

function formatDisplayLocation(
  file: string,
  startLine: number | undefined,
  endLine: number | undefined,
  projectPath: string,
  pathMode: PathMode
): string {
  return formatLocationParts(formatDisplayPath(file, projectPath, pathMode), startLine, endLine);
}

function formatLocationParts(file: string, startLine: number | undefined, endLine: number | undefined): string {
  if (startLine === undefined) {
    return file;
  }

  if (endLine !== undefined && endLine !== startLine) {
    return `${file}:${startLine}-${endLine}`;
  }

  return `${file}:${startLine}`;
}

function formatDisplayPath(file: string, projectPath: string, pathMode: PathMode): string {
  if (pathMode === "relative") {
    return normalizeFindingFile(file) || file;
  }

  if (isAbsolute(file) || posix.isAbsolute(file)) {
    return file;
  }

  return resolve(projectPath, file);
}

function summarizeSuppressions(suppressions: readonly SuppressedFinding[]): SuppressionSummary {
  return {
    suppressedCount: countActiveSuppressions(suppressions),
    expiredSuppressionCount: countExpiredSuppressions(suppressions),
    invalidSuppressionCount: countInvalidSuppressions(suppressions)
  };
}

function attachSuppressionMetadata(
  findings: readonly DiffAwareFinding[],
  suppressions: readonly SuppressedFinding[]
): DiffAwareFinding[] {
  const inactiveSuppressionsByFinding = new Map(
    suppressions
      .filter((suppression) => !suppression.isValid || suppression.isExpired)
      .map((suppression) => [suppressionKey(suppression.ruleId, suppression.file, suppression.line), suppression])
  );

  return findings.map((item) => {
    const line = item.finding.startLine;
    if (line === undefined) return item;

    const suppression = inactiveSuppressionsByFinding.get(suppressionKey(item.finding.ruleId, item.finding.file, line));
    if (suppression === undefined) return item;

    return {
      ...item,
      suppression
    };
  });
}

function suppressionKey(ruleId: string, file: string, line: number): string {
  return `${ruleId}:${file}:${line}`;
}

function renderDiffReviewMarkdown(input: {
  title: string;
  projectPath: string;
  pathMode: PathMode;
  reportMode: DiffReportMode;
  findings: readonly DiffAwareFinding[];
  reviewGroups: readonly ReviewFindingGroup[];
  suppressedFindings: readonly SuppressedFinding[];
  suppressionSummary: SuppressionSummary;
  warnings: readonly string[];
  diffAffectedFiles: readonly string[];
  diffReview: DiffReviewDetails;
  reviewDecision: NonNullable<McpAuditToolOutput["reviewDecision"]>;
}): string {
  const preExistingShown = input.findings.filter((item) => item.diffContext.relation === "pre_existing_in_changed_file").length;
  const sameUnsafeSiteShown = input.findings.filter((item) => item.diffContext.relation === "same_unsafe_site_context").length;
  const sameFunctionShown = input.findings.filter((item) => item.diffContext.relation === "same_function_context").length;
  const legacyNearbyShown = input.findings.filter((item) => item.diffContext.relation === "nearby_legacy_context").length;
  const unrelatedNearbyShown = input.findings.filter((item) => item.diffContext.relation === "unrelated_nearby").length;
  const lines: string[] = [
    "# Rust Security Review: Current Diff",
    "",
    "## Decision",
    "",
    `${decisionLabel(input.reviewDecision.status)}`,
    "",
    `- Safe to commit: ${input.reviewDecision.safeToCommit ? "Yes" : "No"}`,
    `- Reason: ${input.reviewDecision.reason}`,
    `- Blocking findings: ${input.reviewDecision.blockingFindingIds.length}`,
    `- Manual review findings: ${input.reviewDecision.needsManualReviewFindingIds.length}`,
    "",
    "## Summary",
    "",
    `- Introduced findings: ${input.diffReview.relationCounts.introduced_by_diff}`,
    `- Same unsafe-site context findings: ${input.diffReview.relationCounts.same_unsafe_site_context}`,
    `- Same-function context findings: ${input.diffReview.relationCounts.same_function_context}`,
    `- Legacy nearby findings: ${input.diffReview.relationCounts.nearby_legacy_context}`,
    `- Unrelated nearby findings: ${input.diffReview.relationCounts.unrelated_nearby}`,
    `- Hidden pre-existing findings: ${input.diffReview.hiddenPreExistingCount}`,
    `- Unsafe sites grouped: ${input.diffReview.unsafeSiteGroupCount}`,
    `- Suppressed: ${input.suppressionSummary.suppressedCount}`,
    `- Expired suppressions: ${input.suppressionSummary.expiredSuppressionCount}`,
    `- Invalid suppressions: ${input.suppressionSummary.invalidSuppressionCount}`,
    `- Scope: ${formatProjectScope(input.projectPath, input.pathMode)}`,
    `- Diff mode: ${input.diffReview.mode}`,
    `- Report mode: ${input.reportMode}`,
    `- Changed files: ${input.diffAffectedFiles.length}`,
    `- Changed-line window: ${input.diffReview.changedLineWindow}`,
    "- Diff context is split by added lines, same unsafe site, same function, and legacy nearby relation."
  ];

  if (preExistingShown > 0) {
    lines.push(`- Pre-existing findings shown: ${preExistingShown}`);
  }

  if (sameUnsafeSiteShown > 0 || sameFunctionShown > 0 || legacyNearbyShown > 0 || unrelatedNearbyShown > 0) {
    lines.push(
      `- Context findings shown: ${sameUnsafeSiteShown + sameFunctionShown + legacyNearbyShown + unrelatedNearbyShown}`
    );
  }

  if (input.diffReview.hiddenNearChangedCount > 0) {
    lines.push(`- Hidden context findings: ${input.diffReview.hiddenNearChangedCount}`);
  }

  if (input.reportMode === "full") {
    appendChangedFiles(lines, input.diffAffectedFiles, input.projectPath, input.pathMode);
  }

  appendRelationReviewSection(lines, {
    title: "Introduced by this diff",
    emptyText: "No findings start on added lines in this diff.",
    findings: input.findings.filter((item) => item.diffContext.relation === "introduced_by_diff"),
    projectPath: input.projectPath,
    pathMode: input.pathMode,
    reportMode: input.reportMode
  });
  appendRelationReviewSection(lines, {
    title: "Relevant context in same unsafe site",
    emptyText: "No visible findings share an unsafe site with added lines.",
    findings: input.findings.filter((item) => item.diffContext.relation === "same_unsafe_site_context"),
    projectPath: input.projectPath,
    pathMode: input.pathMode,
    reportMode: input.reportMode
  });
  appendRelationReviewSection(lines, {
    title: "Relevant context in same function",
    emptyText: "No visible findings share a function with added lines outside an unsafe site.",
    findings: input.findings.filter((item) => item.diffContext.relation === "same_function_context"),
    projectPath: input.projectPath,
    pathMode: input.pathMode,
    reportMode: input.reportMode
  });
  appendLegacyNearbySection(lines, {
    findings: input.findings.filter(
      (item) => item.diffContext.relation === "nearby_legacy_context" || item.diffContext.relation === "unrelated_nearby"
    ),
    hiddenCount: input.diffReview.hiddenNearChangedCount,
    projectPath: input.projectPath,
    pathMode: input.pathMode,
    reportMode: input.reportMode
  });

  if (input.reportMode === "full") {
    appendRelationReviewSection(lines, {
      title: "Pre-existing findings in changed files",
      emptyText: "No pre-existing findings are included. Set includePreExisting=true to include them.",
      findings: input.findings.filter((item) => item.diffContext.relation === "pre_existing_in_changed_file"),
      projectPath: input.projectPath,
      pathMode: input.pathMode,
      reportMode: input.reportMode
    });
    appendSuppressedRisks(lines, input.suppressedFindings, input.suppressionSummary, input.projectPath, input.pathMode);
  }

  appendSuggestedFixPrompts(lines, input.findings, input.reportMode);
  appendLimitations(lines, input.warnings);

  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd()}\n`;
}

function appendChangedFiles(
  lines: string[],
  diffAffectedFiles: readonly string[],
  projectPath: string,
  pathMode: PathMode
): void {
  lines.push("", "## Changed Files", "");
  if (diffAffectedFiles.length === 0) {
    lines.push("No changed files in the selected git diff.");
    return;
  }

  for (const file of diffAffectedFiles) {
    lines.push(`- \`${formatDisplayPath(file, projectPath, pathMode)}\``);
  }
}

function appendRelationReviewSection(
  lines: string[],
  input: {
    title: string;
    emptyText: string;
    findings: readonly DiffAwareFinding[];
    projectPath: string;
    pathMode: PathMode;
    reportMode: DiffReportMode;
  }
): void {
  lines.push("", `## ${input.title}`, "");

  if (input.findings.length === 0) {
    lines.push(input.emptyText);
    return;
  }

  for (const group of buildInternalReviewGroups(input.findings)) {
    lines.push(...formatReviewGroup(group, input.projectPath, input.pathMode, input.reportMode), "");
  }
}

function appendLegacyNearbySection(
  lines: string[],
  input: {
    findings: readonly DiffAwareFinding[];
    hiddenCount: number;
    projectPath: string;
    pathMode: PathMode;
    reportMode: DiffReportMode;
  }
): void {
  lines.push("", "## Legacy nearby findings hidden by default", "");

  if (input.reportMode === "compact") {
    if (input.hiddenCount === 0) {
      lines.push("No legacy nearby findings were hidden.");
      return;
    }

    lines.push(
      `${input.hiddenCount} legacy nearby or unrelated context finding(s) were hidden from this compact report. Use reportMode=full to inspect them separately.`
    );
    return;
  }

  if (input.findings.length === 0) {
    lines.push("No legacy nearby or unrelated context findings were found.");
    return;
  }

  lines.push("Shown because reportMode=full; these findings are separate legacy context, not default commit blockers.");
  for (const group of buildInternalReviewGroups(input.findings)) {
    lines.push("", ...formatReviewGroup(group, input.projectPath, input.pathMode, input.reportMode));
  }
}

function appendSuggestedFixPrompts(
  lines: string[],
  findings: readonly DiffAwareFinding[],
  reportMode: DiffReportMode
): void {
  const promptFindings = findings.filter(shouldShowSuggestedFixPrompt);

  if (promptFindings.length === 0 && reportMode === "compact") {
    return;
  }

  lines.push("", "## Suggested Codex Fix Prompts", "");

  if (promptFindings.length === 0) {
    lines.push("No Codex fix prompts were generated for this diff.");
    return;
  }

  for (const item of promptFindings) {
    lines.push(`- ${item.actionability?.suggestedFixPrompt ?? "No suggested fix prompt available."}`);
  }
}

function shouldShowSuggestedFixPrompt(item: DiffAwareFinding): boolean {
  return (
    item.diffContext.relation === "introduced_by_diff" ||
    item.diffContext.relation === "same_unsafe_site_context" ||
    item.diffContext.relation === "same_function_context"
  );
}

function appendSuppressedRisks(
  lines: string[],
  suppressedFindings: readonly SuppressedFinding[],
  suppressionSummary: SuppressionSummary,
  projectPath: string,
  pathMode: PathMode
): void {
  lines.push("", "## Accepted / Suppressed Risks", "");
  lines.push(`- Suppressed count: ${suppressionSummary.suppressedCount}`);
  lines.push(`- Expired suppression count: ${suppressionSummary.expiredSuppressionCount}`);
  lines.push(`- Invalid suppression count: ${suppressionSummary.invalidSuppressionCount}`);

  if (suppressedFindings.length === 0) {
    lines.push("", "None.");
    return;
  }

  lines.push("");

  for (const suppression of suppressedFindings) {
    const status = suppression.isValid
      ? suppression.isExpired
        ? "expired suppression"
        : "accepted risk"
      : "invalid suppression";
    const metadata = formatSuppressionMetadata(suppression);
    const reason = suppression.reason.length > 0 ? suppression.reason : "missing required reason";
    const location = formatDisplayLocation(suppression.file, suppression.line, undefined, projectPath, pathMode);
    lines.push(
      `- ${status}: ${suppression.ruleId} at \`${location}\`; reason: ${reason}; ${metadata}`
    );

    if (suppression.isExpired) {
      lines.push("  Expired suppression: finding is shown again and needs review.");
    }

    if (!suppression.isValid) {
      lines.push(`  Invalid suppression: ${suppression.invalidSuppression ?? "suppression directive is invalid"}`);
    }
  }
}

function formatSuppressionMetadata(suppression: SuppressedFinding): string {
  const metadata = [
    suppression.owner === undefined ? undefined : `owner: ${suppression.owner}`,
    suppression.ticket === undefined ? undefined : `ticket: ${suppression.ticket}`,
    suppression.until === undefined ? undefined : `until: ${suppression.until}`
  ].filter((item): item is string => item !== undefined);

  return metadata.length === 0 ? "metadata: none" : metadata.join("; ");
}

function appendLimitations(lines: string[], warnings: readonly string[]): void {
  lines.push(
    "",
    "## Limitations",
    "",
    "- Heuristic static scan.",
    "- Minimal Rust context uses text and brace heuristics, not full AST/data-flow/taint analysis.",
    "- Diff relation is based on added lines and lightweight function/unsafe-site context."
  );

  for (const warning of warnings) {
    lines.push(`- ${warning}`);
  }
}

function renderAcceptedRiskInventoryMarkdown(input: {
  projectPath: string;
  pathMode: PathMode;
  summary: AcceptedRiskInventorySummary;
  acceptedRisks: readonly AcceptedRisk[];
}): string {
  const active = input.acceptedRisks.filter((risk) => risk.isValid && !risk.isExpired);
  const expired = input.acceptedRisks.filter((risk) => risk.isExpired);
  const invalid = input.acceptedRisks.filter((risk) => !risk.isValid);
  const lines: string[] = [
    "# Accepted Risk Inventory",
    "",
    "## Summary",
    "",
    `- Accepted risks: ${input.summary.acceptedRiskCount}`,
    `- Expired: ${input.summary.expiredCount}`,
    `- Invalid: ${input.summary.invalidCount}`,
    `- Owners: ${formatCountRecord(input.summary.byOwner)}`,
    `- Rule IDs: ${formatCountRecord(input.summary.byRuleId)}`,
    `- Scope: ${formatProjectScope(input.projectPath, input.pathMode)}`
  ];

  appendAcceptedRiskSection(lines, "Active Accepted Risks", active, input.projectPath, input.pathMode);
  appendAcceptedRiskSection(lines, "Expired Suppressions", expired, input.projectPath, input.pathMode);
  appendAcceptedRiskSection(lines, "Invalid Suppressions", invalid, input.projectPath, input.pathMode);

  lines.push(
    "",
    "## Recommended Actions",
    "",
    "- Expired suppression: re-evaluate the accepted risk or remove the suppression.",
    "- Invalid suppression: add a reason after `--` or fix the suppression format.",
    "- Missing owner: add `owner=` metadata so future reviewers know who accepted the risk.",
    "- Missing ticket: add `ticket=` metadata for traceability."
  );

  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd()}\n`;
}

function appendAcceptedRiskSection(
  lines: string[],
  title: "Active Accepted Risks" | "Expired Suppressions" | "Invalid Suppressions",
  risks: readonly AcceptedRisk[],
  projectPath: string,
  pathMode: PathMode
): void {
  lines.push("", `## ${title}`, "");

  if (risks.length === 0) {
    lines.push("None.");
    return;
  }

  for (const risk of risks) {
    lines.push(`- ${formatAcceptedRisk(risk, projectPath, pathMode)}`);
  }
}

function formatAcceptedRisk(risk: AcceptedRisk, projectPath: string, pathMode: PathMode): string {
  const metadata = [
    risk.owner === undefined ? "owner: missing" : `owner: ${risk.owner}`,
    risk.ticket === undefined ? "ticket: missing" : `ticket: ${risk.ticket}`,
    risk.until === undefined ? undefined : `until: ${risk.until}`
  ].filter((item): item is string => item !== undefined);
  const reason = risk.reason.length > 0 ? risk.reason : "missing required reason";
  const invalid = risk.isValid ? "" : `; invalid: ${risk.invalidSuppression ?? "suppression directive is invalid"}`;
  const location = formatDisplayLocation(risk.file, risk.line, undefined, projectPath, pathMode);

  return `${risk.ruleId} at \`${location}\`; reason: ${reason}; ${metadata.join("; ")}; raw: \`${risk.rawComment}\`${invalid}`;
}

function formatCountRecord(record: Record<string, number>): string {
  const entries = Object.entries(record);
  if (entries.length === 0) return "none";
  return entries.map(([key, value]) => `${key}: ${value}`).join(", ");
}

interface InternalReviewGroup extends ReviewFindingGroup {
  items: DiffAwareFinding[];
}

function buildReviewGroups(findings: readonly DiffAwareFinding[]): ReviewFindingGroup[] {
  return buildInternalReviewGroups(findings).map((group) => {
    const output: ReviewFindingGroup = {
      id: group.id,
      title: group.title,
      file: group.file,
      relation: group.relation,
      findingIds: [...group.findingIds],
      ruleIds: [...group.ruleIds]
    };

    if (group.startLine !== undefined) output.startLine = group.startLine;
    if (group.endLine !== undefined) output.endLine = group.endLine;
    if (group.functionName !== undefined) output.functionName = group.functionName;
    if (group.unsafeSite !== undefined) output.unsafeSite = group.unsafeSite;

    return output;
  });
}

function buildInternalReviewGroups(findings: readonly DiffAwareFinding[]): InternalReviewGroup[] {
  const groups = new Map<string, DiffAwareFinding[]>();

  for (const item of findings) {
    const key = reviewGroupKey(item);
    const group = groups.get(key) ?? [];
    group.push(item);
    groups.set(key, group);
  }

  return [...groups.entries()]
    .map(([id, items]) => createReviewGroup(id, items))
    .sort((left, right) => {
      const fileOrder = left.file.localeCompare(right.file);
      if (fileOrder !== 0) return fileOrder;
      return (left.startLine ?? 0) - (right.startLine ?? 0);
    });
}

function reviewGroupKey(item: DiffAwareFinding): string {
  const site = item.diffContext.unsafeSite;
  if (site !== undefined && isUnsafeOrFfiFinding(item.finding)) {
    return `unsafe:${item.finding.file}:${site.kind}:${site.startLine}:${site.endLine ?? site.startLine}`;
  }

  return `finding:${item.finding.id}`;
}

function createReviewGroup(id: string, items: DiffAwareFinding[]): InternalReviewGroup {
  const first = items[0];
  if (first === undefined) {
    throw new Error("review group requires at least one finding");
  }

  const unsafeSite = first.diffContext.unsafeSite;
  const startLine = unsafeSite?.startLine ?? first.finding.startLine;
  const endLine = unsafeSite?.endLine ?? first.finding.endLine;
  const functionName = unsafeSite?.functionName ?? first.diffContext.functionName;
  const relation = summarizeGroupRelation(items);
  const group: InternalReviewGroup = {
    id,
    title:
      unsafeSite === undefined
        ? `${first.finding.ruleId}: ${first.finding.title}`
        : `Unsafe site at ${formatLocationParts(first.finding.file, startLine, endLine)}`,
    file: first.finding.file,
    relation,
    findingIds: items.map((item) => item.finding.id),
    ruleIds: [...new Set(items.map((item) => item.finding.ruleId))],
    items
  };

  if (startLine !== undefined) group.startLine = startLine;
  if (endLine !== undefined) group.endLine = endLine;
  if (functionName !== undefined) group.functionName = functionName;
  if (unsafeSite !== undefined) group.unsafeSite = unsafeSite;

  return group;
}

function summarizeGroupRelation(items: readonly DiffAwareFinding[]): ReviewFindingGroup["relation"] {
  const relations = [...new Set(items.map((item) => item.diffContext.relation))];
  return relations.length === 1 ? relations[0] ?? "mixed" : "mixed";
}

function formatReviewGroup(
  group: InternalReviewGroup,
  projectPath: string,
  pathMode: PathMode,
  reportMode: DiffReportMode
): string[] {
  const location = formatDisplayLocation(group.file, group.startLine, group.endLine, projectPath, pathMode);
  const lines = [
    `### ${group.unsafeSite === undefined ? group.title : `Unsafe site at ${location}`}`,
    "",
    `- Location: \`${location}\``,
    `- Function/context: ${group.functionName === undefined ? "unknown" : `\`${group.functionName}\``}`,
    `- Diff relation: ${group.relation}`,
    `- Recommended actions: ${formatRecommendedActions(group.items)}`
  ];

  const nearestChangedLines = [...new Set(group.items.map((item) => item.diffContext.nearestChangedLine).filter(isNumber))].sort(
    (left, right) => left - right
  );
  if (nearestChangedLines.length > 0) {
    lines.push(`- Nearest changed line: ${nearestChangedLines.join(", ")}`);
  }

  const contextNotes = [...new Set(group.items.map((item) => formatContextNote(item)).filter(isNonEmptyString))];
  for (const note of contextNotes) {
    lines.push(`- Context note: ${note}`);
  }

  lines.push("- Findings:");
  for (const item of group.items) {
    lines.push(`  - ${conciseFindingLabel(item.finding)} (${item.finding.ruleId}, ${item.finding.severity}/${item.finding.confidence})`);
  }

  if (reportMode === "full") {
    lines.push("", "#### Finding Details", "");
    for (const item of group.items) {
      lines.push(...formatDiffFinding(item, projectPath, pathMode, "#####"), "");
    }
  }

  return lines;
}

function conciseFindingLabel(finding: Finding): string {
  switch (finding.ruleId) {
    case "RSA-UNSAFE-BLOCK":
      return "Generic unsafe block";
    case "RSA-UNSAFE-TRANSMUTE":
      return "Specific primitive: transmute";
    case "RSA-UNSAFE-SET-LEN":
      return "Specific primitive: set_len";
    case "RSA-UNSAFE-FROM-RAW-PARTS":
      return "Specific primitive: from_raw_parts";
    case "RSA-UNSAFE-MAYBEUNINIT":
      return "Specific primitive: MaybeUninit";
    case "RSA-UNSAFE-BOX-FROM-RAW":
      return "Specific primitive: Box::from_raw";
    default:
      return finding.title;
  }
}

function formatRecommendedActions(items: readonly DiffAwareFinding[]): string {
  return [...new Set(items.map((item) => item.actionability?.recommendedAction ?? "manual_review"))].join(", ");
}

function formatContextNote(item: DiffAwareFinding): string | undefined {
  if (item.diffContext.contextNote !== undefined) {
    return item.diffContext.contextNote;
  }

  if (item.diffContext.relation === "nearby_legacy_context") {
    return "legacy context near changed lines; review separately";
  }

  if (item.diffContext.relation === "unrelated_nearby") {
    return "line-near context with no confirmed function or unsafe-site tie";
  }

  return undefined;
}

function isNumber(value: number | undefined): value is number {
  return value !== undefined;
}

function isNonEmptyString(value: string | undefined): value is string {
  return value !== undefined && value.length > 0;
}

function formatDiffFinding(
  item: DiffAwareFinding,
  projectPath: string,
  pathMode: PathMode,
  headingPrefix = "###"
): string[] {
  const finding = item.finding;
  const nearestChangedLine =
    item.diffContext.nearestChangedLine === undefined ? "none" : String(item.diffContext.nearestChangedLine);
  const distance = item.diffContext.distance === undefined ? "n/a" : String(item.diffContext.distance);
  const actionability = item.actionability;
  const lines = [
    `${headingPrefix} ${finding.ruleId}: ${finding.title}`,
    "",
    `- Severity: ${titleCase(finding.severity)}`,
    `- Confidence: ${titleCase(finding.confidence)}`,
    `- Rule: ${finding.ruleId}`,
    `- Location: \`${formatDisplayLocation(finding.file, finding.startLine, finding.endLine, projectPath, pathMode)}\``,
    `- Diff relation: ${item.diffContext.relation}`,
    `- Nearest changed line: ${nearestChangedLine}`,
    `- Distance: ${distance}`,
    `- Function/context: ${item.diffContext.functionName === undefined ? "unknown" : `\`${item.diffContext.functionName}\``}`,
    `- Recommended action: ${actionability?.recommendedAction ?? "manual_review"}`,
    `- Can Codex fix: ${actionability?.canCodexFix === true ? "Yes" : "No"}`
  ];

  const contextNote = formatContextNote(item);
  if (contextNote !== undefined) {
    lines.push(`- Context note: ${contextNote}`);
  }

  if (actionability?.suppressionSuggestion !== undefined) {
    lines.push(`- Suppression suggestion: \`${actionability.suppressionSuggestion}\``);
  }

  if (item.suppression?.isExpired === true) {
    lines.push("- Suppression status: expired; finding is shown again.");
  }

  if (item.suppression?.isValid === false) {
    lines.push(`- Suppression status: invalid; ${item.suppression.invalidSuppression ?? "directive ignored"}`);
  }

  lines.push(
    "",
    "#### Evidence",
    "",
    ...finding.evidence.map((item) => `- ${item}`),
    "",
    "#### Recommendation",
    "",
    finding.suggestedFix
  );

  return lines;
}

function decisionLabel(status: NonNullable<McpAuditToolOutput["reviewDecision"]>["status"]): string {
  switch (status) {
    case "block":
      return "BLOCK";
    case "needs_attention":
      return "NEEDS ATTENTION";
    case "pass":
      return "PASS";
  }
}

function formatFindingLocation(finding: Finding): string {
  if (finding.startLine === undefined) {
    return finding.file;
  }

  if (finding.endLine !== undefined && finding.endLine !== finding.startLine) {
    return `${finding.file}:${finding.startLine}-${finding.endLine}`;
  }

  return `${finding.file}:${finding.startLine}`;
}

function titleCase(value: string): string {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}

function isUnsafeOrFfiFinding(finding: Finding): boolean {
  return unsafeRulePrefixes.some((prefix) => finding.ruleId.startsWith(prefix));
}

function isDependencyOrBuildFinding(finding: Finding): boolean {
  return dependencyRulePrefixes.some((prefix) => finding.ruleId.startsWith(prefix));
}

function isDocumentedUnsafeFinding(finding: Finding): boolean {
  return (
    finding.ruleId === "RSA-UNSAFE-BLOCK" &&
    finding.confidence === "medium" &&
    (finding.falsePositiveNotes ?? "").includes("Nearby Safety comment")
  );
}

async function scanRustProjectFiles(projectPath: string, files: ReadonlySet<string>): Promise<RustProjectScanResult> {
  const projectResult = await new ProjectScanner().scan({ workspacePath: projectPath });
  const project = filterRustProject(projectResult.project, files);
  const scanOptions = { workspacePath: projectPath, project };
  const [unsafeResult, dependencyResult] = await Promise.all([
    new UnsafeScanner().scan(scanOptions),
    new DependencyScanner().scan(scanOptions)
  ]);
  const suppressedFindings = [
    ...(unsafeResult.suppressedFindings ?? []),
    ...(dependencyResult.suppressedFindings ?? [])
  ];

  return {
    project,
    findings: sortFindings(dedupeFindings([...unsafeResult.findings, ...dependencyResult.findings])),
    warnings: [...projectResult.warnings, ...unsafeResult.warnings, ...dependencyResult.warnings],
    suppressedCount: countActiveSuppressions(suppressedFindings),
    expiredSuppressionCount: countExpiredSuppressions(suppressedFindings),
    invalidSuppressionCount: countInvalidSuppressions(suppressedFindings),
    suppressedFindings
  };
}

function emptyRustProjectScan(projectPath: string): RustProjectScanResult {
  return {
    project: {
      workspacePath: projectPath,
      isRustProject: true,
      cargoTomlFiles: [],
      cargoLockFiles: [],
      buildScripts: [],
      rustSourceFiles: [],
      workspaceManifests: []
    },
    findings: [],
    warnings: []
  };
}

function filterRustProject(project: RustProject, files: ReadonlySet<string>): RustProject {
  return {
    ...project,
    cargoTomlFiles: project.cargoTomlFiles.filter((file) => files.has(file.file)),
    cargoLockFiles: project.cargoLockFiles.filter((file) => files.has(file.file)),
    buildScripts: project.buildScripts.filter((file) => files.has(file.file)),
    rustSourceFiles: project.rustSourceFiles.filter((file) => files.has(file.file)),
    workspaceManifests: project.workspaceManifests.filter((file) => files.has(file.file))
  };
}

function affectedFilePaths(diff: ParsedGitDiff): string[] {
  return [...new Set(diff.files.map((file) => normalizeFindingFile(file.filePath)).filter((file) => file.length > 0))].sort(
    (left, right) => left.localeCompare(right)
  );
}

function enrichFindingsWithDiff(
  findings: readonly Finding[],
  diffFiles: readonly GitDiffFile[],
  nearLineWindow: number,
  rustContexts: ReadonlyMap<string, RustFileContext>
): DiffAwareFinding[] {
  const diffByFile = new Map(diffFiles.map((file) => [file.filePath, file]));
  const enriched: DiffAwareFinding[] = [];

  for (const finding of findings) {
    const file = normalizeFindingFile(finding.file);
    const diffFile = diffByFile.get(file);
    if (diffFile === undefined) continue;

    enriched.push({
      finding,
      diffContext: classifyFindingAgainstDiff(finding, diffFile, nearLineWindow, rustContexts.get(file))
    });
  }

  return enriched;
}

function classifyFindingAgainstDiff(
  finding: Finding,
  diffFile: GitDiffFile,
  nearLineWindow: number,
  rustContext: RustFileContext | undefined
): FindingDiffContext {
  const addedLines = sortedAddedLines(diffFile);
  const line = finding.startLine;

  if (line === undefined) {
    return withRustContext({
      relation: "pre_existing_in_changed_file"
    }, finding, rustContext, undefined);
  }

  const nearestChangedLine = nearestLine(line, addedLines);
  const distance = nearestChangedLine === undefined ? undefined : Math.abs(line - nearestChangedLine);

  if (distance === 0) {
    return withRustContext({
      relation: "introduced_by_diff",
      nearestChangedLine,
      distance
    }, finding, rustContext, nearestChangedLine);
  }

  const nearestSameUnsafeSiteLine = nearestAddedLineMatchingContext(
    line,
    addedLines,
    rustContext,
    "same_unsafe_site_context"
  );
  if (nearestSameUnsafeSiteLine !== undefined) {
    return withRustContext({
      relation: "same_unsafe_site_context",
      nearestChangedLine: nearestSameUnsafeSiteLine,
      distance: Math.abs(line - nearestSameUnsafeSiteLine)
    }, finding, rustContext, nearestSameUnsafeSiteLine);
  }

  const nearestSameFunctionLine = nearestAddedLineMatchingContext(
    line,
    addedLines,
    rustContext,
    "same_function_context"
  );
  if (nearestSameFunctionLine !== undefined) {
    return withRustContext({
      relation: "same_function_context",
      nearestChangedLine: nearestSameFunctionLine,
      distance: Math.abs(line - nearestSameFunctionLine)
    }, finding, rustContext, nearestSameFunctionLine);
  }

  if (distance !== undefined && distance <= nearLineWindow) {
    return withRustContext({
      relation: isKnownDifferentRustContext(line, nearestChangedLine, rustContext)
        ? "nearby_legacy_context"
        : "unrelated_nearby",
      nearestChangedLine,
      distance
    }, finding, rustContext, nearestChangedLine);
  }

  const context: FindingDiffContext = {
    relation: "pre_existing_in_changed_file"
  };

  if (nearestChangedLine !== undefined && distance !== undefined) {
    context.nearestChangedLine = nearestChangedLine;
    context.distance = distance;
  }

  return withRustContext(context, finding, rustContext, nearestChangedLine);
}

function withRustContext(
  context: FindingDiffContext,
  finding: Finding,
  rustContext: RustFileContext | undefined,
  nearestChangedLine: number | undefined
): FindingDiffContext {
  const findingLineContext = contextForLine(rustContext, finding.startLine);
  const changedLineContext = contextForLine(rustContext, nearestChangedLine);
  const enriched: FindingDiffContext = { ...context };

  if (findingLineContext.functionContext !== undefined) {
    enriched.functionName = findingLineContext.functionContext.name;
    enriched.functionStartLine = findingLineContext.functionContext.startLine;
    if (findingLineContext.functionContext.endLine !== undefined) {
      enriched.functionEndLine = findingLineContext.functionContext.endLine;
    }
  }

  if (changedLineContext.functionContext !== undefined) {
    enriched.nearestChangedFunctionName = changedLineContext.functionContext.name;
    enriched.nearestChangedFunctionStartLine = changedLineContext.functionContext.startLine;
    if (changedLineContext.functionContext.endLine !== undefined) {
      enriched.nearestChangedFunctionEndLine = changedLineContext.functionContext.endLine;
    }
  }

  if (findingLineContext.unsafeSite !== undefined) {
    enriched.unsafeSite = findingLineContext.unsafeSite;
  }

  if (changedLineContext.unsafeSite !== undefined) {
    enriched.nearestChangedUnsafeSite = changedLineContext.unsafeSite;
  }

  if (findingLineContext.functionContext !== undefined && changedLineContext.functionContext !== undefined) {
    enriched.sameFunctionAsNearestChange =
      findingLineContext.functionContext.name === changedLineContext.functionContext.name &&
      findingLineContext.functionContext.startLine === changedLineContext.functionContext.startLine;
  }

  if (findingLineContext.unsafeSite !== undefined && changedLineContext.unsafeSite !== undefined) {
    enriched.sameUnsafeSiteAsNearestChange = sameUnsafeSite(
      findingLineContext.unsafeSite,
      changedLineContext.unsafeSite
    );
  }

  if (isContextRelation(context.relation)) {
    enriched.contextAssessment = assessDiffContext(enriched);
    enriched.contextNote = diffContextNote(enriched.contextAssessment);
  }

  return enriched;
}

function nearestAddedLineMatchingContext(
  findingLine: number,
  addedLines: readonly number[],
  rustContext: RustFileContext | undefined,
  relation: "same_unsafe_site_context" | "same_function_context"
): number | undefined {
  const findingLineContext = contextForLine(rustContext, findingLine);
  let nearest: number | undefined;
  let nearestDistance = Number.POSITIVE_INFINITY;

  for (const addedLine of addedLines) {
    const changedLineContext = contextForLine(rustContext, addedLine);
    const matches =
      relation === "same_unsafe_site_context"
        ? findingLineContext.unsafeSite !== undefined &&
          changedLineContext.unsafeSite !== undefined &&
          sameUnsafeSite(findingLineContext.unsafeSite, changedLineContext.unsafeSite)
        : findingLineContext.functionContext !== undefined &&
          changedLineContext.functionContext !== undefined &&
          findingLineContext.functionContext.name === changedLineContext.functionContext.name &&
          findingLineContext.functionContext.startLine === changedLineContext.functionContext.startLine;

    if (!matches) continue;

    const distance = Math.abs(findingLine - addedLine);
    if (distance < nearestDistance) {
      nearest = addedLine;
      nearestDistance = distance;
    }
  }

  return nearest;
}

function isKnownDifferentRustContext(
  findingLine: number,
  changedLine: number | undefined,
  rustContext: RustFileContext | undefined
): boolean {
  if (changedLine === undefined) return false;

  const findingLineContext = contextForLine(rustContext, findingLine);
  const changedLineContext = contextForLine(rustContext, changedLine);

  if (findingLineContext.unsafeSite !== undefined && changedLineContext.unsafeSite !== undefined) {
    return !sameUnsafeSite(findingLineContext.unsafeSite, changedLineContext.unsafeSite);
  }

  if (findingLineContext.functionContext !== undefined && changedLineContext.functionContext !== undefined) {
    return (
      findingLineContext.functionContext.name !== changedLineContext.functionContext.name ||
      findingLineContext.functionContext.startLine !== changedLineContext.functionContext.startLine
    );
  }

  return false;
}

function sameUnsafeSite(left: UnsafeSiteContext, right: UnsafeSiteContext): boolean {
  return left.kind === right.kind && left.startLine === right.startLine && left.endLine === right.endLine;
}

function isContextRelation(relation: FindingDiffContext["relation"]): boolean {
  return (
    relation === "same_unsafe_site_context" ||
    relation === "same_function_context" ||
    relation === "nearby_legacy_context" ||
    relation === "unrelated_nearby"
  );
}

function assessDiffContext(context: FindingDiffContext): NonNullable<FindingDiffContext["contextAssessment"]> {
  switch (context.relation) {
    case "same_unsafe_site_context":
      return "same_unsafe_site";
    case "same_function_context":
      return "same_function";
    case "nearby_legacy_context":
      return "nearby_legacy";
    case "unrelated_nearby":
      return "unrelated_nearby";
    case "introduced_by_diff":
      return "introduced";
    case "pre_existing_in_changed_file":
      return "pre_existing";
  }
}

function diffContextNote(
  assessment: NonNullable<FindingDiffContext["contextAssessment"]>
): string {
  switch (assessment) {
    case "introduced":
      return "finding starts on an added line";
    case "same_unsafe_site":
      return "same unsafe site as an added line; relevant context, not necessarily introduced";
    case "same_function":
      return "same function as an added line, outside the same unsafe site; manual context";
    case "nearby_legacy":
      return "near changed lines but in a different function or unsafe site; legacy context";
    case "unrelated_nearby":
      return "line-near changed code without confirmed function or unsafe-site relation";
    case "pre_existing":
      return "pre-existing finding in a changed file";
    case "unknown":
      return "context relationship could not be determined";
  }
}

function sortedAddedLines(diffFile: GitDiffFile): number[] {
  return [...new Set(diffFile.hunks.flatMap((hunk) => hunk.addedLines))].sort((left, right) => left - right);
}

function nearestLine(line: number, changedLines: readonly number[]): number | undefined {
  let nearest: number | undefined;
  let nearestDistance = Number.POSITIVE_INFINITY;

  for (const changedLine of changedLines) {
    const distance = Math.abs(line - changedLine);
    if (distance < nearestDistance) {
      nearest = changedLine;
      nearestDistance = distance;
    }
  }

  return nearest;
}

function countRelations(findings: readonly DiffAwareFinding[]): DiffReviewDetails["relationCounts"] {
  return {
    introduced_by_diff: findings.filter((item) => item.diffContext.relation === "introduced_by_diff").length,
    same_unsafe_site_context: findings.filter((item) => item.diffContext.relation === "same_unsafe_site_context").length,
    same_function_context: findings.filter((item) => item.diffContext.relation === "same_function_context").length,
    nearby_legacy_context: findings.filter((item) => item.diffContext.relation === "nearby_legacy_context").length,
    unrelated_nearby: findings.filter((item) => item.diffContext.relation === "unrelated_nearby").length,
    pre_existing_in_changed_file: findings.filter((item) => item.diffContext.relation === "pre_existing_in_changed_file").length
  };
}

function includedDiffRelations(
  includePreExisting: boolean,
  reportMode: DiffReportMode
): FindingDiffContext["relation"][] {
  const relations: FindingDiffContext["relation"][] = [
    "introduced_by_diff",
    "same_unsafe_site_context",
    "same_function_context"
  ];

  if (reportMode === "full") {
    relations.push("nearby_legacy_context", "unrelated_nearby");
  } else if (includePreExisting) {
    relations.push("nearby_legacy_context");
  }

  if (includePreExisting) {
    relations.push("pre_existing_in_changed_file");
  }

  return relations;
}

function countHiddenPreExistingFindings(
  allFindings: readonly DiffAwareFinding[],
  visibleFindings: readonly DiffAwareFinding[]
): number {
  const visibleIds = new Set(visibleFindings.map((item) => item.finding.id));

  return allFindings.filter(
    (item) => item.diffContext.relation === "pre_existing_in_changed_file" && !visibleIds.has(item.finding.id)
  ).length;
}

function countHiddenNearChangedFindings(
  allFindings: readonly DiffAwareFinding[],
  visibleFindings: readonly DiffAwareFinding[]
): number {
  const visibleIds = new Set(visibleFindings.map((item) => item.finding.id));

  return allFindings.filter(
    (item) => isContextRelation(item.diffContext.relation) && !visibleIds.has(item.finding.id)
  ).length;
}

async function readGitDiff(
  projectPath: string,
  input: RustReviewCurrentDiffInput
): Promise<{ diff: ParsedGitDiff; mode: DiffReviewMode; warnings: string[] }> {
  const base = normalizeOptionalGitRef(input.baseRef, "baseRef");
  const head = normalizeOptionalGitRef(input.headRef, "headRef");
  const gitState = await runGitCommand(projectPath, ["rev-parse", "--is-inside-work-tree"]);

  if (gitState.exitCode !== 0 || gitState.stdout.trim() !== "true") {
    throw new McpToolInputError(
      "PROJECT_PATH_NOT_GIT_REPO",
      `rust_review_current_diff requires projectPath to be inside a Git work tree: ${describeGitFailure(gitState)}. Use rust_audit_project for a full-project audit or initialize Git before diff review.`
    );
  }

  const { args, mode } = gitDiffArgs({ base, head, staged: input.staged === true });
  const result = await runGitCommand(projectPath, args);

  if (result.exitCode !== 0) {
    throw new McpToolInputError("GIT_DIFF_FAILED", `git ${args.join(" ")} failed: ${describeGitFailure(result)}`);
  }

  return {
    diff: parseUnifiedDiff(result.stdout),
    mode,
    warnings: []
  };
}

function gitDiffArgs(input: {
  base?: string | undefined;
  head?: string | undefined;
  staged: boolean;
}): { args: string[]; mode: DiffReviewMode } {
  const args = ["diff", "--relative", "--no-ext-diff", "--unified=3", "--diff-filter=ACMRTUXB"];

  if (input.staged) {
    return {
      args: [...args, "--cached", "--"],
      mode: "staged"
    };
  }

  if (input.base !== undefined && input.head !== undefined) {
    return {
      args: [...args, `${input.base}..${input.head}`, "--"],
      mode: "range"
    };
  }

  if (input.base !== undefined) {
    return {
      args: [...args, input.base, "--"],
      mode: "range"
    };
  }

  if (input.head !== undefined) {
    return {
      args: [...args, `HEAD..${input.head}`, "--"],
      mode: "range"
    };
  }

  return {
    args: [...args, "--"],
    mode: "working_tree"
  };
}

async function runGitCommand(projectPath: string, args: readonly string[]) {
  return await runShellCommand("git", args, {
    cwd: projectPath,
    timeoutMs: 10_000,
    maxBufferBytes: 5 * 1024 * 1024
  });
}

function normalizeOptionalGitRef(value: string | undefined, fieldName: string): string | undefined {
  if (value === undefined) return undefined;

  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;

  if (trimmed.startsWith("-") || /[\0\r\n]/.test(trimmed)) {
    throw new McpToolInputError("INVALID_GIT_REF", `${fieldName} is not a valid git ref.`);
  }

  return trimmed;
}

function normalizeFindingFile(file: string): string {
  const normalized = posix.normalize(file.trim().replaceAll("\\", "/"));

  if (
    normalized === "." ||
    normalized === ".." ||
    normalized.startsWith("../") ||
    posix.isAbsolute(normalized) ||
    isAbsolute(file)
  ) {
    return "";
  }

  return normalized;
}

function describeGitFailure(result: Awaited<ReturnType<typeof runGitCommand>>): string {
  if (result.error !== undefined) return result.error;
  if (result.timedOut) return "timed out";
  const stderr = result.stderr.trim();
  if (stderr.length > 0) return stderr.split(/\r?\n/)[0] ?? stderr;
  return `exit ${result.exitCode ?? "unknown"}`;
}

function toMcpAuditError(error: unknown): McpAuditError {
  if (error instanceof McpToolInputError) {
    return {
      code: error.code,
      message: error.message
    };
  }

  if (error instanceof Error) {
    return {
      code: "TOOL_EXECUTION_FAILED",
      message: error.message
    };
  }

  return {
    code: "TOOL_EXECUTION_FAILED",
    message: "Unknown MCP tool execution error."
  };
}
