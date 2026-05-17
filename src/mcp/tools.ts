import { realpath, stat } from "node:fs/promises";
import { isAbsolute, posix, resolve } from "node:path";
import { parseUnifiedDiff, type GitDiffFile, type ParsedGitDiff } from "../git/index.js";
import { renderMarkdownReport, toJsonReport, type AuditReportInput, type Category, categories, type Finding, type Severity, severities } from "../reports/index.js";
import { DependencyScanner, ProjectScanner, UnsafeScanner, discoverRustProject, scanRustProject, type RustProject, type RustProjectScanResult } from "../scanners/index.js";
import { dedupeFindings, sortFindings } from "../scanners/resultUtils.js";
import type { SuppressedFinding } from "../scanners/types.js";
import { runShellCommand } from "../utils/shell.js";
import {
  type DiffAwareFinding,
  type DiffReviewDetails,
  type DiffReviewMode,
  type FindingDiffContext,
  type McpAuditError,
  type McpAuditSummary,
  type McpAuditToolOutput,
  type McpToolName,
  type OutputFormat,
  type RustAuditDependenciesInput,
  type RustAuditProjectInput,
  type RustAuditToolInput,
  type RustAuditUnsafeInput,
  type RustReviewCurrentDiffInput,
  mcpToolNames
} from "./types.js";

const dependencyRulePrefixes = ["RSA-DEP-", "RSA-BUILD-"] as const;
const unsafeRulePrefixes = ["RSA-UNSAFE-", "RSA-FFI-"] as const;
const changedLineWindow = 5;

export function isMcpToolName(value: string): value is McpToolName {
  return (mcpToolNames as readonly string[]).includes(value);
}

export async function callRustAuditTool(
  tool: McpToolName,
  input: RustAuditToolInput
): Promise<McpAuditToolOutput> {
  switch (tool) {
    case "rust_audit_project":
      return await rustAuditProject(input as RustAuditProjectInput);
    case "rust_audit_unsafe":
      return await rustAuditUnsafe(input as RustAuditUnsafeInput);
    case "rust_audit_dependencies":
      return await rustAuditDependencies(input as RustAuditDependenciesInput);
    case "rust_review_current_diff":
      return await rustReviewCurrentDiff(input as RustReviewCurrentDiffInput);
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
      outputFormat: input.outputFormat,
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
      outputFormat: input.outputFormat,
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
      outputFormat: input.outputFormat,
      title: "Rust Dependency And Supply-Chain Audit",
      warnings: [...projectResult.warnings, ...dependencyResult.warnings]
    });
  });
}

export async function rustReviewCurrentDiff(input: RustReviewCurrentDiffInput): Promise<McpAuditToolOutput> {
  return await runTool("rust_review_current_diff", input.projectPath, async () => {
    const projectPath = await resolveRustProjectPath(input.projectPath);
    const gitDiff = await readGitDiff(projectPath, input);
    const diffAffectedFiles = affectedFilePaths(gitDiff.diff);
    const affectedFiles = new Set(diffAffectedFiles);
    const scan =
      affectedFiles.size === 0
        ? emptyRustProjectScan(projectPath)
        : await scanRustProjectFiles(projectPath, affectedFiles);
    const allEnrichedFindings = enrichFindingsWithDiff(scan.findings, gitDiff.diff.files, changedLineWindow);
    const includePreExisting = input.includePreExisting === true;
    const enrichedFindings = allEnrichedFindings.filter(
      (item) => item.diffContext.relation !== "pre_existing_in_changed_file" || includePreExisting
    );
    const findings = enrichedFindings.map((item) => item.finding);
    const relationCounts = countRelations(allEnrichedFindings);
    const conclusion = inferDiffReviewConclusion(enrichedFindings);
    const diffReview: DiffReviewDetails = {
      mode: gitDiff.mode,
      changedLineWindow,
      includePreExisting,
      includedRelations: includePreExisting
        ? ["introduced_by_diff", "near_changed_lines", "pre_existing_in_changed_file"]
        : ["introduced_by_diff", "near_changed_lines"],
      relationCounts,
      hiddenPreExistingCount: includePreExisting ? 0 : relationCounts.pre_existing_in_changed_file,
      conclusion
    };
    const warnings = [
      ...scan.warnings,
      ...gitDiff.warnings,
      "rust_review_current_diff is changed-line aware, but it is still heuristic scanner output rather than full data-flow or taint analysis."
    ];

    if (diffAffectedFiles.length === 0) {
      warnings.push("No changed Rust project files were detected in the selected git diff.");
    }

    return buildDiffReviewToolOutput({
      tool: "rust_review_current_diff",
      projectPath,
      findings,
      enrichedFindings,
      suppressedFindings: scan.suppressedFindings ?? [],
      suppressedCount: scan.suppressedCount ?? 0,
      outputFormat: input.outputFormat,
      title: "Rust Current Diff Security Review",
      warnings,
      diffAffectedFiles,
      diff: gitDiff.diff,
      diffReview
    });
  });
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
  outputFormat?: OutputFormat | undefined;
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
    output.reportMarkdown = renderMarkdownReport(reportInput);
  }

  if (input.warnings.length > 0) {
    output.warnings = [...input.warnings];
  }

  if (input.diffAffectedFiles !== undefined) {
    output.diffAffectedFiles = [...input.diffAffectedFiles];
  }

  return output;
}

function buildDiffReviewToolOutput(input: {
  tool: McpToolName;
  projectPath: string;
  findings: readonly Finding[];
  enrichedFindings: readonly DiffAwareFinding[];
  suppressedFindings: readonly SuppressedFinding[];
  suppressedCount: number;
  outputFormat?: OutputFormat | undefined;
  title: string;
  warnings: readonly string[];
  diffAffectedFiles: readonly string[];
  diff: ParsedGitDiff;
  diffReview: DiffReviewDetails;
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
    findings,
    diffAffectedFiles: [...input.diffAffectedFiles],
    diff: {
      files: input.diff.files
    },
    diffReview: input.diffReview,
    enrichedFindings: input.enrichedFindings.map((item) => ({
      finding: item.finding,
      diffContext: item.diffContext
    }))
  };

  if (input.outputFormat === "markdown") {
    output.reportMarkdown = renderDiffReviewMarkdown({
      title: input.title,
      projectPath: input.projectPath,
      findings: input.enrichedFindings,
      suppressedFindings: input.suppressedFindings,
      warnings: input.warnings,
      diffAffectedFiles: input.diffAffectedFiles,
      diffReview: input.diffReview
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

function renderDiffReviewMarkdown(input: {
  title: string;
  projectPath: string;
  findings: readonly DiffAwareFinding[];
  suppressedFindings: readonly SuppressedFinding[];
  warnings: readonly string[];
  diffAffectedFiles: readonly string[];
  diffReview: DiffReviewDetails;
}): string {
  const lines: string[] = [
    `# ${input.title}`,
    "",
    "## Summary",
    "",
    `- Conclusion: ${input.diffReview.conclusion}`,
    `- Diff mode: ${input.diffReview.mode}`,
    `- Changed-line window: ${input.diffReview.changedLineWindow}`,
    `- Scope: ${input.projectPath}`,
    `- Changed files: ${input.diffAffectedFiles.length}`,
    `- Introduced by this diff: ${input.diffReview.relationCounts.introduced_by_diff}`,
    `- Near changed lines: ${input.diffReview.relationCounts.near_changed_lines}`,
    `- Pre-existing in changed files: ${input.diffReview.relationCounts.pre_existing_in_changed_file}`
  ];

  if (input.diffReview.hiddenPreExistingCount > 0) {
    lines.push(`- Hidden pre-existing findings: ${input.diffReview.hiddenPreExistingCount}`);
  }

  if (input.warnings.length > 0) {
    lines.push("", "## Notes", "");
    for (const warning of input.warnings) {
      lines.push(`- ${warning}`);
    }
  }

  lines.push("", "## Changed Files", "");
  if (input.diffAffectedFiles.length === 0) {
    lines.push("No changed files in the selected git diff.");
  } else {
    for (const file of input.diffAffectedFiles) {
      lines.push(`- \`${file}\``);
    }
  }

  appendDiffFindingGroup(lines, "Introduced by this diff", input.findings, "introduced_by_diff");
  appendDiffFindingGroup(lines, "Near changed lines", input.findings, "near_changed_lines");

  if (input.diffReview.includePreExisting) {
    appendDiffFindingGroup(lines, "Pre-existing in changed files", input.findings, "pre_existing_in_changed_file");
  } else {
    lines.push("", "## Pre-existing in changed files", "");
    if (input.diffReview.hiddenPreExistingCount === 0) {
      lines.push("No hidden pre-existing findings in changed files.");
    } else {
      lines.push(
        `${input.diffReview.hiddenPreExistingCount} finding(s) were hidden because they are in changed files but not close to added lines. Re-run with \`includePreExisting: true\` to include them.`
      );
    }
  }

  lines.push("", "## Suppressed findings", "");
  if (input.suppressedFindings.length === 0) {
    lines.push("No inline-suppressed findings in changed files.");
  } else {
    for (const finding of input.suppressedFindings) {
      lines.push(
        `- ${finding.ruleId} at \`${finding.file}:${finding.line}\` suppressed by directive on line ${finding.directiveLine}: ${finding.reason}`
      );
    }
  }

  lines.push("", "## Conclusion", "", conclusionText(input.diffReview.conclusion));

  return `${lines.join("\n").replace(/\n{3,}/g, "\n\n").trimEnd()}\n`;
}

function appendDiffFindingGroup(
  lines: string[],
  title: string,
  findings: readonly DiffAwareFinding[],
  relation: FindingDiffContext["relation"]
): void {
  const group = findings.filter((item) => item.diffContext.relation === relation);
  lines.push("", `## ${title}`, "");

  if (group.length === 0) {
    lines.push("No findings in this group.");
    return;
  }

  for (const item of group) {
    lines.push(...formatDiffFinding(item), "");
  }
}

function formatDiffFinding(item: DiffAwareFinding): string[] {
  const finding = item.finding;
  const nearestChangedLine =
    item.diffContext.nearestChangedLine === undefined ? "none" : String(item.diffContext.nearestChangedLine);
  const distance = item.diffContext.distance === undefined ? "n/a" : String(item.diffContext.distance);

  return [
    `### ${finding.ruleId}: ${finding.title}`,
    "",
    `- Severity: ${titleCase(finding.severity)}`,
    `- Confidence: ${titleCase(finding.confidence)}`,
    `- Rule: ${finding.ruleId}`,
    `- Location: \`${formatFindingLocation(finding)}\``,
    `- Nearest changed line: ${nearestChangedLine}`,
    `- Distance: ${distance}`,
    "",
    "#### Evidence",
    "",
    ...finding.evidence.map((item) => `- ${item}`),
    "",
    "#### Recommendation",
    "",
    finding.suggestedFix
  ];
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

function conclusionText(conclusion: DiffReviewDetails["conclusion"]): string {
  switch (conclusion) {
    case "Block before commit":
      return "Block before commit: this diff introduces a high or critical security finding.";
    case "Needs attention":
      return "Needs attention: review the introduced or nearby findings before committing.";
    case "Safe to proceed":
      return "Safe to proceed: no blocking changed-line-aware findings were reported by the configured checks.";
  }
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
    suppressedCount: suppressedFindings.length,
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
  nearLineWindow: number
): DiffAwareFinding[] {
  const diffByFile = new Map(diffFiles.map((file) => [file.filePath, file]));
  const enriched: DiffAwareFinding[] = [];

  for (const finding of findings) {
    const file = normalizeFindingFile(finding.file);
    const diffFile = diffByFile.get(file);
    if (diffFile === undefined) continue;

    enriched.push({
      finding,
      diffContext: classifyFindingAgainstDiff(finding, diffFile, nearLineWindow)
    });
  }

  return enriched;
}

function classifyFindingAgainstDiff(
  finding: Finding,
  diffFile: GitDiffFile,
  nearLineWindow: number
): FindingDiffContext {
  const addedLines = sortedAddedLines(diffFile);
  const line = finding.startLine;

  if (line === undefined) {
    return {
      relation: "pre_existing_in_changed_file"
    };
  }

  const nearestChangedLine = nearestLine(line, addedLines);
  const distance = nearestChangedLine === undefined ? undefined : Math.abs(line - nearestChangedLine);

  if (distance === 0) {
    return {
      relation: "introduced_by_diff",
      nearestChangedLine,
      distance
    };
  }

  if (distance !== undefined && distance <= nearLineWindow) {
    return {
      relation: "near_changed_lines",
      nearestChangedLine,
      distance
    };
  }

  const context: FindingDiffContext = {
    relation: "pre_existing_in_changed_file"
  };

  if (nearestChangedLine !== undefined && distance !== undefined) {
    context.nearestChangedLine = nearestChangedLine;
    context.distance = distance;
  }

  return context;
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
    near_changed_lines: findings.filter((item) => item.diffContext.relation === "near_changed_lines").length,
    pre_existing_in_changed_file: findings.filter((item) => item.diffContext.relation === "pre_existing_in_changed_file").length
  };
}

function inferDiffReviewConclusion(findings: readonly DiffAwareFinding[]): DiffReviewDetails["conclusion"] {
  const introduced = findings.filter((item) => item.diffContext.relation === "introduced_by_diff");

  if (introduced.some((item) => item.finding.severity === "critical" || item.finding.severity === "high")) {
    return "Block before commit";
  }

  if (introduced.some((item) => item.finding.severity === "medium")) {
    return "Needs attention";
  }

  if (findings.some((item) => item.finding.severity === "critical" || item.finding.severity === "high" || item.finding.severity === "medium")) {
    return "Needs attention";
  }

  return "Safe to proceed";
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
