import { realpath, stat } from "node:fs/promises";
import { isAbsolute, posix, resolve } from "node:path";
import { renderMarkdownReport, toJsonReport, type AuditReportInput, type Category, categories, type Finding, type Severity, severities } from "../reports/index.js";
import { DependencyScanner, ProjectScanner, UnsafeScanner, discoverRustProject, scanRustProject } from "../scanners/index.js";
import { runShellCommand } from "../utils/shell.js";
import {
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
    const diff = await diffAffectedFiles(projectPath, input.baseRef, input.headRef);
    const affectedFiles = new Set(diff.files);
    const scan = await scanRustProject({ workspacePath: projectPath });
    const findings = scan.findings.filter((finding) => affectedFiles.has(normalizeFindingFile(finding.file)));
    const suppressedCount = (scan.suppressedFindings ?? []).filter((finding) =>
      affectedFiles.has(normalizeFindingFile(finding.file))
    ).length;
    const warnings = [
      ...scan.warnings,
      ...diff.warnings,
      "rust_review_current_diff currently scans findings in diff-affected files; it is not full semantic diff analysis."
    ];

    if (diff.files.length === 0) {
      warnings.push("No diff-affected files were detected.");
    }

    return buildToolOutput({
      tool: "rust_review_current_diff",
      projectPath,
      findings,
      suppressedCount,
      outputFormat: input.outputFormat,
      title: "Rust Current Diff Security Review",
      warnings,
      diffAffectedFiles: diff.files
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

async function diffAffectedFiles(
  projectPath: string,
  baseRef?: string,
  headRef?: string
): Promise<{ files: string[]; warnings: string[] }> {
  const base = normalizeOptionalGitRef(baseRef, "baseRef");
  const head = normalizeOptionalGitRef(headRef, "headRef");
  const warnings: string[] = [];
  const files = new Set<string>();
  const gitState = await runGitNameOnly(projectPath, ["rev-parse", "--is-inside-work-tree"]);

  if (gitState.exitCode !== 0 || gitState.stdout.trim() !== "true") {
    warnings.push(
      `git diff is unavailable for projectPath: ${describeGitFailure(gitState)}. ` +
        "rust_review_current_diff requires projectPath to be inside a Git work tree; use rust_audit_project for a full-project audit or initialize Git before diff review."
    );
    return { files: [], warnings };
  }

  if (base !== undefined && head !== undefined) {
    await addGitNameOnlyFiles(projectPath, ["diff", "--name-only", "--diff-filter=ACMRTUXB", base, head, "--"], files, warnings);
    return { files: [...files].sort((left, right) => left.localeCompare(right)), warnings };
  }

  if (base !== undefined) {
    await addGitNameOnlyFiles(projectPath, ["diff", "--name-only", "--diff-filter=ACMRTUXB", base, "--"], files, warnings);
    return { files: [...files].sort((left, right) => left.localeCompare(right)), warnings };
  }

  if (head !== undefined) {
    await addGitNameOnlyFiles(projectPath, ["diff", "--name-only", "--diff-filter=ACMRTUXB", "HEAD", head, "--"], files, warnings);
    return { files: [...files].sort((left, right) => left.localeCompare(right)), warnings };
  }

  const headDiff = await runGitNameOnly(projectPath, ["diff", "--name-only", "--diff-filter=ACMRTUXB", "HEAD", "--"]);
  if (headDiff.exitCode === 0) {
    addSafeRelativeFiles(headDiff.stdout, files);
  } else {
    warnings.push(`git diff HEAD failed: ${describeGitFailure(headDiff)}`);
    await addGitNameOnlyFiles(projectPath, ["diff", "--name-only", "--diff-filter=ACMRTUXB", "--"], files, warnings);
    await addGitNameOnlyFiles(projectPath, ["diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB", "--"], files, warnings);
  }

  await addGitNameOnlyFiles(projectPath, ["ls-files", "--others", "--exclude-standard"], files, warnings);

  return { files: [...files].sort((left, right) => left.localeCompare(right)), warnings };
}

async function addGitNameOnlyFiles(
  projectPath: string,
  args: readonly string[],
  files: Set<string>,
  warnings: string[]
): Promise<void> {
  const result = await runGitNameOnly(projectPath, args);
  if (result.exitCode !== 0) {
    warnings.push(`git ${args.join(" ")} failed: ${describeGitFailure(result)}`);
    return;
  }

  addSafeRelativeFiles(result.stdout, files);
}

async function runGitNameOnly(projectPath: string, args: readonly string[]) {
  return await runShellCommand("git", args, {
    cwd: projectPath,
    timeoutMs: 10_000,
    maxBufferBytes: 1024 * 1024
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

function addSafeRelativeFiles(stdout: string, files: Set<string>): void {
  for (const line of stdout.split(/\r?\n/)) {
    const file = normalizeFindingFile(line);
    if (file.length > 0) {
      files.add(file);
    }
  }
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

function describeGitFailure(result: Awaited<ReturnType<typeof runGitNameOnly>>): string {
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
