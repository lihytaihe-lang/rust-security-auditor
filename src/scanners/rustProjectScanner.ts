import type { AuditReportInput } from "../reports/schemas.js";
import { DependencyScanner } from "./dependencyScanner.js";
import { ProjectScanner, type RustProject } from "./projectScanner.js";
import { countActiveSuppressions, countExpiredSuppressions, countInvalidSuppressions, dedupeFindings, sortFindings } from "./resultUtils.js";
import { SourceRiskScanner } from "./sourceRiskScanner.js";
import type { ScannerContext, ScannerResult } from "./types.js";
import { UnsafeScanner } from "./unsafeScanner.js";

export interface RustProjectScanResult extends ScannerResult {
  project: RustProject;
}

export async function scanRustProject(options: ScannerContext): Promise<RustProjectScanResult> {
  const projectScanner = new ProjectScanner();
  const projectResult = await projectScanner.scan(options);
  const scanOptions = { ...options, project: projectResult.project };
  const [unsafeResult, dependencyResult, sourceRiskResult] = await Promise.all([
    new UnsafeScanner().scan(scanOptions),
    new DependencyScanner().scan(scanOptions),
    new SourceRiskScanner().scan(scanOptions)
  ]);
  const suppressedFindings = [
    ...(unsafeResult.suppressedFindings ?? []),
    ...(dependencyResult.suppressedFindings ?? []),
    ...(sourceRiskResult.suppressedFindings ?? [])
  ];

  return {
    project: projectResult.project,
    findings: sortFindings(
      dedupeFindings([...unsafeResult.findings, ...dependencyResult.findings, ...sourceRiskResult.findings])
    ),
    warnings: [
      ...projectResult.warnings,
      ...unsafeResult.warnings,
      ...dependencyResult.warnings,
      ...sourceRiskResult.warnings
    ],
    suppressedCount: countActiveSuppressions(suppressedFindings),
    expiredSuppressionCount: countExpiredSuppressions(suppressedFindings),
    invalidSuppressionCount: countInvalidSuppressions(suppressedFindings),
    suppressedFindings,
    scanCoverage: projectResult.project.sourceReader.coverage()
  };
}

export function toRustAuditReportInput(
  result: RustProjectScanResult,
  overrides: Omit<AuditReportInput, "findings"> = {}
): AuditReportInput {
  return {
    ...overrides,
    title: overrides.title ?? "Rust Security Audit Report",
    scope: overrides.scope ?? result.project.workspacePath,
    findings: result.findings,
    summaryNotes: [...(overrides.summaryNotes ?? []), ...result.warnings]
  };
}
