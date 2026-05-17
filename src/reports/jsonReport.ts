import {
  type AuditReportInput,
  type Finding,
  schemaVersion,
  summarizeFindings,
  validateFindings
} from "./schemas.js";

export interface JsonAuditReport {
  schemaVersion: typeof schemaVersion;
  title: string;
  generatedAt: string;
  scope?: string;
  summary: ReturnType<typeof summarizeFindings>;
  findings: Finding[];
  summaryNotes: string[];
  releaseGateRecommendation: string;
}

export function toJsonReport(input: AuditReportInput): JsonAuditReport {
  const findings = validateFindings([...input.findings]);
  const report: JsonAuditReport = {
    schemaVersion,
    title: input.title ?? "Rust Security Audit Report",
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    summary: summarizeFindings(findings, input.result),
    findings,
    summaryNotes: [...(input.summaryNotes ?? [])],
    releaseGateRecommendation:
      input.releaseGateRecommendation ?? defaultReleaseGateRecommendation(findings)
  };

  if (input.scope !== undefined) {
    report.scope = input.scope;
  }

  return report;
}

export function renderJsonReport(input: AuditReportInput, space = 2): string {
  return `${JSON.stringify(toJsonReport(input), null, space)}\n`;
}

function defaultReleaseGateRecommendation(findings: readonly Finding[]): string {
  const summary = summarizeFindings(findings);

  switch (summary.result) {
    case "PASS":
      return "No security review signals were reported by the configured checks.";
    case "PASS_WITH_WARNINGS":
      return "Review the warnings, but the current evidence does not block release.";
    case "NEEDS_FIX_BEFORE_RELEASE":
      return "Review or fix high or critical security review signals before release or merge.";
    case "MANUAL_SECURITY_REVIEW_REQUIRED":
      return "Complete manual security review for low-confidence or manual-review items before release.";
  }
}
